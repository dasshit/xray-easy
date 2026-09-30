package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

type archiveItem struct {
	name     string
	typeflag byte
	data     string
}

func makeTestAWGArchive(t *testing.T, items ...archiveItem) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	writer := tar.NewWriter(compressed)
	for _, item := range items {
		typeflag := item.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{Name: item.name, Mode: 0600, Size: int64(len(item.data)), Typeflag: typeflag}
		if typeflag == tar.TypeDir {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			if _, err := io.WriteString(writer, item.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestExtractAWGBackupRejectsUnsafeArchives(t *testing.T) {
	for _, test := range []struct {
		name    string
		archive []byte
		want    string
	}{
		{name: "invalid gzip", archive: []byte("not gzip"), want: "open archive"},
		{name: "path traversal", archive: makeTestAWGArchive(t, archiveItem{name: "../outside", data: "secret"}), want: "unsafe or duplicate path"},
		{name: "absolute path", archive: makeTestAWGArchive(t, archiveItem{name: "/outside", data: "secret"}), want: "unsafe or duplicate path"},
		{name: "unexpected entry", archive: makeTestAWGArchive(t, archiveItem{name: "notes.txt", data: "unexpected"}), want: "unexpected file"},
		{name: "symlink", archive: makeTestAWGArchive(t, archiveItem{name: "state.json", typeflag: tar.TypeSymlink}), want: "unsupported entry"},
		{name: "duplicate state", archive: makeTestAWGArchive(t, archiveItem{name: "state.json", data: "first"}, archiveItem{name: "state.json", data: "second"}), want: "unsafe or duplicate path"},
		{name: "missing state", archive: makeTestAWGArchive(t, archiveItem{name: "profiles/phone.conf", data: "profile"}), want: "no state.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			_, err := extractAWGBackup(root, test.archive)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("extractAWGBackup() error = %v, want %q", err, test.want)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(root), "outside")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("archive wrote outside staging root: %v", err)
			}
		})
	}
}

func TestExtractAWGBackupWritesOnlyValidStateAndProfiles(t *testing.T) {
	root := t.TempDir()
	archive := makeTestAWGArchive(t,
		archiveItem{name: "profiles", typeflag: tar.TypeDir},
		archiveItem{name: "profiles/phone.conf", data: "private-profile"},
		archiveItem{name: "state.json", data: "state-content"},
	)
	state, err := extractAWGBackup(root, archive)
	if err != nil || string(state) != "state-content" {
		t.Fatalf("extractAWGBackup() = %q, %v", state, err)
	}
	profile, err := os.ReadFile(filepath.Join(root, "profiles", "phone.conf"))
	if err != nil || string(profile) != "private-profile" {
		t.Fatalf("extracted private profile = %q, %v", profile, err)
	}
	info, err := os.Stat(filepath.Join(root, "profiles", "phone.conf"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("extracted profile mode = %v, %v", info, err)
	}
}

func TestReadSnapshotStateValidatesJSONAndMasterKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	stateData, err := os.ReadFile(filepath.Join(opts.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := readSnapshotState(stateData, opts)
	if err != nil || state.Version != stateVersion {
		t.Fatalf("valid snapshot state = %+v, %v", state, err)
	}
	if _, err := readSnapshotState([]byte("{"), opts); err == nil || !strings.Contains(err.Error(), "decode state.json") {
		t.Fatalf("invalid snapshot JSON error = %v", err)
	}
	wrongKey := opts
	wrongKey.MasterKey = bytes.Repeat([]byte("x"), 32)
	if _, err := readSnapshotState(stateData, wrongKey); err == nil || !strings.Contains(err.Error(), "decrypt server key") {
		t.Fatalf("wrong snapshot master key error = %v", err)
	}
}

func TestCreateAWGBackupRejectsMissingProfilesAndUnsafeProfileEntries(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(t *testing.T, opts Options, manager *Manager)
		want      string
	}{
		{
			name: "peer profile missing",
			configure: func(t *testing.T, opts Options, manager *Manager) {
				_, publicKey, err := GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := manager.AddPeer("phone", publicKey); err != nil {
					t.Fatal(err)
				}
			},
			want: "saved client profile for peer",
		},
		{
			name: "unsafe profile entry",
			configure: func(t *testing.T, opts Options, manager *Manager) {
				if err := os.MkdirAll(filepath.Join(opts.DataDir, "profiles"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(opts.DataDir, "profiles", "unexpected"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: "unsupported entry",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := testOptions(t)
			manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			test.configure(t, opts, manager)
			if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("createAWGBackup() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCreateAWGBackupRejectsInvalidStateAndProfileDirectories(t *testing.T) {
	if _, err := createAWGBackup("", nil); err == nil {
		t.Fatal("backup accepted an uninitialized service")
	}
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	statePath := filepath.Join(opts.DataDir, "state.json")
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil {
		t.Fatal("backup accepted a missing state file")
	}
	if err := os.WriteFile(statePath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "read persistent state") {
		t.Fatalf("backup accepted malformed state: %v", err)
	}
	if err := os.WriteFile(statePath, stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	profileDir := filepath.Join(opts.DataDir, "profiles")
	if err := os.WriteFile(profileDir, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil {
		t.Fatal("backup accepted a regular file for the profiles directory")
	}
	if err := os.Remove(profileDir); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, profileDir); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("backup accepted a symlinked profile directory: %v", err)
	}
}

func TestRestoreAWGBackupRejectsMissingOrMismatchedPeerProfiles(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := newStructService(manager, opts)
	request, _ := structpb.NewStruct(map[string]any{"name": "phone"})
	if _, err := service.CreatePeer(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	archive, err := createAWGBackup(opts.DataDir, manager)
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	state, err := extractAWGBackup(stage, archive)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(stage, "profiles", "phone.conf")
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedPrivateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	originalPrivateKey, err := privateKeyFromProfile(string(profile))
	if err != nil {
		t.Fatal(err)
	}
	profileText := strings.Replace(string(profile), "PrivateKey = "+originalPrivateKey, "PrivateKey = "+unrelatedPrivateKey, 1)
	mismatched := makeTestAWGArchive(t,
		archiveItem{name: "state.json", data: string(state)},
		archiveItem{name: "profiles/phone.conf", data: profileText},
	)
	if err := restoreAWGBackup(opts.DataDir, manager, mismatched); err == nil || !strings.Contains(err.Error(), "does not match a restored peer") {
		t.Fatalf("restore with mismatched client profile error = %v", err)
	}
	missing := makeTestAWGArchive(t, archiveItem{name: "state.json", data: string(state)})
	if err := restoreAWGBackup(opts.DataDir, manager, missing); err == nil || !strings.Contains(err.Error(), "exactly one client profile") {
		t.Fatalf("restore without client profile error = %v", err)
	}
	if len(manager.Peers()) != 1 {
		t.Fatalf("invalid restore changed active peers: %+v", manager.Peers())
	}
}

func TestSavedClientProfileHelpersRejectUnsafeOrMalformedEntries(t *testing.T) {
	if err := writeClientProfile("", "phone", "profile"); err == nil || !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("write profile without directory = %v", err)
	}
	if err := writeClientProfile(t.TempDir(), "bad_name", "profile"); err == nil {
		t.Fatal("write accepted an invalid peer name")
	}

	root := t.TempDir()
	profile := "[Interface]\nPrivateKey = client-key\n[Peer]\nPublicKey = server-key\n"
	if err := writeClientProfile(root, "phone", profile); err != nil {
		t.Fatal(err)
	}
	got, err := readClientProfile(root, "phone")
	if err != nil || got != profile {
		t.Fatalf("readClientProfile() = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(root, "profiles", "phone.conf"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved profile mode = %v, %v", info, err)
	}
	if err := removeClientProfile(root, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := removeClientProfile(root, "phone"); err != nil {
		t.Fatalf("removing an already absent profile should be idempotent: %v", err)
	}

	for _, test := range []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
	}{
		{name: "malformed", content: "not a WireGuard profile", mode: 0o600, want: "malformed"},
		{name: "oversized", content: strings.Repeat("x", (64<<10)+1), mode: 0o600, want: "exceeds 64 KiB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			profilePath := filepath.Join(dir, "profiles", "phone.conf")
			if err := os.MkdirAll(filepath.Dir(profilePath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(profilePath, []byte(test.content), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := readClientProfile(dir, "phone"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe profile accepted: %v", err)
			}
		})
	}

	linkRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(linkRoot, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(linkRoot, "missing-target"), filepath.Join(linkRoot, "profiles", "phone.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientProfile(linkRoot, "phone"); err == nil {
		t.Fatal("read accepted a symlink as a profile")
	}
}

func TestPrivateKeyFromProfileRequiresExactlyOneInterfaceKey(t *testing.T) {
	for _, profile := range []string{
		"[Peer]\nPrivateKey = peer-key\n",
		"[Interface]\nPrivateKey=bad-format\n",
		"[Interface]\nPrivateKey = one\nPrivateKey = two\n",
		"[Interface]\nPrivateKey = \n",
	} {
		if _, err := privateKeyFromProfile(profile); err == nil {
			t.Fatalf("invalid private key profile was accepted: %q", profile)
		}
	}
	if key, err := privateKeyFromProfile("[Interface]\nPrivateKey = actual-key\n[Peer]\nPrivateKey = ignored\n"); err != nil || key != "actual-key" {
		t.Fatalf("private key extraction = %q, %v", key, err)
	}
}

func TestRestoreAWGBackupRestoresPreviousProfilesWhenLiveApplyFails(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := newStructService(manager, opts)
	firstRequest, _ := structpb.NewStruct(map[string]any{"name": "phone"})
	if _, err := service.CreatePeer(t.Context(), firstRequest); err != nil {
		t.Fatal(err)
	}
	archive, err := createAWGBackup(opts.DataDir, manager)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, _ := structpb.NewStruct(map[string]any{"name": "tablet"})
	if _, err := service.CreatePeer(t.Context(), secondRequest); err != nil {
		t.Fatal(err)
	}
	phoneBefore, err := os.ReadFile(filepath.Join(opts.DataDir, "profiles", "phone.conf"))
	if err != nil {
		t.Fatal(err)
	}
	tabletBefore, err := os.ReadFile(filepath.Join(opts.DataDir, "profiles", "tablet.conf"))
	if err != nil {
		t.Fatal(err)
	}
	device.failPeerApply = true
	if err := restoreAWGBackup(opts.DataDir, manager, archive); err == nil || !strings.Contains(err.Error(), "injected device set failure") {
		t.Fatalf("restore with live-device failure error = %v", err)
	}
	if len(manager.Peers()) != 2 {
		t.Fatalf("live peer state was not rolled back: %+v", manager.Peers())
	}
	for name, expected := range map[string][]byte{"phone": phoneBefore, "tablet": tabletBefore} {
		got, err := os.ReadFile(filepath.Join(opts.DataDir, "profiles", name+".conf"))
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("profile %q after failed restore = %q, %v", name, got, err)
		}
	}
}

func TestProfileMatchesPeerChecksPrivateKeyIdentity(t *testing.T) {
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	profile := "[Interface]\nPrivateKey = " + privateKey + "\n[Peer]\n"
	peers := []Peer{{Name: "phone", PublicKey: publicKey}}
	if !profileMatchesPeer("phone", []byte(profile), peers) {
		t.Fatal("matching client profile was rejected")
	}
	if profileMatchesPeer("other", []byte(profile), peers) {
		t.Fatal("profile was accepted for a different peer name")
	}
	if profileMatchesPeer("phone", []byte("malformed"), peers) {
		t.Fatal("profile without a private key was accepted")
	}
	otherPrivateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if profileMatchesPeer("phone", []byte("[Interface]\nPrivateKey = "+otherPrivateKey+"\n"), peers) {
		t.Fatal("profile containing a different private key was accepted")
	}
}
