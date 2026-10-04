package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
	awgapi "xray-easy/awg-contract/api/v1"
)

// createBackupPeerFixture creates a manager and saved client profiles for backup tests.
func createBackupPeerFixture(t *testing.T, names ...string) (Options, *Manager) {
	t.Helper()
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	service := newStructService(manager, opts)
	for _, name := range names {
		request, err := structpb.NewStruct(map[string]any{"name": name})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.CreatePeer(t.Context(), request); err != nil {
			t.Fatalf("create peer %q: %v", name, err)
		}
	}
	return opts, manager
}

func TestCreateAWGBackupAllowsMissingEmptyProfileDirectory(t *testing.T) {
	opts, manager := createBackupPeerFixture(t)
	profileDirectory := filepath.Join(opts.DataDir, "profiles")
	if err := os.RemoveAll(profileDirectory); err != nil {
		t.Fatal(err)
	}
	archive, err := createAWGBackup(opts.DataDir, manager)
	if err != nil {
		t.Fatalf("create backup without an empty profiles directory: %v", err)
	}
	root := t.TempDir()
	state, err := extractAWGBackup(root, archive)
	if err != nil || len(state) == 0 {
		t.Fatalf("backup state=%q error=%v", state, err)
	}
	if _, err := os.Stat(filepath.Join(root, "profiles")); !os.IsNotExist(err) {
		t.Fatalf("empty profile directory was unexpectedly archived: %v", err)
	}
}

func TestCreateAWGBackupRejectsInvalidEncryptedServerKey(t *testing.T) {
	opts, manager := createBackupPeerFixture(t)
	statePath := filepath.Join(opts.DataDir, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state.PrivateKeyEnvelope = "invalid-envelope"
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "verify encrypted server key") {
		t.Fatalf("backup accepted an invalid encrypted server key: %v", err)
	}
}

func TestCreateAWGBackupRejectsInvalidStateAndMismatchedSavedProfile(t *testing.T) {
	t.Run("invalid persistent state", func(t *testing.T) {
		opts, manager := createBackupPeerFixture(t)
		statePath := filepath.Join(opts.DataDir, "state.json")
		data, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatal(err)
		}
		var state persistedState
		if err := json.Unmarshal(data, &state); err != nil {
			t.Fatal(err)
		}
		state.PrivateKeyEnvelope = ""
		data, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(statePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "persisted server key envelope is missing") {
			t.Fatalf("backup accepted invalid persistent state: %v", err)
		}
	})

	t.Run("saved profile belongs to a different peer", func(t *testing.T) {
		opts, manager := createBackupPeerFixture(t, "phone")
		path := filepath.Join(opts.DataDir, "profiles", "phone.conf")
		profile, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		oldPrivateKey, err := privateKeyFromProfile(string(profile))
		if err != nil {
			t.Fatal(err)
		}
		newPrivateKey, _, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		updated := strings.Replace(string(profile), "PrivateKey = "+oldPrivateKey, "PrivateKey = "+newPrivateKey, 1)
		if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "does not match a configured peer") {
			t.Fatalf("backup accepted a profile with a mismatched key: %v", err)
		}
	})
}

func TestCreateAWGBackupRejectsProfileDirectorySymlink(t *testing.T) {
	opts, manager := createBackupPeerFixture(t)
	profileDirectory := filepath.Join(opts.DataDir, "profiles")
	if err := os.RemoveAll(profileDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(profileDirectory, profileDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil {
		t.Fatal("backup accepted a profile directory symlink")
	}
}

func TestReadSnapshotStateNormalizesNilPeersAndRejectsInvalidState(t *testing.T) {
	opts, _ := createBackupPeerFixture(t)
	statePath := filepath.Join(opts.DataDir, "state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state.Peers = nil
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := readSnapshotState(data, opts)
	if err != nil || loaded.Peers == nil {
		t.Fatalf("normalized peers=%#v error=%v", loaded.Peers, err)
	}
	state.Version = stateVersion + 1
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotState(data, opts); err == nil || !strings.Contains(err.Error(), "unsupported AWG state version") {
		t.Fatalf("snapshot with unsupported version error = %v", err)
	}
	state.Version = stateVersion
	state.PrivateKeyEnvelope = "not-base64"
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshotState(data, opts); err == nil || !strings.Contains(err.Error(), "decrypt server key") {
		t.Fatalf("snapshot with an invalid server key error = %v", err)
	}
}

func TestRestoreAWGBackupRejectsUnavailablePathsAndMalformedSnapshot(t *testing.T) {
	if err := restoreAWGBackup("", nil, nil); err == nil {
		t.Fatal("restore accepted an uninitialized service")
	}
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAWGBackup(filePath, &Manager{}, nil); err == nil {
		t.Fatal("restore created a stage directory below a regular file")
	}
	opts, manager := createBackupPeerFixture(t)
	malformedState := makeTestAWGArchive(t, archiveItem{name: "state.json", data: "{"})
	if err := restoreAWGBackup(opts.DataDir, manager, malformedState); err == nil || !strings.Contains(err.Error(), "decode state.json") {
		t.Fatalf("restore accepted malformed snapshot state: %v", err)
	}
}

func TestRestoreAWGBackupLeavesProfilesWhenManagerIsClosed(t *testing.T) {
	opts, manager := createBackupPeerFixture(t, "phone")
	archive, err := createAWGBackup(opts.DataDir, manager)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(opts.DataDir, "profiles", "phone.conf")
	before, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if err := restoreAWGBackup(opts.DataDir, manager, archive); err == nil || !strings.Contains(err.Error(), "manager is closed") {
		t.Fatalf("restoreAWGBackup() error = %v, want closed manager", err)
	}
	after, err := os.ReadFile(profilePath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed restore changed saved profile: read error=%v", err)
	}
}

func TestTypedRestoreBackupRejectsOversizedAndNilRequests(t *testing.T) {
	service := &Service{}
	if _, err := service.RestoreBackup(context.Background(), &awgapi.RestoreBackupRequest{Data: make([]byte, maxAWGBackupSize+1)}); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("restore accepted an oversized request: %v", err)
	}
	if _, err := service.RestoreBackup(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("restore accepted a nil request without service state: %v", err)
	}
}

func TestCreateAWGBackupRejectsAdditionalUnsafeProfileFiles(t *testing.T) {
	t.Run("unexpected regular file", func(t *testing.T) {
		opts, manager := createBackupPeerFixture(t, "phone")
		path := filepath.Join(opts.DataDir, "profiles", "notes.txt")
		if err := os.WriteFile(path, []byte("not a client profile"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "unsupported entry") {
			t.Fatalf("backup accepted an unexpected profile file: %v", err)
		}
	})

	t.Run("unsafe file permissions", func(t *testing.T) {
		opts, manager := createBackupPeerFixture(t, "phone")
		path := filepath.Join(opts.DataDir, "profiles", "phone.conf")
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
			t.Fatalf("backup accepted a world-readable client profile: %v", err)
		}
	})

	t.Run("profile exceeds per-file size limit", func(t *testing.T) {
		opts, manager := createBackupPeerFixture(t, "phone")
		path := filepath.Join(opts.DataDir, "profiles", "phone.conf")
		if err := os.Truncate(path, maxAWGBackupSize+1); err != nil {
			t.Fatal(err)
		}
		if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("backup accepted an oversized client profile: %v", err)
		}
	})
}

func TestCreateAWGBackupRejectsProfilesOverCombinedArchiveLimit(t *testing.T) {
	opts, manager := createBackupPeerFixture(t, "phone", "tablet")
	for _, name := range []string{"phone", "tablet"} {
		path := filepath.Join(opts.DataDir, "profiles", name+".conf")
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteString(strings.Repeat("#", 9<<20))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("extend profile %q: write=%v close=%v", name, writeErr, closeErr)
		}
	}
	if _, err := createAWGBackup(opts.DataDir, manager); err == nil || !strings.Contains(err.Error(), "exceeds the size limit") {
		t.Fatalf("backup accepted combined profiles above the archive limit: %v", err)
	}
}
