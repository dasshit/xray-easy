package control

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net/netip"
)

type fakeDevice struct {
	sets          []string
	ups           int
	closed        bool
	setErr        error
	upErr         error
	failPeerApply bool
	failed        bool
	snapshot      string
	snapshotErr   error
}

func (d *fakeDevice) Set(config string) error {
	d.sets = append(d.sets, config)
	if d.setErr != nil {
		return d.setErr
	}
	if d.failPeerApply && !d.failed && strings.Contains(config, "allowed_ip=") {
		d.failed = true
		return errors.New("injected device set failure")
	}
	return nil
}
func (d *fakeDevice) Up() error                 { d.ups++; return d.upErr }
func (d *fakeDevice) Snapshot() (string, error) { return d.snapshot, d.snapshotErr }
func (d *fakeDevice) Close()                    { d.closed = true }

type fakeFactory struct {
	device *fakeDevice
	err    error
}

func (f fakeFactory) Open(string, int) (Device, error) { return f.device, f.err }

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		DataDir: t.TempDir(), MasterKey: bytes.Repeat([]byte{0x5a}, 32), PublicHost: "vpn.example.test", PublicPort: 51820, ListenPort: 51820,
		IPv4Prefix:    netip.MustParsePrefix("10.88.0.0/29"),
		IPv6Prefix:    netip.MustParsePrefix("fd88:88:88::/64"),
		DNS:           []string{"1.1.1.1", "2606:4700:4700::1111"},
		InterfaceName: "awg0",
		Obfuscation:   map[string]string{"jc": "4", "jmin": "40", "jmax": "70", "h1": "123456"},
	}
}

func TestGenerateKeypairProducesMatchingPublicKey(t *testing.T) {
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, derived, err := derivePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != publicKey {
		t.Fatalf("derived public key %q does not match generated key %q", derived, publicKey)
	}
}

func TestAddPeerAppliesLiveAndPersistsAllocatedAddresses(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if device.ups != 1 {
		t.Fatalf("engine starts = %d, want 1", device.ups)
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.AddPeer("iphone-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if peer.IPv4 != "10.88.0.2" || peer.IPv6 != "fd88:88:88::2" {
		t.Fatalf("unexpected allocation: %+v", peer)
	}
	if device.ups != 1 {
		t.Fatalf("adding peer restarted engine %d times", device.ups-1)
	}
	if len(device.sets) != 2 || !strings.Contains(device.sets[1], "public_key=") || !strings.Contains(device.sets[1], "allowed_ip=10.88.0.2/32") {
		t.Fatalf("live peer UAPI was not applied: %#v", device.sets)
	}
	profile, err := manager.RenderClientConfig("iphone-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"PrivateKey = " + privateKey,
		"Address = 10.88.0.2/32, fd88:88:88::2/128",
		"DNS = 1.1.1.1, 2606:4700:4700::1111",
		"Jc = 4", "Jmin = 40", "H1 = 123456",
		"AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = vpn.example.test:51820",
	} {
		if !strings.Contains(profile, expected) {
			t.Errorf("profile missing %q:\n%s", expected, profile)
		}
	}
	stateInfo, err := os.Stat(filepath.Join(opts.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0600 {
		t.Errorf("state mode = %04o, want 0600", stateInfo.Mode().Perm())
	}
	if strings.Contains(string(mustRead(t, filepath.Join(opts.DataDir, "state.json"))), privateKey) {
		t.Fatal("client private key was persisted in server state")
	}
	if strings.Contains(string(mustRead(t, filepath.Join(opts.DataDir, "state.json"))), manager.serverPrivateKey) {
		t.Fatal("server private key was not encrypted in persistent state")
	}
}

func TestPeerTelemetryJoinsLiveUAPICountersToManagedPeer(t *testing.T) {
	device := &fakeDevice{}
	manager, err := Open(testOptions(t), fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("iphone", publicKey); err != nil {
		t.Fatal(err)
	}
	device.snapshot = "private_key=must-not-be-returned\n\npublic_key=" + publicKey + "\nendpoint=198.51.100.23:53122\nlast_handshake_time_sec=1790798400\nlast_handshake_time_nsec=0\nrx_bytes=420\ntx_bytes=840\n"
	rows, err := manager.PeerTelemetry()
	if err != nil || len(rows) != 1 {
		t.Fatalf("PeerTelemetry() = %+v, %v", rows, err)
	}
	got := rows[0]
	if got.Name != "iphone" || got.SourceIP != "198.51.100.23" || got.UploadBytes != 420 || got.DownloadBytes != 840 || got.LastHandshake.IsZero() {
		t.Fatalf("peer runtime stats = %+v", got)
	}
}

func TestEndpointIPAcceptsIPSocketAddressesAndIgnoresInvalidEndpoints(t *testing.T) {
	for _, test := range []struct {
		endpoint string
		want     string
	}{
		{endpoint: "198.51.100.8:51820", want: "198.51.100.8"},
		{endpoint: "[2001:db8::8]:51820", want: "2001:db8::8"},
		{endpoint: "[fe80::1%eth0]:51820", want: "fe80::1"},
		{endpoint: "vpn.example.test:51820"},
		{endpoint: "not-an-endpoint"},
		{endpoint: "hostname:port"},
	} {
		if got := endpointIP(test.endpoint); got != test.want {
			t.Errorf("endpointIP(%q) = %q, want %q", test.endpoint, got, test.want)
		}
	}
}

func TestRemovePeerIsAppliedLiveAndRestoredAfterReopen(t *testing.T) {
	opts := testOptions(t)
	firstDevice := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: firstDevice})
	if err != nil {
		t.Fatal(err)
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("macbook", publicKey); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemovePeer("macbook"); err != nil {
		t.Fatal(err)
	}
	if len(manager.Peers()) != 0 || !strings.Contains(firstDevice.sets[len(firstDevice.sets)-1], "remove=true") {
		t.Fatalf("peer was not removed live: %+v / %#v", manager.Peers(), firstDevice.sets)
	}
	manager.Close()
	secondDevice := &fakeDevice{}
	secondManager, err := Open(opts, fakeFactory{device: secondDevice})
	if err != nil {
		t.Fatal(err)
	}
	defer secondManager.Close()
	if len(secondManager.Peers()) != 0 {
		t.Fatalf("removed peer returned after process restart: %+v", secondManager.Peers())
	}
	if len(secondDevice.sets) != 1 {
		t.Fatalf("removed peer unexpectedly restored: %#v", secondDevice.sets)
	}
}

func TestRemovePeerRestoresLivePeerWhenStateFileCannotBeReplaced(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.AddPeer("phone", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(opts.DataDir, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemovePeer("phone"); err == nil {
		t.Fatal("RemovePeer succeeded when the persisted state could not be replaced")
	}
	if got := manager.Peers(); len(got) != 1 || got[0] != peer {
		t.Fatalf("failed persisted removal changed manager state: %+v", got)
	}
	if config := device.sets[len(device.sets)-1]; !strings.Contains(config, "public_key=") || !strings.Contains(config, "allowed_ip="+peer.IPv4+"/32") || strings.Contains(config, "remove=true") {
		t.Fatalf("failed persisted removal did not re-activate peer: %q", config)
	}
}

func TestManagerRejectsDuplicateAndInvalidPeer(t *testing.T) {
	device := &fakeDevice{}
	manager, err := Open(testOptions(t), fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, _ := GenerateKeypair()
	if _, err := manager.AddPeer("bad name", publicKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid name error = %v", err)
	}
	if _, err := manager.AddPeer("iphone", "not-a-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := manager.AddPeer("iphone", publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("iphone", publicKey); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := manager.RenderClientConfig("iphone", "not-a-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid profile key error = %v", err)
	}
	otherPrivate, _, _ := GenerateKeypair()
	if _, err := manager.RenderClientConfig("iphone", otherPrivate); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched profile key error = %v", err)
	}
}

func TestAddressPoolDoesNotAllocateNetworkGatewayOrBroadcast(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, want := range []string{"10.88.0.2", "10.88.0.3", "10.88.0.4", "10.88.0.5", "10.88.0.6"} {
		_, pub, _ := GenerateKeypair()
		peer, err := manager.AddPeer("peer"+strings.ReplaceAll(want, ".", ""), pub)
		if err != nil {
			t.Fatalf("allocate %s: %v", want, err)
		}
		if peer.IPv4 != want {
			t.Errorf("allocated %s, want %s", peer.IPv4, want)
		}
	}
	_, pub, _ := GenerateKeypair()
	if _, err := manager.AddPeer("full", pub); !errors.Is(err, ErrInvalid) {
		t.Fatalf("exhausted pool error = %v", err)
	}
}

func TestLoadOrCreateTokenIsPersistentAndPrivate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "token-dir")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.token")
	first, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("token changed between loads")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("token mode = %04o, want 0640", info.Mode().Perm())
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0700 {
		t.Errorf("existing token directory mode = %04o, want it unchanged at 0700", directoryInfo.Mode().Perm())
	}
}

func TestLoadOrCreateTokenRejectsInsecureFilesAndBlockedPaths(t *testing.T) {
	root := t.TempDir()
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	tokenPath := filepath.Join(root, "writable.token")
	if err := os.WriteFile(tokenPath, []byte(valid), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(tokenPath); err == nil {
		t.Fatal("group/world-writable control token was accepted")
	}
	blocked := filepath.Join(root, "not-directory")
	if err := os.WriteFile(blocked, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(filepath.Join(blocked, "token")); err == nil {
		t.Fatalf("blocked token parent error = %v", err)
	}
	if _, err := LoadOrCreateToken(root); err == nil {
		t.Fatal("directory path was accepted as a token file")
	}
}

func TestEncryptedServerKeyRequiresOriginalMasterKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	opts.MasterKey = bytes.Repeat([]byte{0xa5}, 32)
	if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), "decrypt persisted AWG server key") {
		t.Fatalf("wrong master key error = %v", err)
	}
}

func TestOptionsRejectHostInjectionAndInvalidObfuscation(t *testing.T) {
	for _, mutate := range []func(*Options){
		func(opts *Options) { opts.PublicHost = "vpn.example\n[Peer]" },
		func(opts *Options) { opts.InterfaceName = "interface-name-too-long" },
		func(opts *Options) { opts.Obfuscation = map[string]string{"jc": "4\nremove=true"} },
		func(opts *Options) { opts.Obfuscation = map[string]string{"made-up": "1"} },
		func(opts *Options) { opts.Obfuscation = map[string]string{"header_protection_key": "not-a-key"} },
	} {
		opts := testOptions(t)
		mutate(&opts)
		if err := opts.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("validate error = %v, want invalid", err)
		}
	}
}

func TestManagerOpenCleansUpEveryFailedStartupStage(t *testing.T) {
	t.Run("invalid options", func(t *testing.T) {
		opts := testOptions(t)
		opts.MasterKey = nil
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid options error = %v", err)
		}
	})
	t.Run("data directory", func(t *testing.T) {
		opts := testOptions(t)
		if err := os.RemoveAll(opts.DataDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(opts.DataDir, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), "create AWG data directory") {
			t.Fatalf("invalid data directory error = %v", err)
		}
	})
	for _, test := range []struct {
		name    string
		factory fakeFactory
		want    string
	}{
		{name: "factory", factory: fakeFactory{err: errors.New("factory failed")}, want: "create AmneziaWG device"},
		{name: "initial configuration", factory: fakeFactory{device: &fakeDevice{setErr: errors.New("set failed")}}, want: "set failed"},
		{name: "device up", factory: fakeFactory{device: &fakeDevice{upErr: errors.New("up failed")}}, want: "bring AmneziaWG device up"},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := testOptions(t)
			_, err := Open(opts, test.factory)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startup error = %v, want %q", err, test.want)
			}
			if test.factory.device != nil && !test.factory.device.closed {
				t.Fatal("failed device was not closed")
			}
		})
	}
}

func TestPersistedAWGStateRejectsCorruptionUnsafePermissionsAndInvalidPeers(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	statePath := filepath.Join(opts.DataDir, "state.json")
	state, err := readState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	_, validPeerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	validPeer := Peer{Name: "phone", PublicKey: validPeerKey, IPv4: "10.88.0.2", IPv6: "fd88:88:88::2"}
	for _, test := range []struct {
		name  string
		state persistedState
	}{
		{name: "missing server key", state: persistedState{Version: stateVersion}},
		{name: "invalid name", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "../bad", PublicKey: validPeerKey, IPv4: validPeer.IPv4, IPv6: validPeer.IPv6}}}},
		{name: "invalid public key", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "phone", PublicKey: "bad", IPv4: validPeer.IPv4, IPv6: validPeer.IPv6}}}},
		{name: "gateway address", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "phone", PublicKey: validPeerKey, IPv4: "10.88.0.1", IPv6: validPeer.IPv6}}}},
		{name: "broadcast address", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "phone", PublicKey: validPeerKey, IPv4: "10.88.0.7", IPv6: validPeer.IPv6}}}},
		{name: "invalid IPv6", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "phone", PublicKey: validPeerKey, IPv4: validPeer.IPv4, IPv6: "2001:db8::2"}}}},
		{name: "duplicate identity", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{validPeer, validPeer}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateState(test.state, opts); err == nil {
				t.Fatal("invalid persisted state was accepted")
			}
		})
	}
	if _, err := readState(filepath.Join(opts.DataDir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing persisted state error = %v", err)
	}
	if err := os.WriteFile(statePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(statePath); err == nil || !strings.Contains(err.Error(), "decode AWG state") {
		t.Fatalf("malformed persisted state = %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"version":2,"privateKeyEnvelope":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(statePath); err == nil || !strings.Contains(err.Error(), "unsupported AWG state version") {
		t.Fatalf("unsupported state version = %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"version":1,"privateKeyEnvelope":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(statePath); err == nil || !strings.Contains(err.Error(), "permissions are too broad") {
		t.Fatalf("unsafe state permissions = %v", err)
	}
}

func TestClosedManagerAndTelemetryErrorsAreReported(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	device.snapshotErr = errors.New("snapshot failed")
	if _, err := manager.PeerTelemetry(); err == nil || !strings.Contains(err.Error(), "read AWG peer telemetry") {
		t.Fatalf("snapshot failure = %v", err)
	}
	device.snapshotErr = nil
	device.snapshot = "public_key=broken\nrx_bytes=not-a-number\n"
	if _, err := manager.PeerTelemetry(); err == nil {
		t.Fatal("invalid live telemetry snapshot was accepted")
	}
	stateData, err := os.ReadFile(filepath.Join(opts.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RestorePersistedState([]byte("{")); err == nil || !strings.Contains(err.Error(), "decode restored AWG state") {
		t.Fatalf("malformed restore state = %v", err)
	}
	if err := manager.RestorePersistedState([]byte(`{"version":1,"privateKeyEnvelope":"bad"}`)); err == nil || !strings.Contains(err.Error(), "decrypt restored AWG server key") {
		t.Fatalf("invalid restore key envelope = %v", err)
	}
	manager.Close()
	if err := manager.RestorePersistedState(stateData); err == nil || !strings.Contains(err.Error(), "manager is closed") {
		t.Fatalf("restore on closed manager = %v", err)
	}
	if _, _, err := manager.Status(); err == nil {
		t.Fatal("closed manager returned a server status")
	}
	if _, err := manager.PeerTelemetry(); err == nil {
		t.Fatal("closed manager returned peer telemetry")
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("phone", publicKey); err == nil {
		t.Fatal("closed manager accepted a new peer")
	}
	if err := manager.RemovePeer("phone"); err == nil {
		t.Fatal("closed manager removed a peer")
	}
	if _, err := manager.RenderClientConfig("phone", publicKey); err == nil {
		t.Fatal("closed manager rendered a peer profile")
	}
}

func TestWriteStateAndPeerLifecycleRollBackFilesystemFailures(t *testing.T) {
	root := t.TempDir()
	if err := writeState(filepath.Join(root, "state.json"), persistedState{Version: stateVersion, Peers: []Peer{}}); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeState(filepath.Join(blocked, "state.json"), persistedState{Version: stateVersion}); err != nil {
		t.Fatalf("write state in an existing directory: %v", err)
	}
	// A directory at the destination prevents atomic activation after the
	// temporary file has been written and synced.
	if err := os.Mkdir(filepath.Join(root, "occupied.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeState(filepath.Join(root, "occupied.json"), persistedState{Version: stateVersion}); err == nil {
		t.Fatal("writeState replaced an occupied destination directory")
	}

	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(opts.DataDir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(opts.DataDir, "state.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("rollback", publicKey); err == nil {
		t.Fatal("AddPeer succeeded although persistent state could not be replaced")
	}
	if len(manager.Peers()) != 0 || !strings.Contains(device.sets[len(device.sets)-1], "remove=true") {
		t.Fatalf("failed peer creation was not removed from live device: peers=%+v sets=%v", manager.Peers(), device.sets)
	}
	manager.Close()
}

func TestWriteStateReportsTemporaryFileAndActivationFailures(t *testing.T) {
	state := persistedState{Version: stateVersion, Peers: []Peer{}}
	if err := writeState(filepath.Join(t.TempDir(), "missing", "state.json"), state); err == nil || !strings.Contains(err.Error(), "temporary file") {
		t.Fatalf("writeState with a missing parent = %v", err)
	}

	root := t.TempDir()
	target := filepath.Join(root, "state.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeState(target, state); err == nil || !strings.Contains(err.Error(), "activate AWG state") {
		t.Fatalf("writeState replacing a directory = %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("failed write left temporary state files: entries=%v err=%v", entries, err)
	}
}

type faultStateFile struct {
	*os.File
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
}

func (f *faultStateFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *faultStateFile) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.Write(data)
}

func (f *faultStateFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultStateFile) Close() error {
	actualErr := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return actualErr
}

func TestWriteStateCleansTemporaryFilesAfterIOErrors(t *testing.T) {
	chmodErr := errors.New("injected chmod failure")
	writeErr := errors.New("injected write failure")
	syncErr := errors.New("injected sync failure")
	closeErr := errors.New("injected close failure")
	for _, test := range []struct {
		name string
		file *faultStateFile
		want string
	}{
		{name: "chmod", file: &faultStateFile{chmodErr: chmodErr}, want: "secure AWG state"},
		{name: "write", file: &faultStateFile{writeErr: writeErr}, want: "write AWG state"},
		{name: "sync", file: &faultStateFile{syncErr: syncErr}, want: "sync AWG state"},
		{name: "close", file: &faultStateFile{closeErr: closeErr}, want: "close AWG state"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "state.json")
			if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := writeStateWith(target, persistedState{Version: stateVersion}, func(dir, pattern string) (stateTempFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				test.file.File = file
				return test.file, nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("writeStateWith error = %v, want %q", err, test.want)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "original" {
				t.Fatalf("failed write changed persisted state: %q, %v", data, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 {
				t.Fatalf("failed write left temporary state files: %v, %v", entries, err)
			}
		})
	}
	if err := writeStateWith(filepath.Join(t.TempDir(), "state.json"), persistedState{Version: stateVersion}, func(string, string) (stateTempFile, error) {
		return nil, errors.New("temporary file unavailable")
	}); err == nil || !strings.Contains(err.Error(), "temporary file") {
		t.Fatalf("writeStateWith create failure = %v", err)
	}
}

func TestHeaderProtectionUsesHexInUAPIAndBase64InClientProfile(t *testing.T) {
	opts := testOptions(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	opts.Obfuscation = map[string]string{
		"header_protection_key": key,
		"s1":                    "12", "s2": "12", "s3": "12", "s4": "12",
	}
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if !strings.Contains(device.sets[0], "header_protection_key="+strings.Repeat("00", 32)) {
		t.Fatalf("UAPI must receive hex-encoded header key: %q", device.sets[0])
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "HeaderProtectionKey = "+key) || !strings.Contains(profile, "S1 = 12") {
		t.Fatalf("client profile lost AWG 3 header-protection parameters:\n%s", profile)
	}
}

func TestBooleanObfuscationOverridesUseClientOnOffFormat(t *testing.T) {
	opts := testOptions(t)
	opts.Obfuscation["random_trailers"] = "true"
	opts.Obfuscation["disable_cookies"] = "false"
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if !strings.Contains(device.sets[0], "random_trailers=true") || !strings.Contains(device.sets[0], "disable_cookies=false") {
		t.Fatalf("UAPI bool values were not normalized: %q", device.sets[0])
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "RandomTrailers = on") || !strings.Contains(profile, "DisableCookies = off") {
		t.Fatalf("client profile bool values are not on/off: %s", profile)
	}
}

func TestDefaultAWG3PresetConfiguresEngineAndClientProfileConsistently(t *testing.T) {
	opts := testOptions(t)
	opts.Obfuscation = DefaultObfuscation(opts.MasterKey)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, expected := range []string{
		"jc=4", "jmin=10", "jmax=50", "s1=12", "s2=12", "s3=12", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4", "random_trailers=true", "disable_cookies=true",
		"content_padding_addition=10-100", "rekey_after_time=100-120", "max_handshake_attempts=15-20",
	} {
		if !strings.Contains(device.sets[0], expected) {
			t.Errorf("server UAPI config missing %q", expected)
		}
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Jc = 4", "Jmin = 10", "Jmax = 50", "S1 = 12", "S2 = 12", "S3 = 12", "S4 = 12",
		"H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4", "RandomTrailers = on", "DisableCookies = on",
		"ContentPaddingAddition = 10-100", "RekeyAfterTime = 100-120",
	} {
		if !strings.Contains(profile, expected) {
			t.Errorf("client profile missing %q", expected)
		}
	}
}

func TestOptionsValidateAllNetworkAndObfuscationConstraints(t *testing.T) {
	cases := map[string]func(*Options){
		"missing directory":          func(o *Options) { o.DataDir = "  " },
		"missing public host":        func(o *Options) { o.PublicHost = "" },
		"host with URL syntax":       func(o *Options) { o.PublicHost = "https://vpn.example.test" },
		"zero public port":           func(o *Options) { o.PublicPort = 0 },
		"zero listen port":           func(o *Options) { o.ListenPort = 0 },
		"IPv4 pool has wrong family": func(o *Options) { o.IPv4Prefix = netip.MustParsePrefix("fd88::/64") },
		"IPv4 pool too narrow":       func(o *Options) { o.IPv4Prefix = netip.MustParsePrefix("10.0.0.0/30") },
		"IPv6 pool has wrong family": func(o *Options) { o.IPv6Prefix = netip.MustParsePrefix("10.0.0.0/24") },
		"IPv6 pool too narrow":       func(o *Options) { o.IPv6Prefix = netip.MustParsePrefix("fd00::/121") },
		"noncanonical IPv4 pool":     func(o *Options) { o.IPv4Prefix = netip.MustParsePrefix("10.88.0.1/29") },
		"noncanonical IPv6 pool":     func(o *Options) { o.IPv6Prefix = netip.MustParsePrefix("fd88:88:88::1/64") },
		"invalid DNS":                func(o *Options) { o.DNS = []string{"dns.example.test"} },
		"header key without padding": func(o *Options) {
			o.Obfuscation = map[string]string{"header_protection_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}
		},
		"header key with too-small padding": func(o *Options) {
			o.Obfuscation = map[string]string{"header_protection_key": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "s1": "11", "s2": "12", "s3": "12", "s4": "12"}
		},
		"bad boolean parameter": func(o *Options) { o.Obfuscation["random_trailers"] = "yes" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			opts := testOptions(t)
			mutate(&opts)
			if err := opts.validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("validate() = %v, want ErrInvalid", err)
			}
		})
	}
	for _, host := range []string{"8.8.8.8", "2001:4860:4860::8888", "vpn.example.test", "vpn.example.test."} {
		if !validPublicHost(host) {
			t.Errorf("valid public host %q was rejected", host)
		}
	}
	for _, host := range []string{"", "-bad.example", "bad..example", strings.Repeat("x", 254)} {
		if validPublicHost(host) {
			t.Errorf("invalid public host %q was accepted", host)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
