package control

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net/netip"
)

type fakeDevice struct {
	sets          []string
	ups           int
	closed        bool
	setErr        error
	setErrors     []error
	upErr         error
	failPeerApply bool
	failed        bool
	snapshot      string
	snapshotErr   error
}

func (d *fakeDevice) Set(config string) error {
	d.sets = append(d.sets, config)
	if len(d.setErrors) > 0 {
		err := d.setErrors[0]
		d.setErrors = d.setErrors[1:]
		if err != nil {
			return err
		}
	}
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

type observingFactory struct {
	device        *fakeDevice
	interfaceName string
	mtu           int
}

func (f *observingFactory) Open(interfaceName string, mtu int) (Device, error) {
	f.interfaceName = interfaceName
	f.mtu = mtu
	return f.device, nil
}

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

func TestKeyDerivationPropagatesCurveImplementationErrors(t *testing.T) {
	curveFailure := errors.New("curve implementation rejected point")
	if privateKey, publicKey, err := generateKeypairWith(bytes.NewReader(make([]byte, 32)), func([]byte, []byte) ([]byte, error) {
		return nil, curveFailure
	}); !errors.Is(err, curveFailure) || privateKey != "" || publicKey != "" {
		t.Fatalf("generateKeypairWith() = %q, %q, %v; want curve error", privateKey, publicKey, err)
	}
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if publicKey, encoded, err := derivePublicKeyWith(privateKey, func([]byte, []byte) ([]byte, error) {
		return nil, curveFailure
	}); !errors.Is(err, curveFailure) || publicKey != nil || encoded != "" {
		t.Fatalf("derivePublicKeyWith() = %x, %q, %v; want curve error", publicKey, encoded, err)
	}
}

func TestPeerMutationCoversOperationReceiptConflictsAndExpiredEnable(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AddPeerWithExpiry("bad-operation", publicKey, "invalid", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("AddPeerWithExpiry() invalid operation ID = %v", err)
	}
	serverPublicKey, _, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AddPeerWithExpiry("self", serverPublicKey, "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("AddPeerWithExpiry() with the server key = %v", err)
	}

	operationID := "0123456789abcdef0123456789abcdef"
	peer, _, err := manager.AddPeerForOperation("phone", publicKey, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetPeerEnabled(peer.Name, false); err != nil {
		t.Fatal(err)
	}
	receipt, ok := manager.OperationReceipt(operationID)
	if !ok || !receipt.Peer.Disabled {
		t.Fatalf("disable did not update create receipt: %+v, %v", receipt, ok)
	}
	future := time.Now().UTC().Add(time.Hour)
	if _, err := manager.SetPeerExpiry(peer.Name, &future); err != nil {
		t.Fatal(err)
	}
	receipt, _ = manager.OperationReceipt(operationID)
	if receipt.Peer.ExpiresAt == nil || !receipt.Peer.ExpiresAt.Equal(future) {
		t.Fatalf("expiry did not update create receipt: %+v", receipt)
	}

	manager.mu.Lock()
	delete(manager.state.Operations, operationID)
	manager.mu.Unlock()
	replayed, repeated, err := manager.AddPeerWithExpiry(peer.Name, publicKey, operationID, &future)
	if err != nil || !repeated || replayed.Name != peer.Name {
		t.Fatalf("AddPeerWithExpiry() same retry = %+v, %v, %v; want idempotent result", replayed, repeated, err)
	}
	changedExpiry := future.Add(time.Hour)
	if _, _, err := manager.AddPeerWithExpiry(peer.Name, publicKey, operationID, &changedExpiry); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("AddPeerWithExpiry() changed retry expiry = %v, want operation conflict", err)
	}

	if _, _, err := manager.AddPeerWithExpiry("expired", "not-base64", "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("AddPeerWithExpiry() accepted an invalid public-key encoding: %v", err)
	}
	expiredAt := time.Now().UTC().Add(-time.Second)
	_, anotherPublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AddPeerWithExpiry("expired", anotherPublicKey, "", &expiredAt); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetPeerEnabled("expired", false); err != nil {
		t.Fatalf("SetPeerEnabled() disable expired peer = %v", err)
	}
	if _, err := manager.SetPeerEnabled("expired", true); !errors.Is(err, ErrPeerExpired) {
		t.Fatalf("SetPeerEnabled() reenabled expired peer = %v", err)
	}
}

func TestPeerMutationReportsDerivationActivationAndPersistenceErrors(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	originalServerKey := manager.serverPrivateKey
	manager.serverPrivateKey = "invalid"
	if _, _, err := manager.AddPeerWithExpiry("derive-failure", publicKey, "", nil); err == nil {
		t.Fatal("AddPeerWithExpiry() accepted an invalid server key")
	}
	manager.serverPrivateKey = originalServerKey

	device.setErr = errors.New("activate failed")
	if _, _, err := manager.AddPeerWithExpiry("activate-failure", publicKey, "", nil); err == nil || !strings.Contains(err.Error(), "activate peer") {
		t.Fatalf("AddPeerWithExpiry() activation error = %v", err)
	}
	device.setErr = nil

	peer, err := manager.AddPeer("phone", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.RenderClientConfig(peer.Name, privateKey); err != nil {
		t.Fatalf("RenderClientConfig() before server-key mutation: %v", err)
	}
	manager.serverPrivateKey = "invalid"
	if _, err := manager.RenderClientConfig(peer.Name, privateKey); err == nil {
		t.Fatal("RenderClientConfig() accepted an invalid persisted server key")
	}
	manager.serverPrivateKey = originalServerKey
	if _, err := manager.SetPeerEnabled(peer.Name, false); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(opts.DataDir, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(statePath)
	device.sets = nil
	if _, err := manager.SetPeerEnabled(peer.Name, true); err == nil {
		t.Fatal("SetPeerEnabled() persisted a state over an occupied directory")
	}
	if len(device.sets) < 2 || !strings.Contains(device.sets[len(device.sets)-2], "allowed_ip=") || !strings.Contains(device.sets[len(device.sets)-1], "remove=true") {
		t.Fatalf("failed re-enable did not restore the prior device state: %#v", device.sets)
	}
}

func TestManagerOpenReportsPersistedStateAndMigrationFailures(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		opts := testOptions(t)
		if err := os.Mkdir(filepath.Join(opts.DataDir, "state.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil {
			t.Fatal("Open() accepted a directory as persisted state")
		}
	})
	t.Run("initial state write error", func(t *testing.T) {
		opts := testOptions(t)
		if err := os.Chmod(opts.DataDir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(opts.DataDir, 0o700)
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), "temporary file") {
			t.Fatalf("Open() initial state write error = %v", err)
		}
	})
	t.Run("migration write error", func(t *testing.T) {
		opts := testOptions(t)
		privateKey, _, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := sealPrivateKey(privateKey, opts.MasterKey)
		if err != nil {
			t.Fatal(err)
		}
		statePath := filepath.Join(opts.DataDir, "state.json")
		if err := writeState(statePath, persistedState{Version: 1, PrivateKeyEnvelope: envelope, Peers: []Peer{}}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(opts.DataDir, 0o500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(opts.DataDir, 0o700)
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), "migrate AWG state") {
			t.Fatalf("Open() migration write error = %v", err)
		}
	})
	t.Run("invalid peer state", func(t *testing.T) {
		opts := testOptions(t)
		privateKey, _, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := sealPrivateKey(privateKey, opts.MasterKey)
		if err != nil {
			t.Fatal(err)
		}
		state := persistedState{Version: stateVersion, PrivateKeyEnvelope: envelope, Peers: []Peer{{Name: "../bad"}}}
		if err := writeState(filepath.Join(opts.DataDir, "state.json"), state); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Open() invalid state error = %v", err)
		}
	})
}

func TestPeerMutationAndTelemetryHandleDeviceFailuresAndDisabledPeers(t *testing.T) {
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
	decodedKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	device.snapshot = "public_key=" + hex.EncodeToString(decodedKey) + "\nrx_bytes=1\ntx_bytes=2\n"
	if telemetry, err := manager.PeerTelemetry(); err != nil || len(telemetry) != 1 {
		t.Fatalf("PeerTelemetry() for active peer = %#v, %v", telemetry, err)
	}
	if _, err := manager.SetPeerEnabled(peer.Name, false); err != nil {
		t.Fatal(err)
	}
	if telemetry, err := manager.PeerTelemetry(); err != nil || len(telemetry) != 0 {
		t.Fatalf("PeerTelemetry() included disabled peer: %#v, %v", telemetry, err)
	}

	device.setErr = errors.New("remove failed")
	if err := manager.RemovePeer(peer.Name); err == nil || !strings.Contains(err.Error(), "deactivate peer") {
		t.Fatalf("RemovePeer() device error = %v", err)
	}
	if _, err := manager.RemovePeerForOperation(peer.Name, "fedcba9876543210fedcba9876543210"); err == nil || !strings.Contains(err.Error(), "deactivate peer") {
		t.Fatalf("RemovePeerForOperation() device error = %v", err)
	}
}

func TestPeerExpiryAndRemovalReportPersistenceFailures(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("phone", publicKey); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(opts.DataDir, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(statePath)
	future := time.Now().UTC().Add(time.Hour)
	if _, err := manager.SetPeerExpiry("phone", &future); err == nil {
		t.Fatal("SetPeerExpiry() persisted state over an occupied directory")
	}
	if _, err := manager.RemovePeerForOperation("missing", "fedcba9876543210fedcba9876543210"); err == nil {
		t.Fatal("RemovePeerForOperation() persisted receipt over an occupied directory")
	}
}

func TestApplyAllSkipsDisabledAndExpiredPeers(t *testing.T) {
	options := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(options, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, disabledKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := manager.AddPeer("disabled", disabledKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SetPeerEnabled(disabled.Name, false); err != nil {
		t.Fatal(err)
	}
	_, expiredKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	expiredAt := time.Now().UTC().Add(-time.Second)
	if _, _, err := manager.AddPeerWithExpiry("expired", expiredKey, "", &expiredAt); err != nil {
		t.Fatal(err)
	}
	device.sets = nil
	if err := manager.applyAllLocked(); err != nil {
		t.Fatal(err)
	}
	if len(device.sets) != 1 || strings.Contains(device.sets[0], "allowed_ip=") {
		t.Fatalf("applyAllLocked() did not skip unavailable peers: %#v", device.sets)
	}
}

func TestRestorePersistedStateValidatesAndRollsBackDeviceFailures(t *testing.T) {
	options := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(options, fakeFactory{device: device})
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
	currentData, err := os.ReadFile(filepath.Join(options.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RestorePersistedState([]byte(`{"version":2,"privateKeyEnvelope":"valid","peers":[{"name":"../bad"}]}`)); err == nil || !strings.Contains(err.Error(), "validate restored AWG state") {
		t.Fatalf("RestorePersistedState() invalid state = %v", err)
	}
	if err := manager.RestorePersistedState(currentData); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(options.DataDir, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestorePersistedState(currentData); err == nil || !strings.Contains(err.Error(), "persist restored AWG state") {
		t.Fatalf("RestorePersistedState() persistence error = %v", err)
	}
	if got := manager.Peers(); len(got) != 1 || got[0].Name != peer.Name {
		t.Fatalf("manager state was not retained after failed restore: %#v", got)
	}
	if err := os.RemoveAll(statePath); err != nil {
		t.Fatal(err)
	}

	nextPrivateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	nextEnvelope, err := sealPrivateKey(nextPrivateKey, options.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	nextData, err := json.Marshal(persistedState{Version: stateVersion, PrivateKeyEnvelope: nextEnvelope, Peers: []Peer{}})
	if err != nil {
		t.Fatal(err)
	}
	restoreFailure := errors.New("restored interface apply failed")
	device.setErrors = []error{nil, restoreFailure, nil, nil, nil}
	if err := manager.RestorePersistedState(nextData); err == nil || !strings.Contains(err.Error(), "apply restored AWG state") {
		t.Fatalf("RestorePersistedState() apply error = %v", err)
	}
	if got := manager.Peers(); len(got) != 1 || got[0].Name != peer.Name {
		t.Fatalf("manager state was not restored after apply failure: %#v", got)
	}

	device.setErrors = []error{errors.New("remove before restore failed"), errors.New("reapply current state failed")}
	if err := manager.RestorePersistedState(nextData); err == nil || !strings.Contains(err.Error(), "reapply current state") {
		t.Fatalf("RestorePersistedState() remove rollback error = %v", err)
	}
}

func TestRestoreDeviceLockedCoversRollbackFailurePaths(t *testing.T) {
	for _, test := range []struct {
		name      string
		failures  []error
		blockedDB bool
		wantError string
	}{
		{name: "remove peers and restore current state", failures: []error{errors.New("remove failed"), nil, nil}, wantError: "remove current AWG peers before restore"},
		{name: "remove peers and fail current-state recovery", failures: []error{errors.New("remove failed"), errors.New("reapply failed")}, wantError: "reapply current state"},
		{name: "restored state and fail rollback", failures: []error{nil, errors.New("apply restored failed"), nil, errors.New("rollback failed")}, wantError: "roll back live device"},
		{name: "persist restore and fail rollback", failures: []error{nil, nil, errors.New("remove during rollback failed"), errors.New("reapply during rollback failed")}, blockedDB: true, wantError: "roll back live device"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := testOptions(t)
			device := &fakeDevice{}
			manager, err := Open(options, fakeFactory{device: device})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			_, publicKey, err := GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.AddPeer("phone", publicKey); err != nil {
				t.Fatal(err)
			}
			nextPrivateKey, _, err := GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := sealPrivateKey(nextPrivateKey, options.MasterKey)
			if err != nil {
				t.Fatal(err)
			}
			nextData, err := json.Marshal(persistedState{Version: stateVersion, PrivateKeyEnvelope: envelope, Peers: []Peer{}})
			if err != nil {
				t.Fatal(err)
			}
			if test.blockedDB {
				statePath := filepath.Join(options.DataDir, "state.json")
				if err := os.Remove(statePath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(statePath, 0o700); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(statePath)
			}
			device.setErrors = test.failures
			err = manager.RestorePersistedState(nextData)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("RestorePersistedState() error = %v, want message containing %q", err, test.wantError)
			}
		})
	}
}

func TestValidateStateRejectsUnsupportedVersionAndZeroExpiry(t *testing.T) {
	options := testOptions(t)
	privateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealPrivateKey(privateKey, options.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	_, peerKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []persistedState{
		{Version: stateVersion + 1, PrivateKeyEnvelope: envelope},
		{Version: stateVersion, PrivateKeyEnvelope: envelope, Peers: []Peer{{Name: "phone", PublicKey: peerKey, IPv4: "10.88.0.2", IPv6: "fd88:88:88::2", ExpiresAt: &time.Time{}}}},
	} {
		if err := validateState(state, options); !errors.Is(err, ErrInvalid) && !strings.Contains(err.Error(), "unsupported AWG state version") {
			t.Fatalf("validateState() accepted invalid state: %v", err)
		}
	}
}

func TestRemovePeerForOperationRejectsInvalidAndReusedIDs(t *testing.T) {
	manager, err := Open(testOptions(t), fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, err := manager.RemovePeerForOperation("phone", "bad-id"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("RemovePeerForOperation() invalid ID = %v", err)
	}
	operationID := "abcdef0123456789abcdef0123456789"
	if alreadyRemoved, err := manager.RemovePeerForOperation("phone", operationID); err != nil || alreadyRemoved {
		t.Fatalf("RemovePeerForOperation() missing peer = %v, %v", alreadyRemoved, err)
	}
	if _, err := manager.RemovePeerForOperation("tablet", operationID); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("RemovePeerForOperation() reused ID = %v, want conflict", err)
	}
}

func TestApplyAllLockedRejectsInvalidServerAndHeaderKeys(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	originalPrivateKey := manager.serverPrivateKey
	manager.serverPrivateKey = "invalid"
	if err := manager.applyAllLocked(); err == nil || !strings.Contains(err.Error(), "invalid persisted server private key") {
		t.Fatalf("applyAllLocked() invalid server key = %v", err)
	}
	manager.serverPrivateKey = originalPrivateKey
	manager.opts.Obfuscation["header_protection_key"] = "invalid"
	if err := manager.applyAllLocked(); err == nil || !strings.Contains(err.Error(), "decode AmneziaWG header-protection key") {
		t.Fatalf("applyAllLocked() invalid header-protection key = %v", err)
	}
}

func TestOpenDefaultsInterfaceAndInitializesMissingStateCollections(t *testing.T) {
	opts := testOptions(t)
	opts.InterfaceName = ""
	privateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealPrivateKey(privateKey, opts.MasterKey)
	if err != nil {
		t.Fatal(err)
	}
	stateData, err := json.Marshal(persistedState{Version: stateVersion, PrivateKeyEnvelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(opts.DataDir, "state.json")
	if err := os.WriteFile(statePath, stateData, 0o600); err != nil {
		t.Fatal(err)
	}
	factory := &observingFactory{device: &fakeDevice{}}
	manager, err := Open(opts, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if factory.interfaceName != "awg0" || factory.mtu != 1280 {
		t.Fatalf("device opened with interface=%q mtu=%d, want awg0/1280", factory.interfaceName, factory.mtu)
	}
	if manager.state.Peers == nil || manager.state.Operations == nil {
		t.Fatalf("legacy state collections were not initialized: peers=%#v operations=%#v", manager.state.Peers, manager.state.Operations)
	}
}

func TestKeyEnvelopeAndPublicKeyRejectMalformedKeys(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x5a}, 32)
	if _, err := sealPrivateKey("not-base64", masterKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("seal malformed private key = %v", err)
	}
	if _, _, err := derivePublicKey("not-base64"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("derive public key from malformed private key = %v", err)
	}
	if _, err := openPrivateKey("not-base64", masterKey); err == nil {
		t.Fatal("open accepted malformed envelope encoding")
	}
	if _, err := openPrivateKey(base64.StdEncoding.EncodeToString([]byte("short")), masterKey); err == nil {
		t.Fatal("open accepted a truncated envelope")
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

func TestPeerExpiryIsReversibleAndDoesNotDeletePeerIdentity(t *testing.T) {
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
	deadline := time.Now().UTC().Add(time.Hour)
	peer, _, err := manager.AddPeerWithExpiry("phone", publicKey, "", &deadline)
	if err != nil || peer.ExpiresAt == nil || !peer.ExpiresAt.Equal(deadline) || peer.Disabled {
		t.Fatalf("AddPeerWithExpiry() = %+v, %v", peer, err)
	}
	past := time.Now().UTC().Add(-time.Second)
	if _, err := manager.SetPeerExpiry("phone", &past); err != nil {
		t.Fatal(err)
	}
	expired, err := manager.ExpireDuePeers(time.Now().UTC())
	if err != nil || len(expired) != 1 || !expired[0].Disabled {
		t.Fatalf("ExpireDuePeers() = %+v, %v", expired, err)
	}
	if len(manager.Peers()) != 1 || !manager.Peers()[0].Disabled {
		t.Fatalf("expiration removed or enabled the peer: %+v", manager.Peers())
	}
	if !strings.Contains(device.sets[len(device.sets)-1], "remove=true") {
		t.Fatalf("expiration did not remove the live UAPI peer: %q", device.sets[len(device.sets)-1])
	}
	if _, err := manager.SetPeerEnabled("phone", true); !errors.Is(err, ErrPeerExpired) {
		t.Fatalf("enabling expired peer = %v", err)
	}
	future := time.Now().UTC().Add(time.Hour)
	extended, err := manager.SetPeerExpiry("phone", &future)
	if err != nil || !extended.Disabled || extended.ExpiresAt == nil || !extended.ExpiresAt.Equal(future) {
		t.Fatalf("SetPeerExpiry() after expiration = %+v, %v", extended, err)
	}
	if _, err := manager.SetPeerEnabled("phone", true); err != nil {
		t.Fatalf("explicit re-enable after extension = %v", err)
	}
	if manager.Peers()[0].Disabled || len(manager.Peers()) != 1 {
		t.Fatalf("explicit enable did not restore retained peer: %+v", manager.Peers())
	}
}

func TestAWGExpiryManagerHandlesIdempotencyAndTransactionalFailures(t *testing.T) {
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
	if _, err := manager.AddPeer("phone", publicKey); err != nil {
		t.Fatal(err)
	}
	sets := len(device.sets)
	if _, err := manager.SetPeerEnabled("phone", true); err != nil || len(device.sets) != sets {
		t.Fatalf("idempotent enable changed runtime: sets=%d error=%v", len(device.sets), err)
	}
	if _, err := manager.SetPeerExpiry("missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expiry change for missing peer = %v", err)
	}
	device.setErr = errors.New("injected live device failure")
	if _, err := manager.SetPeerEnabled("phone", false); err == nil {
		t.Fatal("device failure while disabling was ignored")
	}
	device.setErr = nil
	past := time.Now().UTC().Add(-time.Second)
	if _, err := manager.SetPeerExpiry("phone", &past); err != nil {
		t.Fatal(err)
	}
	device.setErr = errors.New("injected expiry device failure")
	if expired, err := manager.ExpireDuePeers(time.Now().UTC()); err == nil || len(expired) != 0 || manager.Peers()[0].Disabled {
		t.Fatalf("failed expiry sweep = peers=%+v error=%v", expired, err)
	}
	device.setErr = nil
	statePath := filepath.Join(opts.DataDir, "state.json")
	backupPath := filepath.Join(opts.DataDir, "state.json.saved")
	if err := os.Rename(statePath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExpireDuePeers(time.Now().UTC()); err == nil || manager.Peers()[0].Disabled {
		t.Fatalf("state persistence failure did not roll back peer: %+v, error=%v", manager.Peers(), err)
	}
	if !strings.Contains(device.sets[len(device.sets)-1], "allowed_ip=10.88.0.2/32") {
		t.Fatalf("live peer was not restored after persistence failure: %q", device.sets[len(device.sets)-1])
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupPath, statePath); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if _, err := manager.SetPeerEnabled("phone", false); err == nil {
		t.Fatal("closed manager accepted peer state change")
	}
	if _, err := manager.SetPeerExpiry("phone", nil); err == nil {
		t.Fatal("closed manager accepted expiry change")
	}
	if _, err := manager.ExpireDuePeers(time.Now().UTC()); err == nil {
		t.Fatal("closed manager accepted expiration sweep")
	}
}

func TestAddPeerWithExpiryRejectsChangedExpiryForOperationRetry(t *testing.T) {
	manager, err := Open(testOptions(t), fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	operationID := "abcdef0123456789abcdef0123456789"
	deadline := time.Now().UTC().Add(time.Hour)
	if _, _, err := manager.AddPeerWithExpiry("phone", publicKey, operationID, &deadline); err != nil {
		t.Fatal(err)
	}
	different := deadline.Add(time.Second)
	if _, _, err := manager.AddPeerWithExpiry("phone", publicKey, operationID, &different); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation retry with a different expiry = %v", err)
	}
}

func TestAWGExpiryMethodsRejectClosedManager(t *testing.T) {
	manager, err := Open(testOptions(t), fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if _, _, err := manager.AddPeerWithExpiry("phone", "invalid", "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid create after close should validate input first: %v", err)
	}
}

func TestOldAWGStateMigratesExistingPeersAsEnabledAndUnlimited(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("old-phone", publicKey); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	statePath := filepath.Join(opts.DataDir, "state.json")
	state, err := readState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state.Version = 1
	state.Peers[0].ExpiresAt = nil
	state.Peers[0].Disabled = false
	if err := writeState(statePath, state); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatalf("open legacy state: %v", err)
	}
	defer restarted.Close()
	peers := restarted.Peers()
	if len(peers) != 1 || peers[0].Disabled || peers[0].ExpiresAt != nil {
		t.Fatalf("migrated legacy peer = %+v", peers)
	}
	migrated, err := readState(statePath)
	if err != nil || migrated.Version != stateVersion {
		t.Fatalf("persisted migrated state version = %d, %v", migrated.Version, err)
	}
}

func TestAddPeerForOperationIsIdempotentAndSurvivesRestart(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	if _, found := manager.PeerForOperation("invalid"); found {
		t.Fatal("peer lookup accepted a malformed operation ID")
	}
	if _, found := manager.OperationReceipt("invalid"); found {
		t.Fatal("receipt lookup accepted a malformed operation ID")
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	operationID := "abcdef0123456789abcdef0123456789"
	first, repeated, err := manager.AddPeerForOperation("iphone", publicKey, operationID)
	if err != nil || repeated {
		t.Fatalf("first AddPeerForOperation = %+v, repeated=%v, err=%v", first, repeated, err)
	}
	second, repeated, err := manager.AddPeerForOperation("iphone", publicKey, operationID)
	if err != nil || !repeated || second != first {
		t.Fatalf("repeated AddPeerForOperation = %+v, repeated=%v, err=%v", second, repeated, err)
	}
	if len(manager.Peers()) != 1 {
		t.Fatalf("retry created %d peers", len(manager.Peers()))
	}
	if _, _, err := manager.AddPeerForOperation("tablet", publicKey, operationID); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("operation ID reused for another peer = %v", err)
	}
	removeID := "fedcba9876543210fedcba9876543210"
	if repeated, err := manager.RemovePeerForOperation("iphone", removeID); err != nil || repeated {
		t.Fatalf("first RemovePeerForOperation = repeated=%v, err=%v", repeated, err)
	}
	_, replacementKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("iphone", replacementKey); err != nil {
		t.Fatalf("recreate peer name after revoke = %v", err)
	}
	if repeated, err := manager.RemovePeerForOperation("iphone", removeID); err != nil || !repeated {
		t.Fatalf("repeated RemovePeerForOperation = repeated=%v, err=%v", repeated, err)
	}
	if len(manager.Peers()) != 1 || manager.Peers()[0].PublicKey != replacementKey {
		t.Fatalf("old revoke removed the replacement peer: %+v", manager.Peers())
	}
	manager.Close()
	restarted, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restored, ok := restarted.PeerForOperation(operationID)
	if ok || restored != (Peer{}) {
		t.Fatalf("revoked create operation still appears active: %+v, found=%v", restored, ok)
	}
	if _, _, err := restarted.AddPeerForOperation("iphone", publicKey, operationID); !errors.Is(err, ErrOperationCompleted) {
		t.Fatalf("replayed revoked create = %v", err)
	}
	if repeated, err := restarted.RemovePeerForOperation("iphone", removeID); err != nil || !repeated || len(restarted.Peers()) != 1 {
		t.Fatalf("replayed revoke after restart removed replacement: repeated=%v err=%v peers=%+v", repeated, err, restarted.Peers())
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
	publicKeyBytes, err := decodeKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	device.snapshot = "private_key=must-not-be-returned\n\npublic_key=" + hex.EncodeToString(publicKeyBytes) + "\nendpoint=198.51.100.23:53122\nlast_handshake_time_sec=1790798400\nlast_handshake_time_nsec=0\nrx_bytes=420\ntx_bytes=840\n"
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
		{name: "invalid peer operation ID", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Peers: []Peer{{Name: "phone", PublicKey: validPeerKey, IPv4: validPeer.IPv4, IPv6: validPeer.IPv6, OperationID: "bad"}}}},
		{name: "invalid operation receipt key", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Operations: map[string]OperationReceipt{"bad": {Action: "remove", Name: "phone"}}}},
		{name: "invalid operation receipt action", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Operations: map[string]OperationReceipt{"abcdef0123456789abcdef0123456789": {Action: "edit", Name: "phone"}}}},
		{name: "mismatched create receipt", state: persistedState{Version: stateVersion, PrivateKeyEnvelope: state.PrivateKeyEnvelope, Operations: map[string]OperationReceipt{"abcdef0123456789abcdef0123456789": {Action: "create", Name: "phone", Peer: Peer{Name: "tablet"}}}}},
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
	if err := os.WriteFile(statePath, []byte(`{"version":99,"privateKeyEnvelope":"x"}`), 0o600); err != nil {
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
