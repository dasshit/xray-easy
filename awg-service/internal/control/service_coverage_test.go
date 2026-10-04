package control

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	awgapi "xray-easy/awg-contract/api/v1"
)

type failingKeyRandomReader struct{}

func (failingKeyRandomReader) Read([]byte) (int, error) {
	return 0, errors.New("injected key entropy failure")
}

func TestRemoveOrphanedOperationKeysKeepsRecoverableIntent(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)

	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	activeID := "0123456789abcdef0123456789abcdef"
	activePeer, _, err := manager.AddPeerForOperation("active", publicKey, activeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.persistPeerProfile(activePeer, privateKey, ""); err != nil {
		t.Fatal(err)
	}

	_, missingProfilePublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	missingProfileID := "abcdef0123456789abcdef0123456789"
	if _, _, err := manager.AddPeerForOperation("interrupted", missingProfilePublicKey, missingProfileID); err != nil {
		t.Fatal(err)
	}

	operations := filepath.Join(options.DataDir, "operations")
	if err := os.MkdirAll(operations, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		activeID + ".key":         privateKey,
		missingProfileID + ".key": "stale-key",
		"orphan.key":              "orphan-key",
		"notes.txt":               "keep this unrelated file",
	} {
		if err := os.WriteFile(filepath.Join(operations, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(operations, "nested.key"), 0o700); err != nil {
		t.Fatal(err)
	}

	NewService(manager, options)

	for _, name := range []string{missingProfileID + ".key", "notes.txt", "nested.key"} {
		if _, err := os.Lstat(filepath.Join(operations, name)); err != nil {
			t.Errorf("cleanup removed preserved entry %q: %v", name, err)
		}
	}
	for _, name := range []string{activeID + ".key", "orphan.key"} {
		if _, err := os.Lstat(filepath.Join(operations, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cleanup retained orphaned entry %q: %v", name, err)
		}
	}
}

func TestPersistPeerProfileReportsRenderAndReceiptFailures(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.AddPeer("phone", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.persistPeerProfile(Peer{Name: "missing"}, privateKey, ""); err == nil {
		t.Fatal("persistPeerProfile() succeeded for an unknown peer")
	}
	if err := service.persistPeerProfile(peer, privateKey, "invalid-operation-id"); err == nil {
		t.Fatal("persistPeerProfile() succeeded with an invalid receipt ID")
	}
}

func TestClientProfileHelpersRejectInvalidPathsAndMkdirFailures(t *testing.T) {
	if _, err := clientProfilePath("", "phone"); err == nil {
		t.Fatal("clientProfilePath() accepted an empty data directory")
	}
	if _, err := clientProfilePath(t.TempDir(), "../phone"); err == nil {
		t.Fatal("clientProfilePath() accepted a path traversal name")
	}
	if _, err := readClientProfile(t.TempDir(), "../phone"); err == nil {
		t.Fatal("readClientProfile() accepted an invalid peer name")
	}
	if err := writeClientProfile(t.TempDir(), "../phone", "profile"); err == nil {
		t.Fatal("writeClientProfile() accepted an invalid peer name")
	}

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "profiles"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClientProfile(dataDir, "phone", "profile"); err == nil {
		t.Fatal("writeClientProfile() succeeded when profiles parent is a file")
	}
}

func TestExpiryFromProtoRejectsTimestampOutsideProtobufRange(t *testing.T) {
	now := timestamppb.Now().AsTime()
	invalid := &timestamppb.Timestamp{Seconds: 253402300800}
	if _, err := expiryFromProto(invalid, now); err == nil {
		t.Fatal("expiryFromProto() accepted a timestamp outside the protobuf range")
	}
	if deadline, err := expiryFromProto(nil, now); err != nil || deadline != nil {
		t.Fatalf("expiryFromProto(nil) = %v, %v; want nil, nil", deadline, err)
	}
	future := timestamppb.New(now.Add(time.Minute))
	deadline, err := expiryFromProto(future, now)
	if err != nil || deadline == nil || !deadline.Equal(future.AsTime()) {
		t.Fatalf("expiryFromProto(future) = %v, %v", deadline, err)
	}
	if _, err := expiryFromProto(timestamppb.New(now), now); err == nil {
		t.Fatal("expiryFromProto() accepted a deadline equal to now")
	}
}

func TestReadPendingOperationKeyRejectsInvalidDataDirectoryAndMalformedKey(t *testing.T) {
	if _, err := readPendingOperationKey("", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("readPendingOperationKey() accepted an empty data directory")
	}
	dataDir := t.TempDir()
	operations := filepath.Join(dataDir, "operations")
	if err := os.MkdirAll(operations, 0o700); err != nil {
		t.Fatal(err)
	}
	operationID := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(operations, operationID+".key")
	if err := os.WriteFile(path, []byte("not-a-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPendingOperationKey(dataDir, operationID); err == nil {
		t.Fatal("readPendingOperationKey() accepted malformed key material")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPendingOperationKey(dataDir, operationID); err == nil {
		t.Fatal("readPendingOperationKey() accepted an unsafe mode")
	}
	if err := removePendingOperationKey(dataDir, operationID); err != nil {
		t.Fatalf("removePendingOperationKey() tolerated missing key: %v", err)
	}
	if err := removePendingOperationKey(dataDir, operationID); err != nil {
		t.Fatalf("removePendingOperationKey() should be idempotent: %v", err)
	}
	if err := removePendingOperationKey(dataDir, "bad-id"); err == nil {
		t.Fatal("removePendingOperationKey() accepted an invalid operation ID")
	}
}

func TestCreatePeerCoversNilAndInterruptedRecoveryFailures(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	if _, err := service.CreatePeer(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreatePeer(nil) = %v, want InvalidArgument", err)
	}

	operationID := "0123456789abcdef0123456789abcdef"
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	peer, _, err := manager.AddPeerWithExpiry("phone", publicKey, operationID, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	if _, err := service.CreatePeer(ctx, &awgapi.CreatePeerRequest{Name: peer.Name}); status.Code(err) != codes.Aborted {
		t.Fatalf("CreatePeer() reusing an operation with a different expiry = %v, want Aborted", err)
	}

	operations := filepath.Join(options.DataDir, "operations")
	if err := os.MkdirAll(operations, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operations, operationID+".key"), []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(ctx, &awgapi.CreatePeerRequest{Name: peer.Name, ExpiresAt: timestamppb.New(expiresAt)}); status.Code(err) != codes.Internal {
		t.Fatalf("CreatePeer() recovery with malformed private key = %v, want Internal", err)
	}

	secondOperationID := "abcdef0123456789abcdef0123456789"
	privateKey, recoveryPublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AddPeerForOperation("recovery", recoveryPublicKey, secondOperationID); err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(options.DataDir, secondOperationID, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.DataDir, "profiles"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	recoveryContext := context.WithValue(context.Background(), operationIDKey, secondOperationID)
	if _, err := service.CreatePeer(recoveryContext, &awgapi.CreatePeerRequest{Name: "recovery"}); status.Code(err) != codes.Internal {
		t.Fatalf("CreatePeer() recovery with an unwritable profile location = %v, want Internal", err)
	}
}

func TestCreatePeerUsesPersistedKeyAndReportsKeyGenerationFailures(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	operationID := "0123456789abcdef0123456789abcdef"
	privateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(options.DataDir, operationID, privateKey); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	if _, err := service.CreatePeer(ctx, &awgapi.CreatePeerRequest{Name: "recovered-key"}); err != nil {
		t.Fatalf("CreatePeer() with a saved client key = %v", err)
	}

	previousReader := cryptorand.Reader
	cryptorand.Reader = failingKeyRandomReader{}
	defer func() { cryptorand.Reader = previousReader }()
	_, err = service.CreatePeer(context.Background(), &awgapi.CreatePeerRequest{Name: "entropy-failure"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "generate peer keypair") {
		t.Fatalf("CreatePeer() key-generation error = %v", err)
	}
}

func TestCreatePeerReportsPendingKeyPersistenceFailure(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	operations := filepath.Join(options.DataDir, "operations")
	if err := os.Mkdir(operations, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(operations, 0o700)
	operationID := "abcdef0123456789abcdef0123456789"
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	_, err = NewService(manager, options).CreatePeer(ctx, &awgapi.CreatePeerRequest{Name: "phone"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "persist peer creation intent") {
		t.Fatalf("CreatePeer() pending-key write error = %v", err)
	}
}

func TestRunConnectionMonitorUsesTrafficGrowthAndSkipsEmptyPeerNames(t *testing.T) {
	options := testOptions(t)
	device := &telemetryTestDevice{}
	manager, err := Open(options, telemetryTestFactory{device: device})
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
	decoded, err := decodeKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(decoded)
	handshake := time.Now().UTC().Unix()
	device.setSnapshotSequence(
		fmt.Sprintf("public_key=%s\nlast_handshake_time_sec=%d\nrx_bytes=1\ntx_bytes=1\n", key, handshake),
		fmt.Sprintf("public_key=%s\nlast_handshake_time_sec=%d\nrx_bytes=2\ntx_bytes=1\n", key, handshake),
	)
	service := NewService(manager, options)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runConnectionMonitor(ctx, time.Millisecond)
	}()
	deadline := time.After(time.Second)
	for device.snapshotCallCount() < 2 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("connection monitor did not sample traffic growth")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection monitor did not stop")
	}

	device.setSnapshot(fmt.Sprintf("public_key=%s\nrx_bytes=2\ntx_bytes=1\n", key))
	manager.mu.Lock()
	manager.state.Peers[0].Name = ""
	manager.mu.Unlock()
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	service.runConnectionMonitor(ctx, 0)
}

func TestRemoveOrphanedOperationKeysIgnoresUnreadableDirectory(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	operations := filepath.Join(options.DataDir, "operations")
	if err := os.Mkdir(operations, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(operations, "orphan.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(operations, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(operations, 0o700)
	NewService(manager, options)
}

func TestGetClientConfigAndRenderClientConfigRejectMalformedProfilesAndNilRequest(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("phone", publicKey); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(options.DataDir, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.DataDir, "profiles", "phone.conf"), []byte("[Interface]\n[Peer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetClientConfig(context.Background(), &awgapi.GetClientConfigRequest{Name: "phone"}); status.Code(err) != codes.Internal {
		t.Fatalf("GetClientConfig() accepted a saved profile without a private key: %v", err)
	}
	if _, err := service.RenderClientConfig(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("RenderClientConfig(nil) = %v, want InvalidArgument", err)
	}
}

func TestRunExpirationMonitorProcessesTickerAndStops(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expired := now.Add(-time.Second)
	if _, _, err := manager.AddPeerWithExpiry("phone", publicKey, "", &expired); err != nil {
		t.Fatal(err)
	}
	service := NewService(manager, options)
	service.telemetryNow = func() time.Time { return now }
	canceled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	service.runExpirationMonitor(canceled, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runExpirationMonitor(ctx, time.Millisecond)
	}()
	deadline := time.After(time.Second)
	for {
		peers := manager.Peers()
		if len(peers) == 1 && peers[0].Disabled {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("expiration monitor did not disable expired peer: %+v", peers)
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(3 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expiration monitor did not stop after cancellation")
	}
}
