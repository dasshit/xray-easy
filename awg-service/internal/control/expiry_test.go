package control

import (
	"context"
	"strings"
	"testing"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPeerExpiryRPCAndBackgroundWorkerKeepClientProfile(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	future := time.Now().UTC().Add(time.Hour)
	created, err := service.CreatePeer(context.Background(), &awgapi.CreatePeerRequest{Name: "phone", ExpiresAt: timestamppb.New(future)})
	if err != nil || created.GetExpiresAt() == nil || !created.GetExpiresAt().AsTime().Equal(future) || created.GetDisabled() {
		t.Fatalf("CreatePeer() = %+v, %v", created, err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "phone", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	updated, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ClearExpiry: true})
	if err != nil || updated.GetExpiresAt() != nil || !updated.GetDisabled() {
		t.Fatalf("clear expiry changed enabled state: peer=%+v err=%v", updated, err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "phone", Enabled: true}); err != nil {
		t.Fatalf("explicit enable of unlimited peer = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: timestamppb.New(future), ClearExpiry: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ambiguous expiry request = %v", err)
	}

	past := time.Now().UTC().Add(-time.Second)
	if _, err := manager.SetPeerExpiry("phone", &past); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runExpirationMonitor(ctx, 10*time.Millisecond)
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		peers := manager.Peers()
		if len(peers) == 1 && peers[0].Disabled {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if peers := manager.Peers(); len(peers) != 1 || !peers[0].Disabled {
		cancel()
		<-done
		t.Fatalf("background expiry worker did not disable peer: %+v", peers)
	}
	profile, err := service.GetClientConfig(context.Background(), &awgapi.GetClientConfigRequest{Name: "phone"})
	if err != nil || !strings.Contains(profile.GetConfig(), "PrivateKey = ") {
		t.Fatalf("expired peer client profile was not retained: profile=%v err=%v", profile, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expiry monitor did not stop after cancellation")
	}
}

func TestPeerExpiryRejectsPastDeadlinesAndDoesNotReenableOnExtension(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	if _, err := service.CreatePeer(context.Background(), &awgapi.CreatePeerRequest{Name: "phone", ExpiresAt: timestamppb.New(time.Now().Add(-time.Second))}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("create with past expiry = %v", err)
	}
	if _, err := service.CreatePeer(context.Background(), &awgapi.CreatePeerRequest{Name: "phone"}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Second)
	if _, err := manager.SetPeerExpiry("phone", &past); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: timestamppb.New(future)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("extend expiry while enforcement is pending = %v", err)
	}
	if peers := manager.Peers(); len(peers) != 1 || peers[0].Disabled || peers[0].ExpiresAt == nil || !peers[0].ExpiresAt.Before(time.Now()) {
		t.Fatalf("rejected extension changed overdue peer state: %+v", peers)
	}
	if _, err := manager.ExpireDuePeers(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	peer, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: timestamppb.New(future)})
	if err != nil || !peer.GetDisabled() {
		t.Fatalf("expiry extension implicitly enabled peer: %+v %v", peer, err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "phone", Enabled: true}); err != nil {
		t.Fatalf("explicit enable after extension = %v", err)
	}
}

func TestPeerExpiryRPCValidationsAndExpiredEnableError(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	now := time.Now().UTC()
	service.telemetryNow = func() time.Time { return now }

	if _, err := service.SetPeerEnabled(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil enable request = %v", err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "bad name"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid enable name = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil expiry request = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "bad name", ClearExpiry: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid expiry name = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: timestamppb.New(now.Add(time.Hour)), ClearExpiry: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("conflicting expiry request = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing expiry request value = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: &timestamppb.Timestamp{Seconds: -1}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid expiry timestamp = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "phone", ExpiresAt: timestamppb.New(now)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("non-future expiry = %v", err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "missing", Enabled: true}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown peer enable = %v", err)
	}
	if _, err := service.SetPeerExpiry(context.Background(), &awgapi.SetPeerExpiryRequest{Name: "missing", ClearExpiry: true}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown peer expiry = %v", err)
	}

	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(-time.Second)
	if _, _, err := manager.AddPeerWithExpiry("phone", publicKey, "", &deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ExpireDuePeers(now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetPeerEnabled(context.Background(), &awgapi.SetPeerEnabledRequest{Name: "phone", Enabled: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("enable expired peer = %v", err)
	}
}

func TestRunExpirationMonitorUsesPeriodicRetryAndPublicEntryPoint(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	now := time.Now().UTC()
	service.telemetryNow = func() time.Time { return now }
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(-time.Second)
	if _, _, err := manager.AddPeerWithExpiry("phone", publicKey, "", &deadline); err != nil {
		t.Fatal(err)
	}
	device.setErr = context.DeadlineExceeded
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service.RunExpirationMonitor(ctx)
	if peers := manager.Peers(); len(peers) != 1 || peers[0].Disabled {
		t.Fatalf("failed expiration sweep changed persisted state: %+v", peers)
	}
	device.setErr = nil
	if _, err := manager.ExpireDuePeers(now); err != nil {
		t.Fatal(err)
	}
	if peers := manager.Peers(); len(peers) != 1 || !peers[0].Disabled {
		t.Fatalf("peer remained enabled after expiration retry: %+v", peers)
	}

	var nilService *Service
	nilService.RunExpirationMonitor(context.Background())
	(&Service{}).RunExpirationMonitor(context.Background())
}
