package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeXrayHandler struct {
	called     string
	args       []string
	users      []string
	err        error
	adds       int
	removes    int
	traces     []interaction.Trace
	requestIDs []string
}

func (f *fakeXrayHandler) AddUser(ctx context.Context, email, id, flow string) error {
	f.called, f.args = "add-vless", []string{email, id, flow}
	f.adds++
	f.users = append(f.users, email)
	f.captureTrace(ctx)
	return f.err
}
func (f *fakeXrayHandler) RemoveUser(_ context.Context, email string) error {
	f.called, f.args = "remove-vless", []string{email}
	f.removes++
	f.users = withoutUser(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) Users(ctx context.Context) ([]string, error) {
	f.called = "list-vless"
	f.captureTrace(ctx)
	return f.users, f.err
}
func (f *fakeXrayHandler) captureTrace(ctx context.Context) {
	f.traces = append(f.traces, interaction.TraceFromContext(ctx))
	f.requestIDs = append(f.requestIDs, interaction.RequestID(ctx))
}
func (f *fakeXrayHandler) AddHysteriaUser(_ context.Context, email, id string) error {
	f.called, f.args = "add-hysteria2", []string{email, id}
	f.adds++
	f.users = append(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) RemoveHysteriaUser(_ context.Context, email string) error {
	f.called, f.args = "remove-hysteria2", []string{email}
	f.removes++
	f.users = withoutUser(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) AddVMessUser(_ context.Context, email, id string) error {
	f.called, f.args = "add-vmess", []string{email, id}
	f.adds++
	f.users = append(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) RemoveVMessUser(_ context.Context, email string) error {
	f.called, f.args = "remove-vmess", []string{email}
	f.removes++
	f.users = withoutUser(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) AddShadowsocksUser(_ context.Context, email, password, method string) error {
	f.called, f.args = "add-shadowsocks", []string{email, password, method}
	f.adds++
	f.users = append(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) RemoveShadowsocksUser(_ context.Context, email string) error {
	f.called, f.args = "remove-shadowsocks", []string{email}
	f.removes++
	f.users = withoutUser(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) AddTrojanUser(_ context.Context, email, password string) error {
	f.called, f.args = "add-trojan", []string{email, password}
	f.adds++
	f.users = append(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) RemoveTrojanUser(_ context.Context, email string) error {
	f.called, f.args = "remove-trojan", []string{email}
	f.removes++
	f.users = withoutUser(f.users, email)
	return f.err
}
func (f *fakeXrayHandler) UsersInInbound(_ context.Context, inbound string) ([]string, error) {
	f.called, f.args = "list-"+inbound, []string{inbound}
	return f.users, f.err
}

func withoutUser(users []string, email string) []string {
	result := users[:0]
	for _, user := range users {
		if user != email {
			result = append(result, user)
		}
	}
	return result
}

type fakeXrayStats struct {
	users []xrayapi.UserStats
	err   error
}

func (f fakeXrayStats) Poll(context.Context) ([]xrayapi.UserStats, error) { return f.users, f.err }

type fakeAWGRuntime struct {
	status    domain.AmneziaWGStatus
	peers     []domain.AmneziaWGPeer
	peerStats []domain.AmneziaWGPeerStats
	config    string
	backup    []byte
	removed   string
	restored  []byte
	err       error
}

func (f *fakeAWGRuntime) Status(context.Context) (domain.AmneziaWGStatus, error) {
	return f.status, f.err
}
func (f *fakeAWGRuntime) ListPeers(context.Context) ([]domain.AmneziaWGPeer, error) {
	return f.peers, f.err
}
func (f *fakeAWGRuntime) CreatePeer(_ context.Context, name string) (domain.AmneziaWGPeer, error) {
	return domain.AmneziaWGPeer{Name: name, PublicKey: "public", IPv4: "10.0.0.2", IPv6: "fd00::2", CreatedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}, f.err
}
func (f *fakeAWGRuntime) RemovePeer(_ context.Context, name string) error {
	f.removed = name
	return f.err
}
func (f *fakeAWGRuntime) ClientConfig(context.Context, string) (string, error) {
	return f.config, f.err
}
func (f *fakeAWGRuntime) PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error) {
	return f.peerStats, f.err
}
func (f *fakeAWGRuntime) ExportBackup(context.Context) ([]byte, error) { return f.backup, f.err }
func (f *fakeAWGRuntime) RestoreBackup(_ context.Context, data []byte) error {
	f.restored = append([]byte(nil), data...)
	return f.err
}

var _ awgcontrol.Gateway = (*fakeAWGRuntime)(nil)

func TestServiceRoutesXrayHandlerAndTypedTelemetry(t *testing.T) {
	handler := &fakeXrayHandler{users: []string{"one@example.test", "two@example.test"}}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	stats := fakeXrayStats{users: []xrayapi.UserStats{{
		Email: "one@example.test", UploadBytes: 17, DownloadBytes: 29, LastSeen: now,
		SourceIPs: []xrayapi.IPObservation{{Address: "203.0.113.8", LastSeen: now}, {Address: "203.0.113.9"}},
	}, {Email: "two@example.test"}}}
	service := NewServiceWithAdapters(&fakeRuntime{}, handler, stats, nil)
	if _, err := service.GetCapabilities(context.Background(), &controllerv1.EmptyRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ protocol, expected string }{{"vless", "add-vless"}, {"vmess", "add-vmess"}, {"hysteria2", "add-hysteria2"}} {
		if _, err := service.AddDeviceUser(context.Background(), &controllerv1.AddDeviceUserRequest{Protocol: test.protocol, Email: "device@example.test", Id: "credential", Flow: "vision"}); err != nil || handler.called != test.expected {
			t.Fatalf("AddDeviceUser(%s) dispatch=%q error=%v", test.protocol, handler.called, err)
		}
	}
	for _, test := range []struct{ protocol, expected string }{{"vless", "remove-vless"}, {"vmess", "remove-vmess"}, {"hysteria2", "remove-hysteria2"}} {
		if _, err := service.RemoveDeviceUser(context.Background(), &controllerv1.RemoveDeviceUserRequest{Protocol: test.protocol, Email: "device@example.test"}); err != nil || handler.called != test.expected {
			t.Fatalf("RemoveDeviceUser(%s) dispatch=%q error=%v", test.protocol, handler.called, err)
		}
	}
	for _, test := range []struct{ protocol, expected string }{{"vless", "list-vless"}, {"vmess", "list-vmess-tls"}, {"hysteria2", "list-hysteria2"}} {
		response, err := service.ListDeviceUsers(context.Background(), &controllerv1.ListDeviceUsersRequest{Protocol: test.protocol})
		if err != nil || len(response.GetUsers()) != 2 || handler.called != test.expected {
			t.Fatalf("ListDeviceUsers(%s) = %+v, %v; called=%s", test.protocol, response, err, handler.called)
		}
	}
	response, err := service.GetXrayTelemetry(context.Background(), &controllerv1.EmptyRequest{})
	if err != nil || len(response.GetUsers()) != 2 {
		t.Fatalf("GetXrayTelemetry() = %+v, %v", response, err)
	}
	first := response.Users[0]
	if first.UploadBytes != 17 || first.DownloadBytes != 29 || first.LastSeen.AsTime() != now || len(first.SourceIps) != 2 || first.SourceIps[0].Address != "203.0.113.8" || first.SourceIps[1].LastSeen != nil {
		t.Fatalf("Xray telemetry response = %+v", first)
	}
}

func TestServiceRoutesAllAmneziaWGRuntimeOperations(t *testing.T) {
	createdAt := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)
	backup := []byte{0, 1, 2, 255}
	awg := &fakeAWGRuntime{
		status:    domain.AmneziaWGStatus{Running: true, PublicKey: "public", ListenPort: 1234, PublicHost: "vpn.example.test", PublicPort: 1234, PeerCount: 1, IPv4Network: "10.0.0.0/24", IPv6Network: "fd00::/64", ServiceVersion: "v1"},
		peers:     []domain.AmneziaWGPeer{{Name: "phone", PublicKey: "peer-public", IPv4: "10.0.0.2", IPv6: "fd00::2", CreatedAt: createdAt}},
		peerStats: []domain.AmneziaWGPeerStats{{Name: "phone", SourceIP: "203.0.113.8", LastSeen: createdAt, UploadBytes: 12, DownloadBytes: 34}},
		config:    "[Interface]\\nPrivateKey=redacted", backup: backup,
	}
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, awg)
	if response, err := service.GetCapabilities(context.Background(), &controllerv1.EmptyRequest{}); err != nil || !response.Amneziawg.Configured {
		t.Fatalf("AWG capability = %v, %v", response, err)
	}
	if response, err := service.GetAmneziaWGStatus(context.Background(), &controllerv1.EmptyRequest{}); err != nil || !response.Running || response.ListenPort != 1234 {
		t.Fatalf("GetAmneziaWGStatus() = %+v, %v", response, err)
	}
	if response, err := service.ListAmneziaWGPeers(context.Background(), &controllerv1.EmptyRequest{}); err != nil || len(response.Peers) != 1 || response.Peers[0].CreatedAt.AsTime() != createdAt {
		t.Fatalf("ListAmneziaWGPeers() = %+v, %v", response, err)
	}
	if response, err := service.CreateAmneziaWGPeer(context.Background(), &controllerv1.CreateAmneziaWGPeerRequest{Name: "tablet"}); err != nil || response.Name != "tablet" {
		t.Fatalf("CreateAmneziaWGPeer() = %+v, %v", response, err)
	}
	if _, err := service.RemoveAmneziaWGPeer(context.Background(), &controllerv1.RemoveAmneziaWGPeerRequest{Name: "phone"}); err != nil || awg.removed != "phone" {
		t.Fatalf("RemoveAmneziaWGPeer() = %v, removed=%q", err, awg.removed)
	}
	if response, err := service.GetAmneziaWGPeerStats(context.Background(), &controllerv1.EmptyRequest{}); err != nil || response.Peers[0].UploadBytes != 12 || response.Peers[0].LastSeen.AsTime() != createdAt {
		t.Fatalf("GetAmneziaWGPeerStats() = %+v, %v", response, err)
	}
	if response, err := service.GetAmneziaWGClientConfig(context.Background(), &controllerv1.GetAmneziaWGClientConfigRequest{Name: "phone"}); err != nil || response.Config != awg.config {
		t.Fatalf("GetAmneziaWGClientConfig() = %+v, %v", response, err)
	}
	if response, err := service.ExportAmneziaWGBackup(context.Background(), &controllerv1.EmptyRequest{}); err != nil || string(response.Data) != string(backup) {
		t.Fatalf("ExportAmneziaWGBackup() = %+v, %v", response, err)
	}
	if _, err := service.RestoreAmneziaWGBackup(context.Background(), &controllerv1.RestoreAmneziaWGBackupRequest{Data: backup}); err != nil || string(awg.restored) != string(backup) {
		t.Fatalf("RestoreAmneziaWGBackup() = %v, restored=%v", err, awg.restored)
	}
}

type concurrentAddHandler struct {
	fakeXrayHandler
	mu           sync.Mutex
	users        []string
	listCalls    int
	firstList    chan struct{}
	secondList   chan struct{}
	releaseFirst chan struct{}
	addCalls     int
}

func (h *concurrentAddHandler) Users(context.Context) ([]string, error) {
	h.mu.Lock()
	h.listCalls++
	call := h.listCalls
	users := append([]string(nil), h.users...)
	h.mu.Unlock()
	if call == 1 {
		close(h.firstList)
		<-h.releaseFirst
	}
	if call == 2 {
		close(h.secondList)
	}
	return users, nil
}

func (h *concurrentAddHandler) AddUser(_ context.Context, email, _, _ string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.addCalls++
	h.users = append(h.users, email)
	return nil
}

func TestXrayDeviceMutationCheckAndApplyAreSerialized(t *testing.T) {
	handler := &concurrentAddHandler{firstList: make(chan struct{}), secondList: make(chan struct{}), releaseFirst: make(chan struct{})}
	service := NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil)
	ctx := interaction.WithOperationID(context.Background(), "abcdef0123456789abcdef0123456789")
	request := &controllerv1.AddDeviceUserRequest{Protocol: "vless", Email: "device@xray-easy", Id: "stable-uuid", Flow: "vision"}
	results := make(chan error, 2)
	go func() { _, err := service.AddDeviceUser(ctx, request); results <- err }()
	select {
	case <-handler.firstList:
	case <-time.After(2 * time.Second):
		t.Fatal("first idempotency check did not start")
	}
	go func() { _, err := service.AddDeviceUser(ctx, request); results <- err }()
	concurrentCheck := false
	select {
	case <-handler.secondList:
		concurrentCheck = true
	case <-time.After(100 * time.Millisecond):
	}
	close(handler.releaseFirst)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent AddDeviceUser() = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent add did not finish")
		}
	}
	if concurrentCheck {
		t.Fatal("second operation checked the stale roster before the first add completed")
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.addCalls != 1 || len(handler.users) != 1 {
		t.Fatalf("concurrent retry added duplicate users: calls=%d users=%v", handler.addCalls, handler.users)
	}
}

func TestServiceRejectsUnavailableAndMalformedRuntimeAdapters(t *testing.T) {
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, nil)
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"add user", func() error {
			_, err := service.AddDeviceUser(context.Background(), &controllerv1.AddDeviceUserRequest{Protocol: "vless", Email: "x", Id: "id"})
			return err
		}},
		{"remove user", func() error {
			_, err := service.RemoveDeviceUser(context.Background(), &controllerv1.RemoveDeviceUserRequest{Protocol: "vless", Email: "x"})
			return err
		}},
		{"list user", func() error {
			_, err := service.ListDeviceUsers(context.Background(), &controllerv1.ListDeviceUsersRequest{Protocol: "vless"})
			return err
		}},
		{"stats", func() error {
			_, err := service.GetXrayTelemetry(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}},
		{"awg status", func() error {
			_, err := service.GetAmneziaWGStatus(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}},
		{"awg peers", func() error {
			_, err := service.ListAmneziaWGPeers(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}},
		{"awg create", func() error {
			_, err := service.CreateAmneziaWGPeer(context.Background(), &controllerv1.CreateAmneziaWGPeerRequest{Name: "phone"})
			return err
		}},
		{"awg remove", func() error {
			_, err := service.RemoveAmneziaWGPeer(context.Background(), &controllerv1.RemoveAmneziaWGPeerRequest{Name: "phone"})
			return err
		}},
		{"awg stats", func() error {
			_, err := service.GetAmneziaWGPeerStats(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}},
		{"awg config", func() error {
			_, err := service.GetAmneziaWGClientConfig(context.Background(), &controllerv1.GetAmneziaWGClientConfigRequest{Name: "phone"})
			return err
		}},
		{"awg export", func() error {
			_, err := service.ExportAmneziaWGBackup(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}},
		{"awg restore", func() error {
			_, err := service.RestoreAmneziaWGBackup(context.Background(), &controllerv1.RestoreAmneziaWGBackupRequest{Data: []byte("x")})
			return err
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			if code := status.Code(call.fn()); code != codes.Unavailable {
				t.Fatalf("error code = %s", code)
			}
		})
	}
	for _, call := range []func() error{
		func() error {
			_, err := service.AddDeviceUser(context.Background(), &controllerv1.AddDeviceUserRequest{Protocol: "invalid", Email: "x", Id: "id"})
			return err
		},
		func() error {
			_, err := service.RemoveDeviceUser(context.Background(), &controllerv1.RemoveDeviceUserRequest{Protocol: "invalid", Email: "x"})
			return err
		},
		func() error {
			_, err := service.ListDeviceUsers(context.Background(), &controllerv1.ListDeviceUsersRequest{Protocol: "invalid"})
			return err
		},
		func() error {
			_, err := service.RestoreAmneziaWGBackup(context.Background(), &controllerv1.RestoreAmneziaWGBackupRequest{})
			return err
		},
		func() error {
			_, err := service.GetAmneziaWGClientConfig(context.Background(), &controllerv1.GetAmneziaWGClientConfigRequest{})
			return err
		},
		func() error { _, err := service.AddDeviceUser(context.Background(), nil); return err },
		func() error { _, err := service.RemoveDeviceUser(context.Background(), nil); return err },
		func() error { _, err := service.ListDeviceUsers(context.Background(), nil); return err },
		func() error { _, err := service.CreateAmneziaWGPeer(context.Background(), nil); return err },
	} {
		if status.Code(call()) != codes.InvalidArgument {
			t.Errorf("invalid request error = %v", call())
		}
	}
	failedHandler := &fakeXrayHandler{err: errors.New("adapter failure")}
	failedStats := fakeXrayStats{err: errors.New("stats failure")}
	failedAWG := &fakeAWGRuntime{err: errors.New("awg failure")}
	failed := NewServiceWithAdapters(&fakeRuntime{}, failedHandler, failedStats, failedAWG)
	for _, call := range []func() error{
		func() error {
			_, err := failed.AddDeviceUser(context.Background(), &controllerv1.AddDeviceUserRequest{Protocol: "vless", Email: "x", Id: "id"})
			return err
		},
		func() error {
			_, err := failed.RemoveDeviceUser(context.Background(), &controllerv1.RemoveDeviceUserRequest{Protocol: "vless", Email: "x"})
			return err
		},
		func() error {
			_, err := failed.ListDeviceUsers(context.Background(), &controllerv1.ListDeviceUsersRequest{Protocol: "vless"})
			return err
		},
		func() error {
			_, err := failed.GetXrayTelemetry(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error {
			_, err := failed.GetAmneziaWGStatus(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error {
			_, err := failed.ListAmneziaWGPeers(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error {
			_, err := failed.CreateAmneziaWGPeer(context.Background(), &controllerv1.CreateAmneziaWGPeerRequest{Name: "phone"})
			return err
		},
		func() error {
			_, err := failed.RemoveAmneziaWGPeer(context.Background(), &controllerv1.RemoveAmneziaWGPeerRequest{Name: "phone"})
			return err
		},
		func() error {
			_, err := failed.GetAmneziaWGPeerStats(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error {
			_, err := failed.GetAmneziaWGClientConfig(context.Background(), &controllerv1.GetAmneziaWGClientConfigRequest{Name: "phone"})
			return err
		},
		func() error {
			_, err := failed.ExportAmneziaWGBackup(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error {
			_, err := failed.RestoreAmneziaWGBackup(context.Background(), &controllerv1.RestoreAmneziaWGBackupRequest{Data: []byte("x")})
			return err
		},
	} {
		if err := call(); err == nil {
			t.Error("adapter failure was ignored")
		}
	}
}
