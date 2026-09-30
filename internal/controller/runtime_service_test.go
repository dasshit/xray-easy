package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/domain"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeXrayHandler struct {
	called string
	args   []string
	users  []string
	err    error
}

func (f *fakeXrayHandler) AddUser(_ context.Context, email, id, flow string) error {
	f.called, f.args = "add-vless", []string{email, id, flow}
	return f.err
}
func (f *fakeXrayHandler) RemoveUser(_ context.Context, email string) error {
	f.called, f.args = "remove-vless", []string{email}
	return f.err
}
func (f *fakeXrayHandler) Users(context.Context) ([]string, error) {
	f.called = "list-vless"
	return f.users, f.err
}
func (f *fakeXrayHandler) AddHysteriaUser(_ context.Context, email, id string) error {
	f.called, f.args = "add-hysteria2", []string{email, id}
	return f.err
}
func (f *fakeXrayHandler) RemoveHysteriaUser(_ context.Context, email string) error {
	f.called, f.args = "remove-hysteria2", []string{email}
	return f.err
}
func (f *fakeXrayHandler) AddVMessUser(_ context.Context, email, id string) error {
	f.called, f.args = "add-vmess", []string{email, id}
	return f.err
}
func (f *fakeXrayHandler) RemoveVMessUser(_ context.Context, email string) error {
	f.called, f.args = "remove-vmess", []string{email}
	return f.err
}
func (f *fakeXrayHandler) UsersInInbound(_ context.Context, inbound string) ([]string, error) {
	f.called, f.args = "list-"+inbound, []string{inbound}
	return f.users, f.err
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

func TestServiceRoutesXrayHandlerAndTelemetryOperations(t *testing.T) {
	handler := &fakeXrayHandler{users: []string{"one@example.test", "two@example.test"}}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	stats := fakeXrayStats{users: []xrayapi.UserStats{{
		Email: "one@example.test", UploadBytes: 17, DownloadBytes: 29, LastSeen: now,
		SourceIPs: []xrayapi.IPObservation{{Address: "203.0.113.8", LastSeen: now}, {Address: "203.0.113.9"}},
	}, {Email: "two@example.test"}}}
	service := NewServiceWithAdapters(&fakeRuntime{}, handler, stats, nil)
	if _, err := service.GetCapabilities(context.Background(), emptyRequest()); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		protocol, expected string
	}{
		{"vless", "add-vless"}, {"vmess", "add-vmess"}, {"hysteria2", "add-hysteria2"},
	} {
		if _, err := service.AddDeviceUser(context.Background(), request(map[string]any{"protocol": test.protocol, "email": "device@example.test", "id": "credential", "flow": "vision"})); err != nil {
			t.Fatalf("AddDeviceUser(%s): %v", test.protocol, err)
		}
		if handler.called != test.expected {
			t.Fatalf("AddDeviceUser(%s) dispatched to %q", test.protocol, handler.called)
		}
	}
	for _, test := range []struct {
		protocol, expected string
	}{
		{"vless", "remove-vless"}, {"vmess", "remove-vmess"}, {"hysteria2", "remove-hysteria2"},
	} {
		if _, err := service.RemoveDeviceUser(context.Background(), request(map[string]any{"protocol": test.protocol, "email": "device@example.test"})); err != nil {
			t.Fatalf("RemoveDeviceUser(%s): %v", test.protocol, err)
		}
		if handler.called != test.expected {
			t.Fatalf("RemoveDeviceUser(%s) dispatched to %q", test.protocol, handler.called)
		}
	}
	for _, test := range []struct {
		protocol, expected string
	}{
		{"vless", "list-vless"}, {"vmess", "list-vmess-tls"}, {"hysteria2", "list-hysteria2"},
	} {
		response, err := service.ListDeviceUsers(context.Background(), request(map[string]any{"protocol": test.protocol}))
		if err != nil || len(response.GetFields()["users"].GetListValue().GetValues()) != 2 {
			t.Fatalf("ListDeviceUsers(%s) = %v, %v", test.protocol, response, err)
		}
		if handler.called != test.expected {
			t.Fatalf("ListDeviceUsers(%s) dispatched to %q", test.protocol, handler.called)
		}
	}
	response, err := service.GetXrayTelemetry(context.Background(), emptyRequest())
	if err != nil {
		t.Fatal(err)
	}
	users := response.GetFields()["users"].GetListValue().GetValues()
	first := users[0].GetStructValue().GetFields()
	if first["upload_bytes"].GetStringValue() != "17" || first["download_bytes"].GetStringValue() != "29" || first["last_seen"].GetStringValue() == "" || len(first["source_ips"].GetListValue().GetValues()) != 2 {
		t.Fatalf("Xray telemetry response = %v", first)
	}
	if runtimeTime(time.Time{}) != "" {
		t.Fatal("zero runtime time should be empty")
	}
}

func TestServiceRoutesAllAmneziaWGRuntimeOperations(t *testing.T) {
	createdAt := time.Date(2026, 9, 30, 13, 0, 0, 0, time.UTC)
	awg := &fakeAWGRuntime{
		status:    domain.AmneziaWGStatus{Running: true, PublicKey: "public", ListenPort: 1234, PublicHost: "vpn.example.test", PublicPort: 1234, PeerCount: 1, IPv4Network: "10.0.0.0/24", IPv6Network: "fd00::/64", ServiceVersion: "v1"},
		peers:     []domain.AmneziaWGPeer{{Name: "phone", PublicKey: "peer-public", IPv4: "10.0.0.2", IPv6: "fd00::2", CreatedAt: createdAt}},
		peerStats: []domain.AmneziaWGPeerStats{{Name: "phone", SourceIP: "203.0.113.8", LastSeen: createdAt, UploadBytes: 12, DownloadBytes: 34}},
		config:    "[Interface]\nPrivateKey=redacted", backup: []byte("archive"),
	}
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, awg)
	if response, err := service.GetCapabilities(context.Background(), emptyRequest()); err != nil || !response.GetFields()["amneziawg"].GetStructValue().GetFields()["configured"].GetBoolValue() {
		t.Fatalf("AWG capability = %v, %v", response, err)
	}
	if _, err := service.GetAmneziaWGStatus(context.Background(), emptyRequest()); err != nil {
		t.Fatal(err)
	}
	if response, err := service.ListAmneziaWGPeers(context.Background(), emptyRequest()); err != nil || len(response.GetFields()["peers"].GetListValue().GetValues()) != 1 {
		t.Fatalf("ListAmneziaWGPeers() = %v, %v", response, err)
	}
	if response, err := service.CreateAmneziaWGPeer(context.Background(), request(map[string]any{"name": "tablet"})); err != nil || response.GetFields()["name"].GetStringValue() != "tablet" {
		t.Fatalf("CreateAmneziaWGPeer() = %v, %v", response, err)
	}
	if _, err := service.RemoveAmneziaWGPeer(context.Background(), request(map[string]any{"name": "phone"})); err != nil || awg.removed != "phone" {
		t.Fatalf("RemoveAmneziaWGPeer() = %v, removed=%q", err, awg.removed)
	}
	if response, err := service.GetAmneziaWGPeerStats(context.Background(), emptyRequest()); err != nil || response.GetFields()["peers"].GetListValue().GetValues()[0].GetStructValue().GetFields()["upload_bytes"].GetStringValue() != "12" {
		t.Fatalf("GetAmneziaWGPeerStats() = %v, %v", response, err)
	}
	if response, err := service.GetAmneziaWGClientConfig(context.Background(), request(map[string]any{"name": "phone"})); err != nil || response.GetFields()["config"].GetStringValue() != awg.config {
		t.Fatalf("GetAmneziaWGClientConfig() = %v, %v", response, err)
	}
	if response, err := service.ExportAmneziaWGBackup(context.Background(), emptyRequest()); err != nil || response.GetFields()["data"].GetStringValue() == "" {
		t.Fatalf("ExportAmneziaWGBackup() = %v, %v", response, err)
	}
	if _, err := service.RestoreAmneziaWGBackup(context.Background(), request(map[string]any{"data": "YXJjaGl2ZQ=="})); err != nil || !reflect.DeepEqual(awg.restored, []byte("archive")) {
		t.Fatalf("RestoreAmneziaWGBackup() = %v, restored=%q", err, awg.restored)
	}
}

func TestServiceRejectsUnavailableAndMalformedRuntimeAdapters(t *testing.T) {
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, nil)
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"add user", func() error {
			_, err := service.AddDeviceUser(context.Background(), request(map[string]any{"protocol": "vless", "email": "x", "id": "id"}))
			return err
		}},
		{"remove user", func() error {
			_, err := service.RemoveDeviceUser(context.Background(), request(map[string]any{"protocol": "vless", "email": "x"}))
			return err
		}},
		{"list user", func() error {
			_, err := service.ListDeviceUsers(context.Background(), request(map[string]any{"protocol": "vless"}))
			return err
		}},
		{"stats", func() error { _, err := service.GetXrayTelemetry(context.Background(), emptyRequest()); return err }},
		{"awg status", func() error { _, err := service.GetAmneziaWGStatus(context.Background(), emptyRequest()); return err }},
		{"awg peers", func() error { _, err := service.ListAmneziaWGPeers(context.Background(), emptyRequest()); return err }},
		{"awg create", func() error {
			_, err := service.CreateAmneziaWGPeer(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		}},
		{"awg remove", func() error {
			_, err := service.RemoveAmneziaWGPeer(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		}},
		{"awg stats", func() error {
			_, err := service.GetAmneziaWGPeerStats(context.Background(), emptyRequest())
			return err
		}},
		{"awg config", func() error {
			_, err := service.GetAmneziaWGClientConfig(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		}},
		{"awg export", func() error {
			_, err := service.ExportAmneziaWGBackup(context.Background(), emptyRequest())
			return err
		}},
		{"awg restore", func() error {
			_, err := service.RestoreAmneziaWGBackup(context.Background(), request(map[string]any{"data": "eA=="}))
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
			_, err := service.AddDeviceUser(context.Background(), request(map[string]any{"protocol": "invalid", "email": "x", "id": "id"}))
			return err
		},
		func() error {
			_, err := service.RemoveDeviceUser(context.Background(), request(map[string]any{"protocol": "invalid", "email": "x"}))
			return err
		},
		func() error {
			_, err := service.ListDeviceUsers(context.Background(), request(map[string]any{"protocol": "invalid"}))
			return err
		},
		func() error {
			_, err := service.RestoreAmneziaWGBackup(context.Background(), request(map[string]any{"data": "not-base64"}))
			return err
		},
		func() error {
			_, err := service.GetAmneziaWGClientConfig(context.Background(), emptyRequest())
			return err
		},
	} {
		if status.Code(call()) != codes.InvalidArgument {
			t.Errorf("malformed request error = %v", call())
		}
	}
	if _, err := service.AddDeviceUser(context.Background(), request(map[string]any{"protocol": 1, "email": "x", "id": "id"})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong protocol type = %v", err)
	}
	if _, err := service.GetXrayTelemetry(context.Background(), request(map[string]any{"unexpected": true})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected telemetry field = %v", err)
	}
	failedHandler := &fakeXrayHandler{err: errors.New("adapter failure")}
	failedStats := fakeXrayStats{err: errors.New("stats failure")}
	failedAWG := &fakeAWGRuntime{err: errors.New("awg failure")}
	failed := NewServiceWithAdapters(&fakeRuntime{}, failedHandler, failedStats, failedAWG)
	for _, call := range []func() error{
		func() error {
			_, err := failed.AddDeviceUser(context.Background(), request(map[string]any{"protocol": "vless", "email": "x", "id": "id"}))
			return err
		},
		func() error {
			_, err := failed.RemoveDeviceUser(context.Background(), request(map[string]any{"protocol": "vless", "email": "x"}))
			return err
		},
		func() error {
			_, err := failed.ListDeviceUsers(context.Background(), request(map[string]any{"protocol": "vless"}))
			return err
		},
		func() error { _, err := failed.GetXrayTelemetry(context.Background(), emptyRequest()); return err },
		func() error { _, err := failed.GetAmneziaWGStatus(context.Background(), emptyRequest()); return err },
		func() error { _, err := failed.ListAmneziaWGPeers(context.Background(), emptyRequest()); return err },
		func() error {
			_, err := failed.CreateAmneziaWGPeer(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		},
		func() error {
			_, err := failed.RemoveAmneziaWGPeer(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		},
		func() error { _, err := failed.GetAmneziaWGPeerStats(context.Background(), emptyRequest()); return err },
		func() error {
			_, err := failed.GetAmneziaWGClientConfig(context.Background(), request(map[string]any{"name": "phone"}))
			return err
		},
		func() error { _, err := failed.ExportAmneziaWGBackup(context.Background(), emptyRequest()); return err },
		func() error {
			_, err := failed.RestoreAmneziaWGBackup(context.Background(), request(map[string]any{"data": "YXJjaGl2ZQ=="}))
			return err
		},
	} {
		if err := call(); err == nil {
			t.Error("adapter failure was ignored")
		}
	}
	for _, call := range []func() error{
		func() error {
			_, err := service.GetAmneziaWGStatus(context.Background(), request(map[string]any{"extra": true}))
			return err
		},
		func() error { _, err := service.CreateAmneziaWGPeer(context.Background(), emptyRequest()); return err },
		func() error { _, err := service.RemoveAmneziaWGPeer(context.Background(), emptyRequest()); return err },
		func() error {
			_, err := service.GetAmneziaWGPeerStats(context.Background(), request(map[string]any{"extra": true}))
			return err
		},
		func() error {
			_, err := service.ExportAmneziaWGBackup(context.Background(), request(map[string]any{"extra": true}))
			return err
		},
	} {
		if status.Code(call()) != codes.InvalidArgument {
			t.Errorf("invalid AWG request error = %v", call())
		}
	}
}
