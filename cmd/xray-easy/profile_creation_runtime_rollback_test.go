package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

type createClientRollbackHandler struct {
	users    map[string]bool
	added    []string
	removed  []string
	afterAdd func()
}

func (h *createClientRollbackHandler) AddUser(_ context.Context, email, _, _ string) error {
	h.added = append(h.added, email)
	h.users[email] = true
	if h.afterAdd != nil {
		h.afterAdd()
	}
	return nil
}

func (h *createClientRollbackHandler) RemoveUser(_ context.Context, email string) error {
	h.removed = append(h.removed, email)
	delete(h.users, email)
	return nil
}

func (h *createClientRollbackHandler) Users(context.Context) ([]string, error) {
	users := make([]string, 0, len(h.users))
	for email := range h.users {
		users = append(users, email)
	}
	return users, nil
}

func (h *createClientRollbackHandler) AddHysteriaUser(ctx context.Context, email, _ string) error {
	return h.AddUser(ctx, email, "", "")
}

func (h *createClientRollbackHandler) RemoveHysteriaUser(ctx context.Context, email string) error {
	return h.RemoveUser(ctx, email)
}

func (h *createClientRollbackHandler) AddVMessUser(ctx context.Context, email, _ string) error {
	return h.AddUser(ctx, email, "", "")
}

func (h *createClientRollbackHandler) RemoveVMessUser(ctx context.Context, email string) error {
	return h.RemoveUser(ctx, email)
}

func (h *createClientRollbackHandler) AddShadowsocksUser(ctx context.Context, email, _, _ string) error {
	return h.AddUser(ctx, email, "", "")
}

func (h *createClientRollbackHandler) RemoveShadowsocksUser(ctx context.Context, email string) error {
	return h.RemoveUser(ctx, email)
}

func (h *createClientRollbackHandler) AddTrojanUser(ctx context.Context, email, _ string) error {
	return h.AddUser(ctx, email, "", "")
}

func (h *createClientRollbackHandler) RemoveTrojanUser(ctx context.Context, email string) error {
	return h.RemoveUser(ctx, email)
}

func (h *createClientRollbackHandler) UsersInInbound(ctx context.Context, _ string) ([]string, error) {
	return h.Users(ctx)
}

func TestCreateProtocolClientRollsBackLiveUserWhenConfigPromotionFails(t *testing.T) {
	tests := []struct {
		name        string
		protocol    domain.ClientProtocol
		environment map[string]string
		setup       func(*testing.T, testApp) error
	}{
		{name: "VLESS", protocol: domain.ProtocolVLESS},
		{
			name: "Hysteria 2", protocol: domain.ProtocolHysteria2,
			environment: map[string]string{"XRAY_HYSTERIA2_ENABLED": "true", "XRAY_HYSTERIA2_TLS_MODE": "custom", "XRAY_HYSTERIA2_TLS_SERVER_NAME": "cert.example.test"},
		},
		{name: "VMess", protocol: domain.ProtocolVMess},
		{
			name: "Shadowsocks", protocol: domain.ProtocolShadowsocks,
			environment: map[string]string{"XRAY_SHADOWSOCKS_ENABLED": "true", "XRAY_SHADOWSOCKS_PORT": "8388"},
		},
		{
			name: "Trojan", protocol: domain.ProtocolTrojan,
			environment: map[string]string{"XRAY_TROJAN_ENABLED": "true", "XRAY_TROJAN_PORT": "11443"},
			setup: func(_ *testing.T, app testApp) error {
				app.server.trojanPort = 11443
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			app := newTestApp(t, true)
			handler := &createClientRollbackHandler{users: make(map[string]bool)}
			app.server.handler = handler
			if test.setup != nil {
				if err := test.setup(t, app); err != nil {
					t.Fatal(err)
				}
			}
			if test.protocol != domain.ProtocolVLESS {
				if _, err := app.server.createProtocolClient(t.Context(), testSettings(t, app), domain.ProtocolVLESS, "rollback-baseline", "", "", nil, app.admin.ID); err != nil {
					t.Fatalf("create VLESS baseline: %v", err)
				}
			}
			create := func(name string) (domain.Client, error) {
				return app.server.createProtocolClient(t.Context(), testSettings(t, app), test.protocol, name, "", "", nil, app.admin.ID)
			}
			if _, err := create("rollback-first"); err != nil {
				t.Fatalf("create first %s profile: %v", test.name, err)
			}
			activePath := filepath.Join(app.server.configDir, "active.json")
			handler.afterAdd = func() {
				if err := os.Remove(activePath); err != nil {
					t.Errorf("remove active config while injecting promotion failure: %v", err)
					return
				}
				if err := os.Mkdir(activePath, 0o700); err != nil {
					t.Errorf("replace active config with directory: %v", err)
				}
			}
			if _, err := create("rollback-second"); err == nil || !strings.Contains(err.Error(), "promote Xray config") {
				t.Fatalf("create with promotion failure = %v", err)
			}
			if len(handler.added) < 1 || len(handler.removed) != 1 || handler.removed[0] != handler.added[len(handler.added)-1] || handler.users[handler.removed[0]] {
				t.Fatalf("runtime user rollback: added=%v removed=%v users=%v", handler.added, handler.removed, handler.users)
			}
			clients, err := app.server.store.ListClients(t.Context())
			wantCount := 1
			if test.protocol != domain.ProtocolVLESS {
				wantCount = 2
			}
			if err != nil || len(clients) != wantCount {
				t.Fatalf("profiles after failed %s creation: count=%d, want=%d, err=%v", test.name, len(clients), wantCount, err)
			}
		})
	}
}

func TestCreateProtocolClientRollsBackFullApplyAndNewVMessInbound(t *testing.T) {
	t.Run("first Trojan inbound full-apply promotion failure", func(t *testing.T) {
		t.Setenv("XRAY_TROJAN_ENABLED", "false")
		t.Setenv("XRAY_TROJAN_PORT", "11443")
		app := newTestApp(t, true)
		app.server.trojanPort = 11443
		handler := &createClientRollbackHandler{users: make(map[string]bool)}
		app.server.handler = handler
		if _, err := app.server.createProtocolClient(t.Context(), testSettings(t, app), domain.ProtocolVLESS, "baseline", "", "", nil, app.admin.ID); err != nil {
			t.Fatalf("create VLESS baseline: %v", err)
		}
		t.Setenv("XRAY_TROJAN_ENABLED", "true")
		activePath := filepath.Join(app.server.configDir, "active.json")
		changed := false
		app.sup.applyHook = func(path, _ string) {
			if changed || path == activePath {
				return
			}
			changed = true
			if err := os.Remove(activePath); err != nil {
				t.Errorf("remove active config: %v", err)
				return
			}
			if err := os.Mkdir(activePath, 0o700); err != nil {
				t.Errorf("replace active config with directory: %v", err)
			}
		}
		if _, err := app.server.createProtocolClient(t.Context(), testSettings(t, app), domain.ProtocolTrojan, "first-trojan", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "promote Xray config") {
			t.Fatalf("Trojan full-apply promotion failure = %v", err)
		}
		if len(app.sup.applyCalls) < 3 || !strings.HasSuffix(app.sup.applyCalls[len(app.sup.applyCalls)-1][1], "-rollback") {
			t.Fatalf("full Xray config was not restored: %v", app.sup.applyCalls)
		}
	})

	t.Run("new VMess inbound replacement promotion failure", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &createClientRollbackHandler{users: make(map[string]bool)}
		app.server.handler = handler
		if _, err := app.server.createProtocolClient(t.Context(), testSettings(t, app), domain.ProtocolVLESS, "baseline", "", "", nil, app.admin.ID); err != nil {
			t.Fatalf("create VLESS baseline: %v", err)
		}
		replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
		activePath := filepath.Join(app.server.configDir, "active.json")
		changed := false
		replacer.hook = func() {
			if changed {
				return
			}
			changed = true
			if err := os.Remove(activePath); err != nil {
				t.Errorf("remove active config: %v", err)
				return
			}
			if err := os.Mkdir(activePath, 0o700); err != nil {
				t.Errorf("replace active config with directory: %v", err)
			}
		}
		app.server.xrayRuntime = replacer
		if _, err := app.server.createProtocolClient(t.Context(), testSettings(t, app), domain.ProtocolVMess, "first-vmess", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "promote Xray config") {
			t.Fatalf("VMess inbound replacement promotion failure = %v", err)
		}
		if len(replacer.calls) != 2 || replacer.calls[0][2] != "vmess-tls" || !strings.HasSuffix(replacer.calls[1][3], "-rollback") {
			t.Fatalf("new VMess inbound was not restored: %v", replacer.calls)
		}
	})
}

func testSettings(t *testing.T, app testApp) domain.Settings {
	t.Helper()
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return settings
}
