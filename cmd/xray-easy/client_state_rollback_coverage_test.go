package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestClientStatePersistenceFailureRollsBackLiveAdd(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "rollback-enable")
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
		t.Fatalf("disable before rollback test = %d %s", response.Code, response.Body.String())
	}
	execSQLiteTestMutation(t, app, "reject access update", `CREATE TRIGGER reject_access_update BEFORE UPDATE OF vless_enabled ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END`)

	response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
		t.Fatalf("enable with failed persistence = %d %s", response.Code, response.Body.String())
	}
	stored, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || stored.VLESSEnabled {
		t.Fatalf("failed enable changed persisted access: %+v, %v", stored, err)
	}
	app.handler.mu.Lock()
	users := append([]string(nil), app.handler.users...)
	app.handler.mu.Unlock()
	if len(users) != 0 {
		t.Fatalf("failed enable left a live user after rollback: %v", users)
	}
}

func TestClientStatePersistenceFailureRollsBackVLESSInboundReplacement(t *testing.T) {
	app := newTestApp(t, true)
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer
	client := createRuntimeTestClient(t, app, "rollback-vless-revoke")
	execSQLiteTestMutation(t, app, "reject access update", `CREATE TRIGGER reject_access_update BEFORE UPDATE OF vless_revoked ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END`)

	response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/revoke", nil, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
		t.Fatalf("revoke with failed persistence = %d %s", response.Code, response.Body.String())
	}
	if len(replacer.calls) != 2 || replacer.calls[0][2] != "vless-reality" || replacer.calls[1][2] != "vless-reality" {
		t.Fatalf("VLESS inbound replace and rollback calls = %v", replacer.calls)
	}
	stored, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || stored.VLESSRevoked || !stored.VLESSEnabled {
		t.Fatalf("failed revoke changed persisted access: %+v, %v", stored, err)
	}
}

func TestClientStatePersistenceFailureRollsBackProtocolSpecificLiveAdds(t *testing.T) {
	tests := []struct {
		name        string
		protocol    domain.ClientProtocol
		environment map[string]string
		setup       func(*testing.T, testApp) (domain.Client, func() []string)
		stateColumn string
	}{
		{
			name: "Hysteria 2", protocol: domain.ProtocolHysteria2,
			environment: map[string]string{"XRAY_HYSTERIA2_ENABLED": "true", "XRAY_HYSTERIA2_TLS_MODE": "custom", "XRAY_HYSTERIA2_TLS_SERVER_NAME": "cert.example.test"},
			setup: func(t *testing.T, app testApp) (domain.Client, func() []string) {
				handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				return createRuntimeHysteriaClient(t, app, "rollback-hysteria"), func() []string { return append([]string(nil), handler.users...) }
			},
			stateColumn: "hysteria_enabled",
		},
		{
			name: "VMess", protocol: domain.ProtocolVMess,
			setup: func(t *testing.T, app testApp) (domain.Client, func() []string) {
				handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				return createRuntimeVMessClient(t, app, "rollback-vmess"), func() []string { return append([]string(nil), handler.users...) }
			},
			stateColumn: "vmess_enabled",
		},
		{
			name: "Shadowsocks", protocol: domain.ProtocolShadowsocks,
			environment: map[string]string{"XRAY_SHADOWSOCKS_ENABLED": "true", "XRAY_SHADOWSOCKS_PORT": "8388"},
			setup: func(t *testing.T, app testApp) (domain.Client, func() []string) {
				handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				return createRuntimeShadowsocksClient(t, app, "rollback-shadowsocks"), func() []string { return append([]string(nil), handler.users...) }
			},
			stateColumn: "shadowsocks_enabled",
		},
		{
			name: "Trojan", protocol: domain.ProtocolTrojan,
			environment: map[string]string{"XRAY_TROJAN_ENABLED": "true", "XRAY_TROJAN_PORT": "11443"},
			setup: func(t *testing.T, app testApp) (domain.Client, func() []string) {
				handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				app.server.trojanPort = 11443
				return createRuntimeTrojanClient(t, app, "rollback-trojan"), func() []string { return append([]string(nil), handler.users...) }
			},
			stateColumn: "trojan_enabled",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			app := newTestApp(t, true)
			client, users := test.setup(t, app)
			if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
				t.Fatalf("disable before rollback test = %d %s", response.Code, response.Body.String())
			}
			execSQLiteTestMutation(t, app, "reject access update", "CREATE TRIGGER reject_access_update BEFORE UPDATE OF "+test.stateColumn+" ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END")

			response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
				t.Fatalf("enable with failed persistence = %d %s", response.Code, response.Body.String())
			}
			stored, err := app.server.store.GetClient(t.Context(), client.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := stored.AccessState(test.protocol)
			if err != nil || state.Enabled {
				t.Fatalf("failed enable changed persisted access: %+v, %v", state, err)
			}
			if activeUsers := users(); len(activeUsers) != 0 {
				t.Fatalf("failed enable left a live user after rollback: %v", activeUsers)
			}
		})
	}
}

func TestClientStatePersistenceFailureRestoresProtocolSpecificLiveRemovals(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		stateColumn string
		setup       func(*testing.T, testApp) (domain.Client, func(string) bool)
	}{
		{
			name: "VLESS", stateColumn: "vless_enabled",
			setup: func(t *testing.T, app testApp) (domain.Client, func(string) bool) {
				client := createRuntimeTestClient(t, app, "rollback-remove-vless")
				return client, func(email string) bool {
					app.handler.mu.Lock()
					defer app.handler.mu.Unlock()
					for _, current := range app.handler.users {
						if current == email {
							return true
						}
					}
					return false
				}
			},
		},
		{
			name: "Hysteria 2", stateColumn: "hysteria_enabled",
			environment: map[string]string{"XRAY_HYSTERIA2_ENABLED": "true", "XRAY_HYSTERIA2_TLS_MODE": "custom", "XRAY_HYSTERIA2_TLS_SERVER_NAME": "cert.example.test"},
			setup: func(t *testing.T, app testApp) (domain.Client, func(string) bool) {
				handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				client := createRuntimeHysteriaClient(t, app, "rollback-remove-hysteria")
				return client, func(email string) bool { return containsEmail(handler.users, email) }
			},
		},
		{
			name: "VMess", stateColumn: "vmess_enabled",
			setup: func(t *testing.T, app testApp) (domain.Client, func(string) bool) {
				handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				client := createRuntimeVMessClient(t, app, "rollback-remove-vmess")
				return client, func(email string) bool { return containsEmail(handler.users, email) }
			},
		},
		{
			name: "Shadowsocks", stateColumn: "shadowsocks_enabled",
			environment: map[string]string{"XRAY_SHADOWSOCKS_ENABLED": "true", "XRAY_SHADOWSOCKS_PORT": "8388"},
			setup: func(t *testing.T, app testApp) (domain.Client, func(string) bool) {
				handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				client := createRuntimeShadowsocksClient(t, app, "rollback-remove-shadowsocks")
				return client, func(email string) bool { return containsEmail(handler.users, email) }
			},
		},
		{
			name: "Trojan", stateColumn: "trojan_enabled",
			environment: map[string]string{"XRAY_TROJAN_ENABLED": "true", "XRAY_TROJAN_PORT": "11443"},
			setup: func(t *testing.T, app testApp) (domain.Client, func(string) bool) {
				handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
				app.server.handler = handler
				app.server.trojanPort = 11443
				client := createRuntimeTrojanClient(t, app, "rollback-remove-trojan")
				return client, func(email string) bool { return containsEmail(handler.users, email) }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			app := newTestApp(t, true)
			client, hasUser := test.setup(t, app)
			execSQLiteTestMutation(t, app, "reject access update", "CREATE TRIGGER reject_access_update BEFORE UPDATE OF "+test.stateColumn+" ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END")
			response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
				t.Fatalf("disable with failed persistence = %d %s", response.Code, response.Body.String())
			}
			if !hasUser(client.Email) {
				t.Fatalf("failed disable did not restore the live %s user", test.name)
			}
		})
	}
}

func TestClientStatePersistenceFailureRollsBackFullRuntimeApplyFallback(t *testing.T) {
	tests := []struct {
		name        string
		protocol    domain.ClientProtocol
		environment map[string]string
		stateColumn string
		create      func(*testing.T, testApp) domain.Client
		noHandler   bool
	}{
		{
			name: "VLESS without HandlerService", protocol: domain.ProtocolVLESS,
			stateColumn: "vless_enabled", noHandler: true,
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeTestClient(t, app, "fallback-vless")
			},
		},
		{
			name: "Hysteria without HandlerService", protocol: domain.ProtocolHysteria2,
			environment: map[string]string{"XRAY_HYSTERIA2_ENABLED": "true", "XRAY_HYSTERIA2_TLS_MODE": "custom", "XRAY_HYSTERIA2_TLS_SERVER_NAME": "cert.example.test"},
			stateColumn: "hysteria_enabled",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeHysteriaClient(t, app, "fallback-hysteria")
			},
		},
		{
			name: "VMess without HandlerService", protocol: domain.ProtocolVMess,
			stateColumn: "vmess_enabled",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeVMessClient(t, app, "fallback-vmess")
			},
		},
		{
			name: "Shadowsocks without HandlerService", protocol: domain.ProtocolShadowsocks,
			environment: map[string]string{"XRAY_SHADOWSOCKS_ENABLED": "true", "XRAY_SHADOWSOCKS_PORT": "8388"},
			stateColumn: "shadowsocks_enabled",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeShadowsocksClient(t, app, "fallback-shadowsocks")
			},
		},
		{
			name: "Trojan without HandlerService", protocol: domain.ProtocolTrojan,
			environment: map[string]string{"XRAY_TROJAN_ENABLED": "true", "XRAY_TROJAN_PORT": "11443"},
			stateColumn: "trojan_enabled",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeTrojanClient(t, app, "fallback-trojan")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			app := newTestApp(t, true)
			if test.noHandler {
				app.server.handler = nil
			}
			if test.protocol == domain.ProtocolTrojan {
				app.server.trojanPort = 11443
			}
			client := test.create(t, app)
			beforeApply := len(app.sup.applyCalls)
			execSQLiteTestMutation(t, app, "reject access update", "CREATE TRIGGER reject_access_update BEFORE UPDATE OF "+test.stateColumn+" ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END")

			response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
				t.Fatalf("disable with failed persistence = %d %s", response.Code, response.Body.String())
			}
			if got := len(app.sup.applyCalls) - beforeApply; got != 2 {
				t.Fatalf("runtime apply calls = %d, want candidate apply plus rollback", got)
			}
			stored, err := app.server.store.GetClient(t.Context(), client.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := stored.AccessState(test.protocol)
			if err != nil || !state.Enabled {
				t.Fatalf("failed disable changed persisted access: %+v, %v", state, err)
			}
		})
	}
}

func TestClientStateInboundReplacementErrorsLeaveAccessUnchanged(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		disableEnv  string
		create      func(*testing.T, testApp) domain.Client
		setup       func(testApp)
	}{
		{
			name: "VLESS",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeTestClient(t, app, "replace-error-vless")
			},
		},
		{
			name: "VMess",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeVMessClient(t, app, "replace-error-vmess")
			},
		},
		{
			name:        "Shadowsocks",
			environment: map[string]string{"XRAY_SHADOWSOCKS_ENABLED": "true", "XRAY_SHADOWSOCKS_PORT": "8388"},
			disableEnv:  "XRAY_SHADOWSOCKS_ENABLED",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeShadowsocksClient(t, app, "replace-error-shadowsocks")
			},
		},
		{
			name:        "Trojan",
			environment: map[string]string{"XRAY_TROJAN_ENABLED": "true", "XRAY_TROJAN_PORT": "11443"},
			disableEnv:  "XRAY_TROJAN_ENABLED",
			create: func(t *testing.T, app testApp) domain.Client {
				return createRuntimeTrojanClient(t, app, "replace-error-trojan")
			},
			setup: func(app testApp) { app.server.trojanPort = 11443 },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.environment {
				t.Setenv(name, value)
			}
			app := newTestApp(t, true)
			if test.setup != nil {
				test.setup(app)
			}
			client := test.create(t, app)
			if test.disableEnv != "" {
				t.Setenv(test.disableEnv, "false")
			}
			replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup, err: errors.New("inbound replacement failed")}
			app.server.xrayRuntime = replacer
			response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/revoke", nil, true)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "inbound replacement failed") {
				t.Fatalf("%s replacement failure = %d %s", test.name, response.Code, response.Body.String())
			}
			stored, err := app.server.store.GetClient(t.Context(), client.ID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := stored.AccessState(client.Protocol)
			if err != nil || state.Revoked || !state.Enabled {
				t.Fatalf("failed replacement changed %s access: %+v, %v", test.name, state, err)
			}
		})
	}
}

func TestClientStateFullApplyRollbackFailureIsReported(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "rollback-failure-vless")
	app.server.handler = nil
	app.sup.applyErrors = []error{nil, errors.New("rollback apply rejected")}
	execSQLiteTestMutation(t, app, "reject access update", `CREATE TRIGGER reject_access_update BEFORE UPDATE OF vless_enabled ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END`)
	response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
		t.Fatalf("state persistence failure = %d %s", response.Code, response.Body.String())
	}
	found := false
	for _, entry := range app.server.diagnosticBuffer.Snapshot(10) {
		if strings.Contains(entry.Message, "rollback apply rejected") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("full runtime rollback failure was not recorded in diagnostics")
	}
}
