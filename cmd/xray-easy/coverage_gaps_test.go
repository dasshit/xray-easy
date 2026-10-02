package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type failingCandidateFile struct {
	*os.File
	failure string
	wantErr error
}

func (f *failingCandidateFile) Chmod(mode os.FileMode) error {
	if f.failure == "chmod" {
		return f.wantErr
	}
	return f.File.Chmod(mode)
}

func (f *failingCandidateFile) Write(data []byte) (int, error) {
	if f.failure == "write" {
		return 0, f.wantErr
	}
	return f.File.Write(data)
}

func (f *failingCandidateFile) Sync() error {
	if f.failure == "sync" {
		return f.wantErr
	}
	return f.File.Sync()
}

func (f *failingCandidateFile) Close() error {
	actualErr := f.File.Close()
	if f.failure == "close" {
		return f.wantErr
	}
	return actualErr
}

func TestConfigurationHelpersValidatePortsHostsAndHysteriaFallbacks(t *testing.T) {
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	t.Setenv("XRAY_VMESS_PORT", "9443")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	if port, err := configuredVMessPort(); err != nil || port != 9443 {
		t.Fatalf("configured VMess port = %d, %v", port, err)
	}
	for _, test := range []struct{ key, value string }{
		{"XRAY_VMESS_PORT", "bad"}, {"XRAY_VMESS_PORT", "0"}, {"XRAY_VMESS_PORT", "65536"},
		{"XRAY_PUBLIC_PORT", "bad"}, {"XRAY_PUBLIC_PORT", "0"},
		{"XRAY_EASY_UI_PORT", "bad"}, {"XRAY_EASY_UI_PORT", "0"},
	} {
		t.Run(test.key+"="+test.value, func(t *testing.T) {
			t.Setenv(test.key, test.value)
			if _, err := configuredVMessPort(); err == nil {
				t.Fatal("invalid port configuration was accepted")
			}
		})
	}
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	t.Setenv("XRAY_VMESS_PORT", "443")
	if _, err := configuredVMessPort(); err == nil {
		t.Fatal("VMess and public ports were allowed to overlap")
	}
	t.Setenv("XRAY_VMESS_PORT", "8080")
	if _, err := configuredVMessPort(); err == nil {
		t.Fatal("VMess and UI ports were allowed to overlap")
	}

	t.Setenv("XRAY_HYSTERIA2_ENABLED", " true ")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", domain.HysteriaTLSSelfSigned)
	t.Setenv("XRAY_HYSTERIA2_CERT_IP", "8.8.8.8")
	if err := validateHysteriaPublicHost("1.1.1.1"); err == nil {
		t.Fatal("self-signed Hysteria accepted a mismatched profile endpoint")
	}
	if err := validateHysteriaPublicHost("8.8.8.8"); err != nil {
		t.Fatalf("matching self-signed Hysteria endpoint rejected: %v", err)
	}
	settings := hysteriaSettingsFromEnvironment()
	if !settings.Enabled || settings.TLSCertIP != "8.8.8.8" || !hysteria2Enabled() {
		t.Fatalf("Hysteria environment was not normalized: %+v", settings)
	}
	app := newTestApp(t, true)
	if err := app.server.validateHysteriaHost(context.Background(), "1.1.1.1"); err == nil {
		t.Fatal("stored Hysteria settings did not enforce the mkcert IP")
	}
	app.server.store.Close()
	if !app.server.hysteriaEnabled(context.Background()) {
		t.Fatal("environment fallback should apply when Hysteria settings cannot be read")
	}
}

func TestShadowsocksConfigurationHelpersValidatePortsAndPublicSettings(t *testing.T) {
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	t.Setenv("XRAY_VMESS_PORT", "9443")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", " TRUE ")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Setenv("XRAY_SHADOWSOCKS_METHOD", "aes-256-gcm")
	t.Setenv("XRAY_SHADOWSOCKS_NETWORK", "tcp")
	settings, err := configuredShadowsocksSettings()
	if err != nil || !settings.Enabled || settings.PublicPort != 8388 || settings.Method != "aes-256-gcm" || settings.Network != "tcp" {
		t.Fatalf("configured Shadowsocks settings = %+v, %v", settings, err)
	}
	if !configuredShadowsocksEnabled() || configuredShadowsocksMethod() != "aes-256-gcm" {
		t.Fatal("Shadowsocks environment helpers did not preserve configured values")
	}
	public := publicSettings(domain.Settings{PublicHost: "vpn.example.test", PublicPort: 443}, 9443)
	if public["shadowsocks_enabled"] != true || public["shadowsocks_public_port"] != 8388 || public["shadowsocks_method"] != "aes-256-gcm" || public["shadowsocks_network"] != "tcp" {
		t.Fatalf("public Shadowsocks settings = %#v", public)
	}
	for _, test := range []struct {
		name  string
		value string
	}{
		{"invalid", "bad"}, {"zero", "0"}, {"public port", "443"}, {"VMess port", "9443"}, {"UI port", "8080"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XRAY_SHADOWSOCKS_PORT", test.value)
			if _, err := configuredShadowsocksPort(); err == nil {
				t.Fatal("invalid Shadowsocks port was accepted")
			}
		})
	}
	// A malformed port must not make the public settings endpoint fail; it uses
	// the documented fallback while the doctor reports the invalid environment.
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "bad")
	fallback := publicSettings(domain.Settings{PublicHost: "vpn.example.test", PublicPort: 443}, 9443)
	if fallback["shadowsocks_public_port"] != 8388 || fallback["shadowsocks_method"] != domain.ShadowsocksMethodChaCha20Poly1305 {
		t.Fatalf("invalid-port public settings fallback = %#v", fallback)
	}
	for _, test := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "public port", key: "XRAY_SHADOWSOCKS_PORT", value: "443"},
		{name: "vmess port", key: "XRAY_SHADOWSOCKS_PORT", value: "9443"},
		{name: "ui port", key: "XRAY_SHADOWSOCKS_PORT", value: "8080"},
		{name: "invalid public", key: "XRAY_PUBLIC_PORT", value: "bad"},
		{name: "invalid vmess", key: "XRAY_VMESS_PORT", value: "bad"},
		{name: "invalid ui", key: "XRAY_EASY_UI_PORT", value: "bad"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
			t.Setenv("XRAY_PUBLIC_PORT", "443")
			t.Setenv("XRAY_VMESS_PORT", "9443")
			t.Setenv("XRAY_EASY_UI_PORT", "8080")
			t.Setenv(test.key, test.value)
			if _, err := configuredShadowsocksPort(); err == nil {
				t.Fatal("invalid Shadowsocks port dependency was accepted")
			}
		})
	}
}

func TestConfiguredTrojanPortValidatesEveryPublicPortCollision(t *testing.T) {
	for name, value := range map[string]string{
		"XRAY_PUBLIC_PORT": "443", "XRAY_VMESS_PORT": "9443",
		"XRAY_SHADOWSOCKS_PORT": "8388", "XRAY_EASY_UI_PORT": "8080",
	} {
		t.Setenv(name, value)
	}
	if got, err := configuredTrojanPort(); err != nil || got != 10443 {
		t.Fatalf("default Trojan port = %d, %v", got, err)
	}
	for _, test := range []struct {
		name string
		port string
		want string
	}{
		{"invalid value", "bad", "integer"},
		{"outside range", "65536", "integer"},
		{"public collision", "443", "XRAY_PUBLIC_PORT"},
		{"VMess collision", "9443", "XRAY_VMESS_PORT"},
		{"Shadowsocks collision", "8388", "XRAY_SHADOWSOCKS_PORT"},
		{"UI collision", "8080", "XRAY_EASY_UI_PORT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XRAY_TROJAN_PORT", test.port)
			if _, err := configuredTrojanPort(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("configuredTrojanPort() error = %v, want %q", err, test.want)
			}
		})
	}
	t.Setenv("XRAY_TROJAN_PORT", "10443")
	t.Setenv("XRAY_EASY_UI_PORT", "not-a-port")
	if _, err := configuredTrojanPort(); err == nil || !strings.Contains(err.Error(), "XRAY_EASY_UI_PORT") {
		t.Fatalf("invalid Web UI port was ignored: %v", err)
	}
}

func TestClientStateChangeReportsPreparationAndRuntimeFailures(t *testing.T) {
	t.Run("maintenance lock is busy", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "lock-phone")
		lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		response := httptest.NewRecorder()
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
		defer cancel()
		request := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
		app.server.changeClientState(response, request, client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusConflict {
			t.Fatalf("busy maintenance state change = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("unreadable settings", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "closed-db")
		if err := app.server.store.Close(); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusConflict {
			t.Fatalf("closed store state change = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("REALITY key cannot decrypt", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "bad-key")
		settings, err := app.server.store.GetSettings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityPrivateKeyEnc = "broken-envelope"
		if err := app.server.store.UpdateSettings(t.Context(), settings); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "decrypt REALITY") {
			t.Fatalf("invalid key state change = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("candidate rejected", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "candidate-failure")
		app.sup.validateErr = errors.New("candidate rejected")
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "candidate rejected") {
			t.Fatalf("candidate failure state change = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("short-ID reserve is unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "reserve-table")
		db, err := sql.Open("sqlite", "file:"+filepath.Join(app.server.dataDir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`DROP TABLE reality_short_ids`); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "short-ID reserve") {
			t.Fatalf("missing short-ID reserve state change = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("persist failure restores live access", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "persist-trigger")
		db, err := sql.Open("sqlite", "file:"+filepath.Join(app.server.dataDir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.Exec(`CREATE TRIGGER reject_access_update BEFORE UPDATE OF vless_enabled ON clients BEGIN SELECT RAISE(ABORT, 'access update blocked'); END`); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "access update blocked") {
			t.Fatalf("failed persisted state change = %d %s", response.Code, response.Body.String())
		}
		if len(app.handler.users) != 1 || app.handler.users[0] != client.Email {
			t.Fatalf("runtime access was not rolled back after persistence failure: %v", app.handler.users)
		}
	})
	t.Run("full runtime apply rejected", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "apply-failure")
		app.server.handler = nil
		app.sup.applyErrors = []error{errors.New("apply rejected")}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "apply rejected") {
			t.Fatalf("runtime apply state change = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestJSONAndAtomicFileHelpersCoverMalformedAndFilesystemFailures(t *testing.T) {
	request := httptest.NewRequest("POST", "/", failingReader{})
	if err := decodeJSON(request, &map[string]any{}); err == nil || err.Error() != "read failed" {
		t.Fatalf("decodeJSON read error = %v", err)
	}
	request = httptest.NewRequest("POST", "/", strings.NewReader("{"))
	if err := decodeJSON(request, &map[string]any{}); err == nil || err.Error() != "invalid JSON body" {
		t.Fatalf("decodeJSON malformed body = %v", err)
	}
	request = httptest.NewRequest("POST", "/", bytes.NewReader(make([]byte, 1<<20)))
	if err := decodeJSON(request, &map[string]any{}); err == nil || err.Error() != "request body is too large" {
		t.Fatalf("decodeJSON oversized body = %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "candidate.json")
	if err := writeAtomic(path, []byte("candidate")); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(path); err != nil || string(contents) != "candidate" {
		t.Fatalf("atomic write contents = %q, %v", contents, err)
	}
	blocked := filepath.Join(root, "regular-file")
	if err := os.WriteFile(blocked, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(blocked, "candidate.json"), []byte("x")); err == nil {
		t.Fatal("atomic write succeeded below a regular file")
	}
}

func TestAtomicCandidateWritePropagatesPersistenceFailuresAndCleansUp(t *testing.T) {
	for _, failure := range []string{"create", "chmod", "write", "sync", "close", "rename"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "candidate.json")
			wantErr := errors.New("injected " + failure + " failure")
			file := &failingCandidateFile{failure: failure, wantErr: wantErr}
			err := writeAtomicWith(path, []byte(`{"ok":true}`),
				func(directory, pattern string) (atomicCandidateFile, error) {
					if failure == "create" {
						return nil, wantErr
					}
					created, err := os.CreateTemp(directory, pattern)
					if err != nil {
						return nil, err
					}
					file.File = created
					return file, nil
				},
				func(source, destination string) error {
					if failure == "rename" {
						return wantErr
					}
					return os.Rename(source, destination)
				},
			)
			if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
				t.Fatalf("writeAtomicWith() error = %v, want %q", err, wantErr)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed atomic write left files behind: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestSessionAndRandomIdentifierHelpersHandleEmptyAndValidInputs(t *testing.T) {
	request := httptest.NewRequest("GET", "/", nil)
	if sessionToken(request) != "" {
		t.Fatal("request without a session cookie returned a token")
	}
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: "session-value"})
	if sessionToken(request) != "session-value" {
		t.Fatal("session cookie was not read")
	}
	if got := envOr("XRAY_EASY_COVERAGE_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("unset environment fallback = %q", got)
	}
	id, err := randomID()
	if err != nil || len(id) != 32 {
		t.Fatalf("random ID = %q, %v", id, err)
	}
}
