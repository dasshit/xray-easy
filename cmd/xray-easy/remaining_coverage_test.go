package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/stats"
	"xray-easy/internal/xrayapi"
)

type failingCoverageStatsAPI struct{}

func (failingCoverageStatsAPI) Poll(context.Context) ([]xrayapi.UserStats, error) {
	return nil, errors.New("injected telemetry failure")
}

func TestRemainingAuthenticationAndDiagnosticsFailurePaths(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/totp/setup"},
		{http.MethodPost, "/api/auth/totp/enable"},
		{http.MethodPost, "/api/auth/totp/disable"},
		{http.MethodGet, "/api/status"},
		{http.MethodGet, "/api/logs"},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			if got := requestJSON(t, app, endpoint.method, endpoint.path, map[string]string{}, false).Code; got != http.StatusUnauthorized {
				t.Fatalf("unauthenticated %s status = %d", endpoint.path, got)
			}
		})
	}

	manager := stats.NewManager(app.server.store, failingCoverageStatsAPI{})
	if err := manager.Poll(t.Context()); err == nil {
		t.Fatal("injected stats failure was ignored")
	}
	app.server.stats = manager
	response := requestJSON(t, app, http.MethodGet, "/api/status", nil, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"stats_last_error":"injected telemetry failure"`) {
		t.Fatalf("status omitted stats failure: %d %s", response.Code, response.Body.String())
	}
}

func TestChangePasswordReportsPersistenceFailure(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	execSQLiteTestMutation(t, app, "reject admin password update", `CREATE TRIGGER reject_admin_password_update BEFORE UPDATE OF password_hash ON admin_users BEGIN SELECT RAISE(ABORT, 'injected password update failure'); END`)
	response := requestJSON(t, app, http.MethodPost, "/api/auth/password", passwordChangeRequest{CurrentPassword: "correct horse battery", NewPassword: "new password for admin"}, true)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not change administrator password") {
		t.Fatalf("password persistence failure = %d %s", response.Code, response.Body.String())
	}
}

func TestBrowserOriginRejectsCrossOriginReferer(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://localhost:8080/api/auth/logout", nil)
	request.Header.Set("Referer", "https://attacker.example/path")
	if err := validateBrowserOrigin(request); err == nil {
		t.Fatal("cross-origin Referer was accepted")
	}
}

func TestMalformedActiveConfigDoesNotReportInboundTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasInboundTag(path, "vless-reality") {
		t.Fatal("malformed active JSON reported an inbound tag")
	}
}

func TestRendererSettingsWithMasterKeyReportsDerivationFailure(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	_, err := rendererSettingsWithMasterKey(domain.Settings{}, "private", domain.HysteriaSettings{}, []byte("short"))
	if err == nil || !strings.Contains(err.Error(), "derive Shadowsocks 2022 server key") {
		t.Fatalf("short master key error = %v", err)
	}
}
