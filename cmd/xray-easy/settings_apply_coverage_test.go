package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingsApplyRejectsMethodAndAuthentication(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/settings/apply", settingsApplyRequest{}, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET apply status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: "missing"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated apply status = %d", got)
	}
}

func TestSettingsLogLevelApplyFailurePaths(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		before   func(t *testing.T, app testApp, changeID string, runtime *logLevelXrayRuntime)
		wantCode int
		want     string
	}{
		{
			name: "runtime control plane",
			before: func(_ *testing.T, _ testApp, _ string, runtime *logLevelXrayRuntime) {
				runtime.err = errors.New("runtime unavailable")
			},
			wantCode: http.StatusBadGateway, want: "could not change Xray log level",
		},
		{
			name: "active config persistence",
			before: func(t *testing.T, app testApp, _ string, _ *logLevelXrayRuntime) {
				if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte("not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCode: http.StatusInternalServerError, want: "could not persist Xray log level",
		},
		{
			name: "database persistence",
			before: func(t *testing.T, app testApp, _ string, _ *logLevelXrayRuntime) {
				if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte(`{"log":{"loglevel":"warning"}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				execSQLiteTestMutation(t, app, "reject settings update", `CREATE TRIGGER reject_settings_update BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT, 'injected settings update failure'); END`)
			},
			wantCode: http.StatusInternalServerError, want: "persist settings",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			runtime := &logLevelXrayRuntime{fakeXrayRuntime: app.sup}
			app.server.xrayRuntime = runtime
			level := "debug"
			prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{LogLevel: &level}, true)
			if prepared.Code != http.StatusOK {
				t.Fatalf("prepare log level change = %d %s", prepared.Code, prepared.Body.String())
			}
			change := decodeResponse[struct {
				ChangeID string `json:"change_id"`
			}](t, prepared)
			test.before(t, app, change.ChangeID, runtime)
			response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true)
			if response.Code != test.wantCode || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("apply failure = %d %s; want %q", response.Code, response.Body.String(), test.want)
			}
			if !pendingExists(app.server, change.ChangeID) {
				t.Fatal("failed log level change should remain retryable")
			}
		})
	}
}
