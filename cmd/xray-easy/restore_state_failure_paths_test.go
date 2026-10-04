package main

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/xray"
)

func TestApplyRestoredStateStopsAtPreparationFailures(t *testing.T) {
	tests := []struct {
		name      string
		prepare   func(*testing.T, testApp)
		wantError string
	}{
		{
			name: "list clients",
			prepare: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "rename clients table", `ALTER TABLE clients RENAME TO clients_unavailable`)
			},
			wantError: "no such table: clients",
		},
		{
			name: "seed short ID reserve",
			prepare: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "reject short ID reserve", `DELETE FROM schema_migrations WHERE version=3; DELETE FROM reality_short_ids; CREATE TRIGGER reject_reserve BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'reserve blocked'); END`)
			},
			wantError: "reserve blocked",
		},
		{
			name: "render invalid restored settings",
			prepare: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "invalidate REALITY target", `UPDATE settings SET reality_target='invalid' WHERE id=1`)
			},
			wantError: "REALITY target must be a host:port value",
		},
		{
			name: "create candidates directory",
			prepare: func(t *testing.T, app testApp) {
				candidates := filepath.Join(app.server.configDir, "candidates")
				if err := os.RemoveAll(candidates); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(candidates, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "not a directory",
		},
		{
			name: "record apply operation",
			prepare: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "reject apply operation", `CREATE TRIGGER reject_restore_operation BEFORE INSERT ON apply_operations BEGIN SELECT RAISE(ABORT, 'apply operation blocked'); END`)
			},
			wantError: "record restored Xray configuration apply",
		},
		{
			name: "write candidate file",
			prepare: func(t *testing.T, app testApp) {
				candidates := filepath.Join(app.server.configDir, "candidates")
				if err := os.Chmod(candidates, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(candidates, 0o700) })
			},
			wantError: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(t, true)
			tt.prepare(t, app)
			err := applyRestoredStateWithRuntime(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, app.sup)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantError)) {
				t.Fatalf("applyRestoredStateWithRuntime() error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestApplyRestoredStateStopsAtProtocolAndRuntimeFailures(t *testing.T) {
	tests := []struct {
		name      string
		prepare   func(*testing.T, testApp) xrayRuntimeAPI
		wantError string
	}{
		{
			name: "decrypt a restored protocol credential",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
				t.Setenv("XRAY_SHADOWSOCKS_PORT", "1080")
				client := createRuntimeShadowsocksClient(t, app, "restore-secret")
				execSQLiteTestMutation(t, app, "corrupt Shadowsocks credential", fmt.Sprintf(`UPDATE clients SET shadowsocks_password_enc='invalid' WHERE id='%s'`, client.ID))
				return app.sup
			},
			wantError: "decrypt Shadowsocks password",
		},
		{
			name: "seed reserved short IDs",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				execSQLiteTestMutation(t, app, "reject short ID reserve", `DELETE FROM schema_migrations WHERE version=3`)
				execSQLiteTestMutation(t, app, "reject short ID reserve", `DELETE FROM reality_short_ids`)
				execSQLiteTestMutation(t, app, "reject short ID reserve", `CREATE TRIGGER reject_reserve BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'reserve blocked'); END`)
				return app.sup
			},
			wantError: "reserve blocked",
		},
		{
			name: "load Hysteria settings",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				execSQLiteTestMutation(t, app, "hide Hysteria settings", `ALTER TABLE hysteria_settings RENAME TO hysteria_settings_unavailable`)
				return app.sup
			},
			wantError: "no such table: hysteria_settings",
		},
		{
			name: "generate apply operation ID",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				if err := app.server.store.SeedReservedShortIDs(t.Context(), xray.ReservedShortIDCount, xray.NewShortID); err != nil {
					t.Fatal(err)
				}
				previous := cryptorand.Reader
				cryptorand.Reader = authEntropyReader{}
				t.Cleanup(func() { cryptorand.Reader = previous })
				return app.sup
			},
			wantError: "injected entropy failure",
		},
		{
			name: "record apply operation",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				execSQLiteTestMutation(t, app, "reject apply operation", `CREATE TRIGGER reject_restore_operation BEFORE INSERT ON apply_operations BEGIN SELECT RAISE(ABORT, 'apply operation blocked'); END`)
				return app.sup
			},
			wantError: "record restored Xray configuration apply",
		},
		{
			name: "write candidate config",
			prepare: func(t *testing.T, app testApp) xrayRuntimeAPI {
				candidates := filepath.Join(app.server.configDir, "candidates")
				if err := os.Chmod(candidates, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(candidates, 0o700) })
				return app.sup
			},
			wantError: "permission denied",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			runtime := test.prepare(t, app)
			err := applyRestoredStateWithRuntime(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, runtime)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantError)) {
				t.Fatalf("applyRestoredStateWithRuntime() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestApplyRestoredStateReportsRuntimeRollbackFailure(t *testing.T) {
	app := newTestApp(t, true)
	if err := os.Mkdir(filepath.Join(app.server.configDir, "active.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeXrayRuntime{applyErrors: []error{nil, errors.New("rollback refused")}}
	err := applyRestoredStateWithRuntime(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, runtime)
	if err == nil || !strings.Contains(err.Error(), "rollback failed: rollback refused") {
		t.Fatalf("applyRestoredStateWithRuntime() error = %v, want promotion and rollback failure", err)
	}
}
