package main

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/auth"
	"xray-easy/internal/secret"
	"xray-easy/internal/totp"
)

func execSQLiteTestMutation(t *testing.T, app testApp, name, statement string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(app.server.dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(statement); err != nil {
		t.Fatalf("install %s trigger: %v", name, err)
	}
}

func enableTestTOTP(t *testing.T, app testApp) (string, string) {
	t.Helper()
	secretValue, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := secret.Seal(app.server.masterKey, secretValue, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	recoveryCode := "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
	if err := app.server.store.SetTOTP(context.Background(), app.admin.ID, encrypted, []string{auth.HashRecoveryCode(recoveryCode)}); err != nil {
		t.Fatal(err)
	}
	code, err := totp.Code(secretValue, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return code, recoveryCode
}

func TestAuthHandlersReportStorageFailures(t *testing.T) {
	t.Parallel()
	t.Run("recovery login cannot consume code", func(t *testing.T) {
		app := newTestApp(t, true)
		_, recoveryCode := enableTestTOTP(t, app)
		execSQLiteTestMutation(t, app, "recovery update", `CREATE TRIGGER reject_recovery_use BEFORE UPDATE ON totp_recovery_codes BEGIN SELECT RAISE(ABORT, 'injected recovery update failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/auth/login/recovery", loginRequest{Username: "admin", Password: "correct horse battery", RecoveryCode: recoveryCode}, false)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not consume recovery code") {
			t.Fatalf("recovery storage error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("logout all cannot delete sessions", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "session delete", `CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'injected session delete failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/auth/logout-all", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not revoke sessions") {
			t.Fatalf("logout-all storage error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("TOTP status cannot count recovery codes", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop recovery table", `DROP TABLE totp_recovery_codes`)
		response := requestJSON(t, app, http.MethodGet, "/api/auth/totp/status", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not read TOTP status") {
			t.Fatalf("TOTP status storage error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("TOTP enable cannot save settings", func(t *testing.T) {
		app := newTestApp(t, true)
		setup := decodeResponse[struct {
			SetupToken string `json:"setup_token"`
			Secret     string `json:"secret"`
		}](t, requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true))
		code, err := totp.Code(setup.Secret, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		execSQLiteTestMutation(t, app, "admin TOTP update", `CREATE TRIGGER reject_totp_enable BEFORE UPDATE ON admin_users WHEN NEW.totp_enabled=1 BEGIN SELECT RAISE(ABORT, 'injected TOTP update failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: code}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not save TOTP settings") {
			t.Fatalf("TOTP enable storage error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("TOTP disable cannot update admin", func(t *testing.T) {
		app := newTestApp(t, true)
		code, _ := enableTestTOTP(t, app)
		execSQLiteTestMutation(t, app, "admin TOTP update", `CREATE TRIGGER reject_totp_disable BEFORE UPDATE ON admin_users WHEN NEW.totp_enabled=0 BEGIN SELECT RAISE(ABORT, 'injected TOTP disable failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "correct horse battery", Code: code}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not disable TOTP") {
			t.Fatalf("TOTP disable storage error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("TOTP disable cannot revoke sessions", func(t *testing.T) {
		app := newTestApp(t, true)
		code, _ := enableTestTOTP(t, app)
		execSQLiteTestMutation(t, app, "session delete", `CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'injected session delete failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "correct horse battery", Code: code}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not revoke sessions") {
			t.Fatalf("TOTP session revocation error = %d %s", response.Code, response.Body.String())
		}
	})
}
