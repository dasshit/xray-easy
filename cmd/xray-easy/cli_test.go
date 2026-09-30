package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/auth"
	"xray-easy/internal/backup"
	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/totp"
)

func configureCLIEnv(t *testing.T, app testApp, masterKey []byte) {
	t.Helper()
	t.Setenv("XRAY_EASY_DATA_DIR", app.server.dataDir)
	t.Setenv("XRAY_EASY_CONFIG_DIR", app.server.configDir)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(masterKey))
	t.Setenv("XRAY_PUBLIC_PORT", "443")
}

type cliAWGBackup struct {
	state      []byte
	restored   [][]byte
	exportErr  error
	restoreErr error
}

func (b *cliAWGBackup) ExportBackup(context.Context) ([]byte, error) {
	if b.exportErr != nil {
		return nil, b.exportErr
	}
	return append([]byte(nil), b.state...), nil
}

func (b *cliAWGBackup) RestoreBackup(_ context.Context, state []byte) error {
	b.restored = append(b.restored, append([]byte(nil), state...))
	if b.restoreErr != nil {
		return b.restoreErr
	}
	b.state = append([]byte(nil), state...)
	return nil
}

func TestMasterKeyAndPublicPortEnvironmentValidation(t *testing.T) {
	t.Setenv("XRAY_EASY_MASTER_KEY", "")
	if _, err := loadMasterKey(); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("missing master key error = %v", err)
	}
	t.Setenv("XRAY_EASY_MASTER_KEY", "not-base64")
	if _, err := loadMasterKey(); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("malformed master key error = %v", err)
	}
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := loadMasterKey(); err == nil {
		t.Fatal("short master key accepted")
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("XRAY_EASY_MASTER_KEY", "  "+base64.StdEncoding.EncodeToString(key)+"  ")
	if got, err := loadMasterKey(); err != nil || string(got) != string(key) {
		t.Fatalf("valid master key = %x, %v", got, err)
	}
	for _, invalid := range []string{"bad", "0", "65536"} {
		t.Setenv("XRAY_PUBLIC_PORT", invalid)
		if _, err := configuredPublicPort(); err == nil {
			t.Errorf("invalid public port %q accepted", invalid)
		}
	}
	for _, value := range []string{"1", "443", "65535"} {
		t.Setenv("XRAY_PUBLIC_PORT", value)
		if got, err := configuredPublicPort(); err != nil || got == 0 {
			t.Errorf("valid public port %q = %d, %v", value, got, err)
		}
	}
	t.Setenv("SAMPLE_ENV", " configured ")
	if got := envOr("SAMPLE_ENV", "fallback"); got != "configured" || envOr("MISSING_ENV", "fallback") != "fallback" {
		t.Fatalf("envOr values = %q / %q", got, envOr("MISSING_ENV", "fallback"))
	}
}

func TestDialConfiguredAWGBackupHonorsOptionalServiceConfiguration(t *testing.T) {
	t.Setenv("AWG_PUBLIC_HOST", "")
	client, err := dialConfiguredAWGBackup()
	if err != nil || client != nil {
		t.Fatalf("dialConfiguredAWGBackup without AWG = %v, %v", client, err)
	}

	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	if _, err := dialConfiguredAWGBackup(); err == nil || !strings.Contains(err.Error(), "XRAY_CONTROLLER_ADDR must be configured") {
		t.Fatalf("dialConfiguredAWGBackup without Controller = %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), "control.token")
	if err := os.WriteFile(tokenPath, []byte("test-controller-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	client, err = dialConfiguredAWGBackup()
	if err != nil || client == nil {
		t.Fatalf("dialConfiguredAWGBackup with configured AWG = %v, %v", client, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCLIUsageAdminCommandsBackupAndRestoreValidation(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	if err := runCLI(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("empty CLI args error = %v", err)
	}
	if err := runCLI(context.Background(), []string{"unknown"}); err == nil {
		t.Fatal("unknown CLI command accepted")
	}
	if err := runAdminCLI(context.Background(), app.server.dataDir, nil); err == nil {
		t.Fatal("admin CLI with missing action accepted")
	}
	if err := runCLI(context.Background(), []string{"admin", "unknown"}); err == nil {
		t.Fatal("unknown admin action accepted")
	}
	if err := runCLI(context.Background(), []string{"admin", "logout-all"}); err != nil {
		t.Fatalf("admin logout-all: %v", err)
	}
	if _, err := app.server.store.SessionAdmin(context.Background(), app.token); err == nil {
		t.Fatal("CLI logout-all did not revoke active session")
	}
	if err := runCLI(context.Background(), []string{"admin", "recovery-codes"}); err == nil || !strings.Contains(err.Error(), "TOTP is not enabled") {
		t.Fatalf("recovery codes while TOTP disabled = %v", err)
	}
	secretValue, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := secret.Seal(app.server.masterKey, secretValue, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.store.SetTOTP(context.Background(), app.admin.ID, encrypted, []string{auth.HashRecoveryCode("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE")}); err != nil {
		t.Fatal(err)
	}
	if err := runCLI(context.Background(), []string{"admin", "recovery-codes"}); err != nil {
		t.Fatalf("rotate recovery codes: %v", err)
	}
	if count, err := app.server.store.RecoveryCodeCount(context.Background(), app.admin.ID); err != nil || count != 10 {
		t.Fatalf("recovery code count after CLI rotation = %d, %v", count, err)
	}
	if err := runCLI(context.Background(), []string{"admin", "reset-totp"}); err != nil {
		t.Fatalf("reset TOTP CLI: %v", err)
	}
	admin, err := app.server.store.FindAdmin(context.Background(), "admin")
	if err != nil || admin.TOTPEnabled {
		t.Fatalf("TOTP still enabled after CLI reset: %+v %v", admin, err)
	}
	if err := runCLI(context.Background(), []string{"backup"}); err == nil {
		t.Fatal("backup CLI missing action accepted")
	}
	if err := runCLI(context.Background(), []string{"restore", "backup-name"}); err == nil || !strings.Contains(err.Error(), "RESTORE") {
		t.Fatalf("restore CLI missing confirmation = %v", err)
	}
	if err := runCLI(context.Background(), []string{"restore", "../escape", "RESTORE"}); err == nil || !strings.Contains(err.Error(), "invalid backup name") {
		t.Fatalf("invalid restore name error = %v", err)
	}
	created, err := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey).Create("manual")
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("abcdef0123456789abcdef0123456789")
	if err := verifyBackupMasterKey(created, wrongKey); err == nil || !strings.Contains(err.Error(), "different XRAY_EASY_MASTER_KEY") {
		t.Fatalf("backup key mismatch = %v", err)
	}
	// Restore command verifies the bundle before replacing state and reports bad keys safely.
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(wrongKey))
	if err := runCLI(context.Background(), []string{"restore", created.Name, "RESTORE"}); err == nil || !strings.Contains(err.Error(), "HMAC") {
		t.Fatalf("restore with wrong master key = %v", err)
	}
}

func TestRunBackupCLIAndApplyRestoredStateValidation(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"unknown"}); err == nil {
		t.Fatal("unknown backup action accepted")
	}
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"create", "extra"}); err == nil {
		t.Fatal("extra backup argument accepted")
	}
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"create"}); err != nil {
		t.Fatalf("CLI backup create: %v", err)
	}
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"list"}); err != nil {
		t.Fatalf("CLI backup list: %v", err)
	}
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"create"}); err != nil {
		t.Fatal(err)
	}
	if err := applyRestoredStateWithSupervisor(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, app.sup); err != nil {
		t.Fatalf("apply restored state with usable settings: %v", err)
	}
	_ = os.Remove(filepath.Join(app.server.configDir, "active.json"))
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.RealityPrivateKeyEnc = ""
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := applyRestoredStateWithSupervisor(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, app.sup); err == nil || !strings.Contains(err.Error(), "decrypt restored REALITY key") {
		t.Fatalf("missing encrypted key error = %v", err)
	}
	missing := newTestApp(t, false)
	if err := applyRestoredStateWithSupervisor(context.Background(), missing.server.store, missing.server.masterKey, missing.server.configDir, 443, missing.sup); err == nil || !strings.Contains(err.Error(), "settings are not initialized") {
		t.Fatalf("uninitialized restored state error = %v", err)
	}
}

func TestMainDispatchesValidCLICommand(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	previousArgs := os.Args
	os.Args = []string{"xray-easy", "backup", "list"}
	t.Cleanup(func() { os.Args = previousArgs })
	main()
}

func TestAdminAndBackupCLIPropagateStorageAndLockFailures(t *testing.T) {
	t.Run("admin lookup", func(t *testing.T) {
		dataDir := t.TempDir()
		if err := runAdminCLI(context.Background(), dataDir, []string{"logout-all"}); err == nil || !strings.Contains(err.Error(), "admin not found") {
			t.Fatalf("missing admin error = %v", err)
		}
	})

	t.Run("logout-all storage error", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		execSQLiteTestMutation(t, app, "session delete", `CREATE TRIGGER reject_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'injected session delete failure'); END`)
		if err := runCLI(context.Background(), []string{"admin", "logout-all"}); err == nil || !strings.Contains(err.Error(), "logout all sessions") {
			t.Fatalf("logout-all CLI error = %v", err)
		}
	})

	t.Run("backup lock unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if err := runBackupCLI(ctx, app.server.dataDir, app.server.configDir, []string{"create"}); err == nil || !strings.Contains(err.Error(), "maintenance lock") {
			t.Fatalf("backup lock error = %v", err)
		}
	})

	t.Run("backup manager create error", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte("invalid json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"create"}); err == nil || !strings.Contains(err.Error(), "parse active config") {
			t.Fatalf("backup config error = %v", err)
		}
	})

	t.Run("backup manager list error", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		if err := os.WriteFile(filepath.Join(app.server.dataDir, "backups"), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runBackupCLI(context.Background(), app.server.dataDir, app.server.configDir, []string{"list"}); err == nil {
			t.Fatal("backup list error was ignored")
		}
	})
}

func TestRestoreCLIRejectsInvalidConfiguredPortAfterDryRunRestore(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	target, err := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey).Create("restore-target")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "changed.example.test"
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_PUBLIC_PORT", "not-a-port")
	called := false
	err = runRestoreCLIWithApplier(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "XRAY_PUBLIC_PORT") || called {
		t.Fatalf("invalid restore port error=%v applierCalled=%v", err, called)
	}
	settings, err = app.server.store.GetSettings(context.Background())
	if err != nil || settings.PublicHost != "vpn.example.test" {
		t.Fatalf("restore dry run did not load target state before rejecting port: %+v, %v", settings, err)
	}
}

func TestVerifyBackupMasterKeyAllowsBackupWithoutPrivateKey(t *testing.T) {
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.RealityPrivateKeyEnc = ""
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	info, err := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey).Create("without-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBackupMasterKey(info, []byte("different 32 byte master key value")); err != nil {
		t.Fatalf("backup without encrypted key should be restorable: %v", err)
	}
}

func TestRestoreCLIAppliesBackupAndRollsBackOnApplyFailure(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	manager := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey)
	target, err := manager.Create("before-change")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "changed.example.test"
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	var calls int
	applier := func(ctx context.Context, db *store.Store, key []byte, configDir string, port int) error {
		calls++
		if port != 443 || len(key) < 32 || configDir != app.server.configDir {
			t.Fatalf("restore applier arguments: port=%d key=%d config=%q", port, len(key), configDir)
		}
		if calls == 1 {
			current, err := db.GetSettings(ctx)
			if err != nil || current.PublicHost != "vpn.example.test" {
				t.Fatalf("restored target state before apply = %+v, %v", current, err)
			}
			return errors.New("fake Xray apply failed")
		}
		return nil
	}
	err = runRestoreCLIWithApplier(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, applier)
	if err == nil || !strings.Contains(err.Error(), "state rolled back") || calls != 2 {
		t.Fatalf("restore rollback = %v, apply calls=%d", err, calls)
	}
	settings, err = app.server.store.GetSettings(context.Background())
	if err != nil || settings.PublicHost != "changed.example.test" {
		t.Fatalf("database was not restored to pre-restore state: %+v, %v", settings, err)
	}

	// A fresh restore of the same bundle succeeds, preserving backup state and applying it once.
	settings.PublicHost = "another.example.test"
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	calls = 0
	err = runRestoreCLIWithApplier(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
		calls++
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("successful restore = %v, apply calls=%d", err, calls)
	}
	settings, err = app.server.store.GetSettings(context.Background())
	if err != nil || settings.PublicHost != "vpn.example.test" {
		t.Fatalf("successful restore settings = %+v, %v", settings, err)
	}
}

func TestRestoreCLIIncludesAWGStateAndRollsItBackOnApplyFailure(t *testing.T) {
	app := newTestApp(t, true)
	configureCLIEnv(t, app, app.server.masterKey)
	awg := &cliAWGBackup{state: []byte("awg-before")}
	manager := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey)
	manager.AWG = awg
	target, err := manager.Create("with-awg")
	if err != nil {
		t.Fatal(err)
	}
	awg.state = []byte("awg-current")
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "changed.example.test"
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	var applyCalls int
	apply := func(context.Context, *store.Store, []byte, string, int) error {
		applyCalls++
		if applyCalls == 1 {
			return errors.New("injected restored-config failure")
		}
		return nil
	}
	err = runRestoreCLIWithApplierAndAWG(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, apply, awg)
	if err == nil || !strings.Contains(err.Error(), "state rolled back") || applyCalls != 2 {
		t.Fatalf("restore rollback result = %v, apply calls=%d", err, applyCalls)
	}
	if string(awg.state) != "awg-current" || len(awg.restored) < 2 || string(awg.restored[0]) != "awg-before" || string(awg.restored[len(awg.restored)-1]) != "awg-current" {
		t.Fatalf("AmneziaWG backup/rollback states = %q / %q", awg.state, awg.restored)
	}
}

func TestAtomicWriteDecodeJSONAndSmallHelpers(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "file.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("atomic file = %q, %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("atomic file permissions = %v, %v", info, err)
	}
	if err := writeAtomic(filepath.Join(root, "absent", "file"), []byte("x")); err == nil {
		t.Fatal("writeAtomic accepted missing destination directory")
	}
	var decoded struct {
		Value string `json:"value"`
	}
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":"ok"}`))
	if err := decodeJSON(request, &decoded); err != nil || decoded.Value != "ok" {
		t.Fatalf("decodeJSON valid body = %+v, %v", decoded, err)
	}
	for name, body := range map[string]string{"malformed": "{", "too large": strings.Repeat("x", 1<<20)} {
		t.Run(name, func(t *testing.T) {
			err := decodeJSON(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &decoded)
			if err == nil {
				t.Fatal("invalid JSON body accepted")
			}
		})
	}
	if got := sessionToken(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Fatalf("missing session token = %q", got)
	}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: "session"})
	if got := sessionToken(request); got != "session" {
		t.Fatalf("session token = %q", got)
	}
	if got := publicSettings(domain.Settings{PublicHost: "node.test", PublicPort: 443}, 9443); got["public_host"] != "node.test" || got["protocol"] == "" || got["vmess_public_port"] != 9443 {
		t.Fatalf("public settings = %+v", got)
	}
	first, err := randomID()
	if err != nil || len(first) != 32 {
		t.Fatalf("random ID = %q, %v", first, err)
	}
	second, err := randomID()
	if err != nil || first == second {
		t.Fatalf("random IDs = %q %q, %v", first, second, err)
	}
	passed := false
	requestLimit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passed = true })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !passed {
		t.Fatal("requestLimit did not delegate")
	}
	if cliUsageError() == nil {
		t.Fatal("missing CLI usage error")
	}
}
