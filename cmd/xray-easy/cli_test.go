package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
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
	state         []byte
	restored      [][]byte
	exportErr     error
	restoreErr    error
	restoreErrors []error
}

type cliAWGBackupGateway struct {
	*fakeAmneziaWGGateway
	*cliAWGBackup
}

func (b *cliAWGBackup) ExportBackup(context.Context) ([]byte, error) {
	if b.exportErr != nil {
		return nil, b.exportErr
	}
	return append([]byte(nil), b.state...), nil
}

func (b *cliAWGBackup) RestoreBackup(_ context.Context, state []byte) error {
	b.restored = append(b.restored, append([]byte(nil), state...))
	if len(b.restoreErrors) > 0 {
		err := b.restoreErrors[0]
		b.restoreErrors = b.restoreErrors[1:]
		if err != nil {
			return err
		}
	}
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
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-control.token"))
	if _, err := dialConfiguredAWGBackup(); err == nil || !strings.Contains(err.Error(), "initialize Controller AmneziaWG backup gateway") {
		t.Fatalf("dialConfiguredAWGBackup with unreadable Controller token = %v", err)
	}

	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	client, err = dialConfiguredAWGBackup()
	if err != nil || client == nil {
		t.Fatalf("dialConfiguredAWGBackup with configured AWG = %v, %v", client, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyBackupMasterKeyReportsUnreadableStateDatabase(t *testing.T) {
	info := backup.Info{StatePath: filepath.Join(t.TempDir(), "missing-state.db")}
	if err := verifyBackupMasterKey(info, []byte("0123456789abcdef0123456789abcdef")); err == nil {
		t.Fatal("verifyBackupMasterKey accepted a backup without readable state database")
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
	if err := applyRestoredStateWithRuntime(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, app.sup); err != nil {
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
	if err := applyRestoredStateWithRuntime(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, app.sup); err == nil || !strings.Contains(err.Error(), "decrypt restored REALITY key") {
		t.Fatalf("missing encrypted key error = %v", err)
	}
	missing := newTestApp(t, false)
	if err := applyRestoredStateWithRuntime(context.Background(), missing.server.store, missing.server.masterKey, missing.server.configDir, 443, missing.sup); err == nil || !strings.Contains(err.Error(), "settings are not initialized") {
		t.Fatalf("uninitialized restored state error = %v", err)
	}
}

func TestRestoreCLIValidatesConfirmationAndMasterKeyBeforeOpeningDatabase(t *testing.T) {
	t.Setenv("AWG_PUBLIC_HOST", "")
	t.Setenv("XRAY_EASY_MASTER_KEY", "")
	root := t.TempDir()
	if err := runRestoreCLI(context.Background(), root, root, []string{"backup-name"}); err == nil || !strings.Contains(err.Error(), "RESTORE") {
		t.Fatalf("restore without explicit confirmation = %v", err)
	}
	if err := runRestoreCLI(context.Background(), root, root, []string{"backup-name", "RESTORE"}); err == nil || !strings.Contains(err.Error(), "XRAY_EASY_MASTER_KEY is required") {
		t.Fatalf("restore without master key = %v", err)
	}
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	if err := runRestoreCLI(context.Background(), root, root, []string{"backup-name", "RESTORE"}); err == nil || !strings.Contains(err.Error(), "XRAY_CONTROLLER_ADDR must be configured") {
		t.Fatalf("restore with AWG enabled but no Controller address = %v", err)
	}

	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	tokenPath := filepath.Join(root, "controller.token")
	if err := os.WriteFile(tokenPath, []byte("controller-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	if err := runRestoreCLI(context.Background(), root, root, []string{"missing-backup", "RESTORE"}); err == nil || !strings.Contains(err.Error(), "backup") {
		t.Fatalf("restore with configured AWG gateway should proceed to backup lookup, got %v", err)
	}
}

func TestRestoreCLIReportsDatabaseAndMaintenanceLockFailures(t *testing.T) {
	t.Run("database path is not usable", func(t *testing.T) {
		root := t.TempDir()
		dataPath := filepath.Join(root, "data")
		if err := os.WriteFile(dataPath, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWG_PUBLIC_HOST", "")
		t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
		if err := runRestoreCLI(context.Background(), dataPath, root, []string{"backup-name", "RESTORE"}); err == nil {
			t.Fatal("restore proceeded without opening its database")
		}
	})

	t.Run("maintenance lock path is a directory", func(t *testing.T) {
		root := t.TempDir()
		dataDir := filepath.Join(root, "data")
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dataDir, "maintenance.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWG_PUBLIC_HOST", "")
		t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
		if err := runRestoreCLI(context.Background(), dataDir, root, []string{"backup-name", "RESTORE"}); err == nil || !strings.Contains(err.Error(), "acquire maintenance lock") {
			t.Fatalf("restore maintenance lock error = %v", err)
		}
	})
}

func TestBackupManagerIncludesOptionalAWGBackupService(t *testing.T) {
	app := newTestApp(t, true)
	app.server.awg = &cliAWGBackupGateway{
		fakeAmneziaWGGateway: &fakeAmneziaWGGateway{},
		cliAWGBackup:         &cliAWGBackup{state: []byte("awg snapshot")},
	}
	if manager := app.server.backupManager(); manager.AWG == nil {
		t.Fatal("backup manager did not receive the configured AWG backup service")
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

func TestMainReportsCLIAndControlPlaneFailuresWithoutTerminatingTests(t *testing.T) {
	oldArgs, oldExit, oldStart, oldStderr := os.Args, exitProcess, startControlPlane, os.Stderr
	oldLogger := slog.Default()
	t.Cleanup(func() {
		os.Args, exitProcess, startControlPlane, os.Stderr = oldArgs, oldExit, oldStart, oldStderr
		slog.SetDefault(oldLogger)
	})
	stderr, err := os.CreateTemp(t.TempDir(), "xray-easy-stderr-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = stderr
	var exitCodes []int
	exitProcess = func(code int) { exitCodes = append(exitCodes, code) }

	os.Args = []string{"xray-easy", "unknown-command"}
	main()
	if len(exitCodes) != 1 || exitCodes[0] != 1 {
		t.Fatalf("CLI error exit codes = %v, want [1]", exitCodes)
	}

	os.Args = []string{"xray-easy"}
	startControlPlane = func() error { return errors.New("injected listener failure") }
	main()
	if len(exitCodes) != 2 || exitCodes[1] != 1 {
		t.Fatalf("control-plane error exit codes = %v, want [1 1]", exitCodes)
	}
	startControlPlane = func() error { return nil }
	main()
	if len(exitCodes) != 2 {
		t.Fatalf("successful server startup exited the process: %v", exitCodes)
	}
	if err := stderr.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(stderr)
	if err != nil || !strings.Contains(string(output), "injected listener failure") {
		t.Fatalf("main stderr = %q, %v", output, err)
	}
}

func TestBackupCLIReportsMasterKeyDatabaseAndAWGGatewayFailures(t *testing.T) {
	t.Run("master key missing", func(t *testing.T) {
		t.Setenv("XRAY_EASY_MASTER_KEY", "")
		root := t.TempDir()
		if err := runBackupCLI(t.Context(), root, root, []string{"create"}); err == nil || !strings.Contains(err.Error(), "XRAY_EASY_MASTER_KEY is required") {
			t.Fatalf("backup without master key = %v", err)
		}
	})

	t.Run("database path unusable", func(t *testing.T) {
		root := t.TempDir()
		dataPath := filepath.Join(root, "data")
		if err := os.WriteFile(dataPath, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
		if err := runBackupCLI(t.Context(), dataPath, root, []string{"create"}); err == nil {
			t.Fatal("backup accepted an unusable database path")
		}
	})

	t.Run("AWG controller token unreadable", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
		t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
		t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-controller.token"))
		if err := runBackupCLI(t.Context(), app.server.dataDir, app.server.configDir, []string{"create"}); err == nil || !strings.Contains(err.Error(), "read Controller token") {
			t.Fatalf("backup with unreadable AWG Controller token = %v", err)
		}
	})
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
		// Opening the store runs migrations before the CLI tries the lock. Give
		// that setup enough time under the race detector, then verify that the
		// same deadline is eventually reported by the contended lock acquisition.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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

func TestAdminCLIReportsPasswordAndTOTPFailurePaths(t *testing.T) {
	t.Run("database path is unusable", func(t *testing.T) {
		root := t.TempDir()
		dataPath := filepath.Join(root, "data")
		if err := os.WriteFile(dataPath, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runAdminCLI(t.Context(), dataPath, []string{"logout-all"}); err == nil {
			t.Fatal("admin CLI accepted an unusable data directory")
		}
	})

	t.Run("password reset lock is busy", func(t *testing.T) {
		app := newTestApp(t, true)
		lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		if err := runAdminCLI(ctx, app.server.dataDir, []string{"reset-password"}); err == nil || !strings.Contains(err.Error(), "acquire maintenance lock") {
			t.Fatalf("admin password reset while locked = %v", err)
		}
	})

	t.Run("password input failure", func(t *testing.T) {
		app := newTestApp(t, true)
		previous := readCLIPassword
		readCLIPassword = func(int) ([]byte, error) { return nil, errors.New("terminal unavailable") }
		t.Cleanup(func() { readCLIPassword = previous })
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"reset-password"}); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
			t.Fatalf("password reset terminal failure = %v", err)
		}
	})

	t.Run("password persistence failure", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "reject administrator password update", `CREATE TRIGGER reject_password_update BEFORE UPDATE OF password_hash ON admin_users BEGIN SELECT RAISE(ABORT, 'password update blocked'); END`)
		previous := readCLIPassword
		readCLIPassword = func(int) ([]byte, error) { return []byte("valid replacement password"), nil }
		t.Cleanup(func() { readCLIPassword = previous })
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"reset-password"}); err == nil || !strings.Contains(err.Error(), "reset administrator password") {
			t.Fatalf("password persistence failure = %v", err)
		}
	})

	t.Run("password hash entropy failure", func(t *testing.T) {
		app := newTestApp(t, true)
		previousPasswordReader := readCLIPassword
		readCLIPassword = func(int) ([]byte, error) { return []byte("valid replacement password"), nil }
		t.Cleanup(func() { readCLIPassword = previousPasswordReader })
		previousEntropyReader := cryptorand.Reader
		cryptorand.Reader = failingReader{}
		t.Cleanup(func() { cryptorand.Reader = previousEntropyReader })
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"reset-password"}); err == nil || !strings.Contains(err.Error(), "generate password salt") {
			t.Fatalf("password hash entropy failure = %v", err)
		}
	})

	t.Run("TOTP update failure", func(t *testing.T) {
		app := newTestApp(t, true)
		setTestAdminTOTP(t, app)
		execSQLiteTestMutation(t, app, "reject TOTP reset", `CREATE TRIGGER reject_totp_reset BEFORE UPDATE OF totp_enabled ON admin_users BEGIN SELECT RAISE(ABORT, 'TOTP reset blocked'); END`)
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"reset-totp"}); err == nil || !strings.Contains(err.Error(), "reset TOTP") {
			t.Fatalf("TOTP reset persistence failure = %v", err)
		}
	})

	t.Run("TOTP session revocation failure", func(t *testing.T) {
		app := newTestApp(t, true)
		setTestAdminTOTP(t, app)
		execSQLiteTestMutation(t, app, "reject TOTP reset session deletion", `CREATE TRIGGER reject_totp_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'session revoke blocked'); END`)
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"reset-totp"}); err == nil || !strings.Contains(err.Error(), "revoke sessions") {
			t.Fatalf("TOTP session revocation failure = %v", err)
		}
	})
}

func TestAdminCLIRecoveryCodeGenerationAndPersistenceFailures(t *testing.T) {
	t.Run("entropy source fails", func(t *testing.T) {
		app := newTestApp(t, true)
		setTestAdminTOTP(t, app)
		previous := cryptorand.Reader
		cryptorand.Reader = failingReader{}
		t.Cleanup(func() { cryptorand.Reader = previous })
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"recovery-codes"}); err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("recovery-code entropy error = %v", err)
		}
	})

	t.Run("recovery-code replacement fails", func(t *testing.T) {
		app := newTestApp(t, true)
		setTestAdminTOTP(t, app)
		execSQLiteTestMutation(t, app, "reject recovery-code insert", `CREATE TRIGGER reject_recovery_code_insert BEFORE INSERT ON totp_recovery_codes BEGIN SELECT RAISE(ABORT, 'recovery-code insert blocked'); END`)
		if err := runAdminCLI(t.Context(), app.server.dataDir, []string{"recovery-codes"}); err == nil || !strings.Contains(err.Error(), "replace recovery codes") {
			t.Fatalf("recovery-code persistence error = %v", err)
		}
	})
}

func setTestAdminTOTP(t *testing.T, app testApp) {
	t.Helper()
	secretValue, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := secret.Seal(app.server.masterKey, secretValue, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.store.SetTOTP(t.Context(), app.admin.ID, encrypted, nil); err != nil {
		t.Fatal(err)
	}
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

func TestRestoreCLIReportsPreRestoreAndRollbackFailures(t *testing.T) {
	t.Run("backup master key mismatch", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		settings, err := app.server.store.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityPrivateKeyEnc = "malformed authenticated ciphertext"
		if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
		target, err := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey).Create("key-check")
		if err != nil {
			t.Fatal(err)
		}
		err = runRestoreCLIWithApplier(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
			t.Fatal("restore applier called for a backup with invalid encrypted key material")
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "different XRAY_EASY_MASTER_KEY") {
			t.Fatalf("master-key mismatch result = %v", err)
		}
	})

	t.Run("pre-restore backup fails when AWG snapshot is unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		target, err := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey).Create("restore-target")
		if err != nil {
			t.Fatal(err)
		}
		awg := &cliAWGBackup{exportErr: errors.New("injected AWG snapshot failure")}
		err = runRestoreCLIWithApplierAndAWG(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
			t.Fatal("restore applier called after pre-restore backup failed")
			return nil
		}, awg)
		if err == nil || !strings.Contains(err.Error(), "create pre-restore backup") || !strings.Contains(err.Error(), "injected AWG snapshot failure") {
			t.Fatalf("pre-restore backup result = %v", err)
		}
	})

	t.Run("target state restore failure is reported", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		backupAWG := &cliAWGBackup{state: []byte("target-awg-state")}
		manager := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey)
		manager.AWG = backupAWG
		target, err := manager.Create("restore-target")
		if err != nil {
			t.Fatal(err)
		}
		awg := &cliAWGBackup{state: []byte("current-awg-state"), restoreErr: errors.New("injected AWG restore failure")}
		err = runRestoreCLIWithApplierAndAWG(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
			t.Fatal("restore applier called after state restore failed")
			return nil
		}, awg)
		if err == nil || !strings.Contains(err.Error(), "restore state") || !strings.Contains(err.Error(), "injected AWG restore failure") {
			t.Fatalf("target state restore result = %v", err)
		}
	})

	t.Run("rollback state restore failure is reported", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		backupAWG := &cliAWGBackup{state: []byte("target-awg-state")}
		manager := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey)
		manager.AWG = backupAWG
		target, err := manager.Create("restore-target")
		if err != nil {
			t.Fatal(err)
		}
		awg := &cliAWGBackup{state: []byte("current-awg-state"), restoreErrors: []error{nil, errors.New("injected rollback AWG failure")}}
		applyCalls := 0
		err = runRestoreCLIWithApplierAndAWG(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
			applyCalls++
			return errors.New("injected config apply failure")
		}, awg)
		if err == nil || !strings.Contains(err.Error(), "rollback from") || !strings.Contains(err.Error(), "restore pre-restore snapshot") || !strings.Contains(err.Error(), "injected rollback AWG failure") || applyCalls != 1 {
			t.Fatalf("rollback restore result = %v; apply calls=%d", err, applyCalls)
		}
	})

	t.Run("rollback config apply failure is reported", func(t *testing.T) {
		app := newTestApp(t, true)
		configureCLIEnv(t, app, app.server.masterKey)
		backupAWG := &cliAWGBackup{state: []byte("target-awg-state")}
		manager := backup.NewManager(app.server.store, app.server.dataDir, app.server.configDir, app.server.masterKey)
		manager.AWG = backupAWG
		target, err := manager.Create("restore-target")
		if err != nil {
			t.Fatal(err)
		}
		awg := &cliAWGBackup{state: []byte("current-awg-state")}
		applyCalls := 0
		err = runRestoreCLIWithApplierAndAWG(context.Background(), app.server.dataDir, app.server.configDir, []string{target.Name, "RESTORE"}, func(context.Context, *store.Store, []byte, string, int) error {
			applyCalls++
			return errors.New("injected apply failure")
		}, awg)
		if err == nil || !strings.Contains(err.Error(), "rollback from") || !strings.Contains(err.Error(), "apply pre-restore snapshot") || applyCalls != 2 {
			t.Fatalf("rollback apply result = %v; apply calls=%d", err, applyCalls)
		}
	})
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
