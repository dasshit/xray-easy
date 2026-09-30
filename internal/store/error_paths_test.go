package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestStoreTransactionsRollBackWhenTOTPTriggersFail(t *testing.T) {
	db, ctx := openTestStore(t, "trigger-totp.db")
	admin := initTestAdmin(t, db, ctx)
	if _, err := db.db.Exec(`CREATE TRIGGER reject_recovery_insert BEFORE INSERT ON totp_recovery_codes BEGIN SELECT RAISE(ABORT, 'injected insert error'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTOTP(ctx, admin.ID, "encrypted", []string{"hash"}); err == nil || !strings.Contains(err.Error(), "injected insert error") {
		t.Fatalf("SetTOTP insertion failure = %v", err)
	}
	after, err := db.FirstAdmin(ctx)
	if err != nil || after.TOTPEnabled || after.TOTPSecretEnc != "" {
		t.Fatalf("SetTOTP left a partial update after trigger failure: %+v, %v", after, err)
	}
	if _, err := db.db.Exec(`DROP TRIGGER reject_recovery_insert`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetTOTP(ctx, admin.ID, "encrypted", []string{"hash"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER reject_recovery_delete BEFORE DELETE ON totp_recovery_codes BEGIN SELECT RAISE(ABORT, 'injected delete error'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.DisableTOTP(ctx, admin.ID); err == nil || !strings.Contains(err.Error(), "injected delete error") {
		t.Fatalf("DisableTOTP deletion failure = %v", err)
	}
	after, err = db.FirstAdmin(ctx)
	if err != nil || !after.TOTPEnabled || after.TOTPSecretEnc != "encrypted" {
		t.Fatalf("DisableTOTP partial update was not rolled back: %+v, %v", after, err)
	}
}

func TestStoreRejectsCorruptRowsAndCanceledWrites(t *testing.T) {
	db, ctx := openTestStore(t, "corrupt-rows.db")
	admin := initTestAdmin(t, db, ctx)
	if _, err := db.Initialize(ctx, "", "", "", 0); err == nil {
		t.Fatal("Initialize accepted empty credentials")
	}
	if _, err := db.Initialize(ctx, "other", "hash", "other.example", 443); err == nil {
		t.Fatal("Initialize accepted a second administrator")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.CreateSession(canceled, admin.ID, time.Hour); err == nil {
		t.Fatal("CreateSession succeeded with canceled context")
	}
	if err := db.AddAudit(ctx, admin.ID, "test", "admin", admin.ID, "valid audit event"); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsAndClientStateTransactionRollsBackOnWriteFailures(t *testing.T) {
	db, ctx := openTestStore(t, "settings-client-failures.db")
	initTestAdmin(t, db, ctx)
	initial, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate := initial
	candidate.PublicHost = "candidate.example.test"

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := db.UpdateSettingsAndClientStates(canceled, candidate, nil); err == nil {
		t.Fatal("settings/client transaction began with canceled context")
	}

	if _, err := db.db.Exec(`CREATE TRIGGER reject_rotation_settings BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT, 'settings update blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSettingsAndClientStates(ctx, candidate, nil); err == nil || !strings.Contains(err.Error(), "settings update blocked") {
		t.Fatalf("settings update failure = %v", err)
	}
	if _, err := db.db.Exec(`DROP TRIGGER reject_rotation_settings`); err != nil {
		t.Fatal(err)
	}

	client := createTestClient(t, db, ctx, "phone-1")
	if _, err := db.db.Exec(`CREATE TRIGGER reject_rotation_client BEFORE UPDATE ON clients BEGIN SELECT RAISE(ABORT, 'client update blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSettingsAndClientStates(ctx, candidate, map[string]ClientState{client.ID: {Revoked: true}}); err == nil || !strings.Contains(err.Error(), "client update blocked") {
		t.Fatalf("client update failure = %v", err)
	}
	after, err := db.GetSettings(ctx)
	if err != nil || after.PublicHost != initial.PublicHost {
		t.Fatalf("failed client update committed settings: %+v, %v", after, err)
	}
}

func TestRestoreFromRollsBackWhenDestinationDeleteOrSourceSchemaFails(t *testing.T) {
	ctx := context.Background()
	t.Run("destination trigger", func(t *testing.T) {
		destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer destination.Close()
		initTestAdmin(t, destination, ctx)
		before, err := destination.GetSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		initTestAdmin(t, source, ctx)
		changed, err := source.GetSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		changed.PublicHost = "source.example.test"
		if err := source.UpdateSettings(ctx, changed); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "source.snapshot.db")
		if err := source.BackupTo(path); err != nil {
			t.Fatal(err)
		}
		if _, err := destination.db.Exec(`CREATE TRIGGER block_settings_delete BEFORE DELETE ON settings BEGIN SELECT RAISE(ABORT, 'blocked delete'); END`); err != nil {
			t.Fatal(err)
		}
		if err := destination.RestoreFrom(path); err == nil || !strings.Contains(err.Error(), "clear table settings") {
			t.Fatalf("restore delete-trigger error = %v", err)
		}
		after, err := destination.GetSettings(ctx)
		if err != nil || after.PublicHost != before.PublicHost {
			t.Fatalf("failed restore changed destination settings: %+v, %v", after, err)
		}
	})

	t.Run("source schema mismatch", func(t *testing.T) {
		destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer destination.Close()
		admin := initTestAdmin(t, destination, ctx)
		before, err := destination.GetSettings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
		if err != nil {
			t.Fatal(err)
		}
		initTestAdmin(t, source, ctx)
		path := filepath.Join(t.TempDir(), "wrong-schema.db")
		if err := source.BackupTo(path); err != nil {
			t.Fatal(err)
		}
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		wrong, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wrong.Exec(`DROP TABLE schema_migrations`); err != nil {
			_ = wrong.Close()
			t.Fatal(err)
		}
		if _, err := wrong.Exec(`CREATE TABLE schema_migrations (wrong_column TEXT)`); err != nil {
			_ = wrong.Close()
			t.Fatal(err)
		}
		if err := wrong.Close(); err != nil {
			t.Fatal(err)
		}
		if err := destination.RestoreFrom(path); err == nil || !strings.Contains(err.Error(), "restore table schema_migrations") {
			t.Fatalf("restore source-schema error = %v", err)
		}
		after, err := destination.GetSettings(ctx)
		if err != nil || after.PublicHost != before.PublicHost {
			t.Fatalf("schema failure changed destination: %+v, %v", after, err)
		}
		if _, err := destination.FindAdmin(ctx, "admin"); err != nil || admin.ID == "" {
			t.Fatalf("destination admin lost after failed restore: %v", err)
		}
	})
}

func TestRestoreFromLegacySettingsWithoutLogLevelDefaultsToWarning(t *testing.T) {
	ctx := context.Background()
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	initTestAdmin(t, destination, ctx)
	settings, err := destination.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	settings.LogLevel = "debug"
	if err := destination.UpdateSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}

	source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	initTestAdmin(t, source, ctx)
	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	if err := source.BackupTo(legacyPath); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", "file:"+legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`ALTER TABLE settings DROP COLUMN log_level`); err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(legacyPath); err != nil {
		t.Fatalf("restore legacy settings: %v", err)
	}
	got, err := destination.GetSettings(ctx)
	if err != nil || got.LogLevel != "warning" {
		t.Fatalf("restored log level = %q, %v", got.LogLevel, err)
	}
}

func TestRestoreFromOlderSnapshotDefaultsMissingOptionalProtocolTables(t *testing.T) {
	ctx := context.Background()
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	initTestAdmin(t, destination, ctx)
	if err := destination.InitializeHysteriaSettings(ctx, domain.HysteriaSettings{
		Enabled: true, Host: "old.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "old.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}); err != nil {
		t.Fatal(err)
	}

	source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	initTestAdmin(t, source, ctx)
	for _, table := range []string{"hysteria_settings", "reality_short_ids"} {
		if _, err := source.db.Exec(`DROP TABLE ` + table); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "older-snapshot.db")
	if err := source.BackupTo(path); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(path); err != nil {
		t.Fatalf("restore snapshot without optional protocol tables: %v", err)
	}
	settings, err := destination.GetHysteriaSettings(ctx)
	if err != nil || settings.Enabled || settings.TLSMode != domain.HysteriaTLSLegacy || settings.UDPIdleTimeout != 60 {
		t.Fatalf("default Hysteria settings after legacy restore = %+v, %v", settings, err)
	}
	reserved, err := destination.ListReservedShortIDs(ctx)
	if err != nil || len(reserved) != 0 {
		t.Fatalf("short-ID history after legacy restore = %v, %v", reserved, err)
	}
}

func TestRestoreFromReportsClosedDestination(t *testing.T) {
	ctx := context.Background()
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	initTestAdmin(t, source, ctx)
	path := filepath.Join(t.TempDir(), "source-snapshot.db")
	if err := source.BackupTo(path); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(path); err == nil {
		t.Fatal("RestoreFrom succeeded after the destination store was closed")
	}
}

func TestRestoreFromHandlesProtocolSnapshotsWithMissingVMessStateColumns(t *testing.T) {
	ctx := context.Background()
	for _, missing := range []string{"vmess_enabled vmess_revoked", "vmess_revoked", "vmess_enabled"} {
		t.Run(strings.ReplaceAll(missing, " ", "_"), func(t *testing.T) {
			destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			initTestAdmin(t, destination, ctx)

			source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
			if err != nil {
				t.Fatal(err)
			}
			client := domain.Client{
				ID: "vmess-phone", Name: "VMess phone", Protocol: domain.ProtocolVMess,
				UUID: "vmess-uuid", Email: "vmess-phone@xray-easy", Enabled: true, VMessEnabled: true,
			}
			if err := source.CreateVMessClient(ctx, client); err != nil {
				_ = source.Close()
				t.Fatal(err)
			}
			for _, column := range strings.Fields(missing) {
				if _, err := source.db.Exec(`ALTER TABLE clients DROP COLUMN ` + column); err != nil {
					_ = source.Close()
					t.Fatalf("drop legacy optional column %s: %v", column, err)
				}
			}
			path := filepath.Join(t.TempDir(), "legacy-protocol-state.db")
			if err := source.BackupTo(path); err != nil {
				_ = source.Close()
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if err := destination.RestoreFrom(path); err != nil {
				t.Fatalf("restore protocol-aware legacy snapshot: %v", err)
			}
			restored, err := destination.GetClient(ctx, client.ID)
			if err != nil {
				t.Fatal(err)
			}
			wantEnabled := !strings.Contains(missing, "vmess_enabled")
			if restored.VMessEnabled != wantEnabled || restored.VMessRevoked {
				t.Fatalf("legacy VMess state = enabled:%v revoked:%v, want enabled:%v revoked:false", restored.VMessEnabled, restored.VMessRevoked, wantEnabled)
			}
		})
	}
}

func TestRestoreFromRejectsMalformedClientAndSettingsSchemasAtomically(t *testing.T) {
	ctx := context.Background()
	for _, table := range []string{"clients", "settings"} {
		t.Run(table, func(t *testing.T) {
			destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			initTestAdmin(t, destination, ctx)
			before, err := destination.GetSettings(ctx)
			if err != nil {
				t.Fatal(err)
			}

			source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
			if err != nil {
				t.Fatal(err)
			}
			initTestAdmin(t, source, ctx)
			path := filepath.Join(t.TempDir(), "malformed-source.db")
			if err := source.BackupTo(path); err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			malformed, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := malformed.Exec(`DROP TABLE ` + table); err != nil {
				_ = malformed.Close()
				t.Fatal(err)
			}
			if _, err := malformed.Exec(`CREATE TABLE ` + table + ` (unexpected TEXT)`); err != nil {
				_ = malformed.Close()
				t.Fatal(err)
			}
			if err := malformed.Close(); err != nil {
				t.Fatal(err)
			}
			if err := destination.RestoreFrom(path); err == nil || !strings.Contains(err.Error(), "restore table "+table) {
				t.Fatalf("restore malformed %s schema = %v", table, err)
			}
			after, err := destination.GetSettings(ctx)
			if err != nil || after.PublicHost != before.PublicHost {
				t.Fatalf("failed %s restore partially changed destination: %+v, %v", table, after, err)
			}
		})
	}
}

func TestClientProtocolMigrationRejectsLegacyForeignKeyViolationsWithoutReplacingTable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-with-orphan.db")
	initial, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(OFF)")
	if err != nil {
		t.Fatal(err)
	}
	legacy.SetMaxOpenConns(1)
	statements := []string{
		`DROP TABLE traffic_snapshots`,
		`DROP TABLE clients`,
		`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, short_id TEXT NOT NULL UNIQUE, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE traffic_snapshots (client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE, raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0, total_upload INTEGER NOT NULL DEFAULT 0, total_download INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL DEFAULT '', last_polled_at TEXT NOT NULL)`,
		`INSERT INTO traffic_snapshots(client_id, last_polled_at) VALUES('orphan', '2026-01-01T00:00:00Z')`,
		`DELETE FROM schema_migrations WHERE version=4`,
	}
	for _, statement := range statements {
		if _, err := legacy.Exec(statement); err != nil {
			_ = legacy.Close()
			t.Fatalf("prepare malformed legacy database: %v (%s)", err, statement)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if migrated, err := Open(ctx, path); err == nil {
		_ = migrated.Close()
		t.Fatal("protocol migration accepted an orphaned traffic snapshot")
	} else if !strings.Contains(err.Error(), "foreign key check failed after clients migration") {
		t.Fatalf("migration foreign-key error = %v", err)
	}

	check, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var hasProtocol int
	if err := check.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name='protocol'`).Scan(&hasProtocol); err != nil {
		t.Fatal(err)
	}
	if hasProtocol != 0 {
		t.Fatal("failed migration left the protocol-aware clients table installed")
	}
	var orphanCount int
	if err := check.QueryRow(`SELECT COUNT(*) FROM traffic_snapshots WHERE client_id='orphan'`).Scan(&orphanCount); err != nil || orphanCount != 1 {
		t.Fatalf("failed migration changed orphan snapshot: count=%d err=%v", orphanCount, err)
	}
}
