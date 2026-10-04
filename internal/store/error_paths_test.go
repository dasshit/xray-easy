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

func TestTOTPAndRecoveryCodeOperationsPropagateEachTransactionalWriteFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		trigger   string
		operation func(*Store, context.Context, Admin) error
		want      string
	}{
		{
			name:    "TOTP account update",
			trigger: `CREATE TRIGGER reject_totp_account_update BEFORE UPDATE ON admin_users BEGIN SELECT RAISE(ABORT, 'admin update blocked'); END`,
			operation: func(db *Store, ctx context.Context, admin Admin) error {
				return db.SetTOTP(ctx, admin.ID, "secret", nil)
			},
			want: "admin update blocked",
		},
		{
			name:    "recovery-code replacement delete",
			trigger: `CREATE TRIGGER reject_recovery_replace_delete BEFORE DELETE ON totp_recovery_codes BEGIN SELECT RAISE(ABORT, 'recovery delete blocked'); END`,
			operation: func(db *Store, ctx context.Context, admin Admin) error {
				return db.ReplaceRecoveryCodes(ctx, admin.ID, []string{"hash"})
			},
			want: "recovery delete blocked",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, ctx := openTestStore(t, "totp-write-"+strings.ReplaceAll(test.name, " ", "-")+".db")
			admin := initTestAdmin(t, db, ctx)
			if test.name == "recovery-code replacement delete" {
				if err := db.SetTOTP(ctx, admin.ID, "old-secret", []string{"old-hash"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.db.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			if err := test.operation(db, ctx, admin); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("operation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestInitializeAndPasswordChangeRollBackAfterWriteTriggers(t *testing.T) {
	t.Run("administrator insert", func(t *testing.T) {
		db, ctx := openTestStore(t, "initialize-admin-trigger.db")
		if _, err := db.db.Exec(`CREATE TRIGGER reject_initial_admin BEFORE INSERT ON admin_users BEGIN SELECT RAISE(ABORT, 'admin insert blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Initialize(ctx, "admin", "hash", "vpn.example.test", 443); err == nil || !strings.Contains(err.Error(), "admin insert blocked") {
			t.Fatalf("Initialize admin insertion error = %v", err)
		}
	})

	t.Run("password update", func(t *testing.T) {
		db, ctx := openTestStore(t, "password-update-trigger.db")
		admin := initTestAdmin(t, db, ctx)
		if _, err := db.db.Exec(`CREATE TRIGGER reject_admin_password BEFORE UPDATE OF password_hash ON admin_users BEGIN SELECT RAISE(ABORT, 'password update blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := db.ChangeAdminPassword(ctx, admin.ID, "new-hash"); err == nil || !strings.Contains(err.Error(), "password update blocked") {
			t.Fatalf("ChangeAdminPassword update error = %v", err)
		}
		current, err := db.FirstAdmin(ctx)
		if err != nil || current.PasswordHash != "password-hash" {
			t.Fatalf("failed password update partially changed hash: %+v, %v", current, err)
		}
	})

	t.Run("session deletion", func(t *testing.T) {
		db, ctx := openTestStore(t, "password-session-delete-trigger.db")
		admin := initTestAdmin(t, db, ctx)
		if _, err := db.CreateSession(ctx, admin.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`CREATE TRIGGER reject_password_session_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'session delete blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := db.ChangeAdminPassword(ctx, admin.ID, "new-hash"); err == nil || !strings.Contains(err.Error(), "session delete blocked") {
			t.Fatalf("ChangeAdminPassword session deletion error = %v", err)
		}
		current, err := db.FirstAdmin(ctx)
		if err != nil || current.PasswordHash != "password-hash" {
			t.Fatalf("failed password transaction changed hash: %+v, %v", current, err)
		}
	})
}

func TestCreateClientRollsBackOnClientOrShortIDHistoryWriteFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		trigger string
		client  domain.Client
		shortID string
		want    string
	}{
		{name: "client row", trigger: `CREATE TRIGGER reject_client_row BEFORE INSERT ON clients BEGIN SELECT RAISE(ABORT, 'client insert blocked'); END`, client: domain.Client{ID: "phone", Name: "phone", Enabled: true}, shortID: "", want: "client insert blocked"},
		{name: "short ID history", trigger: `CREATE TRIGGER reject_short_id_history BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'history insert blocked'); END`, client: domain.Client{ID: "phone", Name: "phone", Enabled: true}, shortID: "0123456789abcdef", want: "history insert blocked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, ctx := openTestStore(t, "create-client-"+strings.ReplaceAll(test.name, " ", "-")+".db")
			if _, err := db.db.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			err := db.CreateClient(ctx, test.client, "uuid", "phone@example.test", test.shortID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("CreateClient() error = %v, want %q", err, test.want)
			}
			if clients, listErr := db.ListClients(ctx); listErr != nil || len(clients) != 0 {
				t.Fatalf("failed profile transaction left clients: %+v, %v", clients, listErr)
			}
		})
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

func TestCreateApplyOperationWithNextRevisionReportsMissingSequence(t *testing.T) {
	db, ctx := openTestStore(t, "missing-apply-revision-sequence.db")
	if _, err := db.db.ExecContext(ctx, `DELETE FROM apply_revision_sequence WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err := db.CreateApplyOperationWithNextRevision(ctx, ApplyOperation{
		ID: "missing-sequence", State: "pending", CreatedAt: now, UpdatedAt: now,
	})
	if err == nil || !strings.Contains(err.Error(), "read apply revision sequence") {
		t.Fatalf("apply operation creation error = %v, want missing-sequence error", err)
	}
}

func TestStoreShortIDAndApplyRevisionTransactionsRollbackWriteFailures(t *testing.T) {
	t.Run("reserved short ID insert", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-insert-trigger.db")
		if _, err := db.db.Exec(`CREATE TRIGGER reject_short_id_insert BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'short ID blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "0123456789abcdef", nil }); err == nil || !strings.Contains(err.Error(), "short ID blocked") {
			t.Fatalf("short ID seed error = %v", err)
		}
		if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 0 {
			t.Fatalf("failed reserve left partial IDs: %v, %v", ids, err)
		}
	})

	t.Run("apply operation insert", func(t *testing.T) {
		db, ctx := openTestStore(t, "apply-operation-insert-trigger.db")
		if _, err := db.db.Exec(`CREATE TRIGGER reject_revision_apply BEFORE INSERT ON apply_operations BEGIN SELECT RAISE(ABORT, 'apply insert blocked'); END`); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		operation := ApplyOperation{ID: "blocked", State: "pending", CreatedAt: now, UpdatedAt: now}
		if _, err := db.CreateApplyOperationWithNextRevision(ctx, operation); err == nil || !strings.Contains(err.Error(), "apply insert blocked") {
			t.Fatalf("apply operation error = %v", err)
		}
		if _, err := db.db.Exec(`DROP TRIGGER reject_revision_apply`); err != nil {
			t.Fatal(err)
		}
		operation.ID = "after-rollback"
		revision, err := db.CreateApplyOperationWithNextRevision(ctx, operation)
		if err != nil || revision != 1 {
			t.Fatalf("revision after failed insert = %d, %v; want 1", revision, err)
		}
	})
}

func TestRestoreFromReportsShortIDHistoryInsertFailureAtomically(t *testing.T) {
	ctx := context.Background()
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "restore-destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	initTestAdmin(t, destination, ctx)
	before, err := destination.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source, err := Open(ctx, filepath.Join(t.TempDir(), "restore-source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	initTestAdmin(t, source, ctx)
	if err := source.CreateClient(ctx, domain.Client{ID: "phone", Name: "phone", Enabled: true}, "uuid-phone", "phone@example.test", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.db.ExecContext(ctx, `DELETE FROM reality_short_ids`); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(t.TempDir(), "restore-source.snapshot.db")
	if err := source.BackupTo(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := destination.db.Exec(`CREATE TRIGGER reject_restored_short_id BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'short ID history blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(snapshot); err == nil || !strings.Contains(err.Error(), "restore short ID history") {
		t.Fatalf("restore history insertion error = %v", err)
	}
	current, err := destination.GetSettings(ctx)
	if err != nil || current.PublicHost != before.PublicHost {
		t.Fatalf("short ID history failure partially restored settings: %+v, %v", current, err)
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

func TestRestoreFromDefaultsMissingShadowsocksAndTrojanColumns(t *testing.T) {
	ctx := context.Background()
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
	defer source.Close()
	shadowsocks, err := domain.NewShadowsocksClient("ss-device", "ss-phone")
	if err != nil {
		t.Fatal(err)
	}
	shadowsocks.Email = "ss@xray-easy"
	shadowsocks.ShadowsocksPasswordEnc = "encrypted-ss"
	shadowsocks.ShadowsocksEnabled = true
	if err := source.CreateShadowsocksClient(ctx, shadowsocks); err != nil {
		t.Fatal(err)
	}
	trojan, err := domain.NewProtocolClient("trojan-device", "trojan-phone", domain.ProtocolTrojan, "", "")
	if err != nil {
		t.Fatal(err)
	}
	trojan.Email = "trojan@xray-easy"
	trojan.TrojanPasswordEnc = "encrypted-trojan"
	trojan.TrojanEnabled = true
	if err := source.CreateTrojanClient(ctx, trojan); err != nil {
		t.Fatal(err)
	}

	fullSnapshot := filepath.Join(t.TempDir(), "full.db")
	if err := source.BackupTo(fullSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(fullSnapshot); err != nil {
		t.Fatalf("restore current protocol columns: %v", err)
	}
	for id, password := range map[string]string{"ss-device": "encrypted-ss", "trojan-device": "encrypted-trojan"} {
		client, err := destination.GetClient(ctx, id)
		if err != nil || client.ShadowsocksPasswordEnc+client.TrojanPasswordEnc != password {
			t.Fatalf("restored protocol credentials for %s = %+v, %v", id, client, err)
		}
	}

	for _, column := range []string{
		"shadowsocks_password_enc", "shadowsocks_enabled", "shadowsocks_revoked",
		"trojan_password_enc", "trojan_enabled", "trojan_revoked",
	} {
		if _, err := source.db.Exec(`ALTER TABLE clients DROP COLUMN ` + column); err != nil {
			t.Fatalf("drop legacy optional column %s: %v", column, err)
		}
	}
	legacySnapshot := filepath.Join(t.TempDir(), "legacy.db")
	if err := source.BackupTo(legacySnapshot); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(legacySnapshot); err != nil {
		t.Fatalf("restore legacy protocol columns: %v", err)
	}
	for _, id := range []string{"ss-device", "trojan-device"} {
		client, err := destination.GetClient(ctx, id)
		if err != nil || client.ShadowsocksPasswordEnc != "" || client.ShadowsocksEnabled || client.ShadowsocksRevoked || client.TrojanPasswordEnc != "" || client.TrojanEnabled || client.TrojanRevoked {
			t.Fatalf("legacy protocol defaults for %s = %+v, %v", id, client, err)
		}
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
