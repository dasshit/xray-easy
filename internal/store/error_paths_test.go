package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
