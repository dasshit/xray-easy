package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestValidateDatabaseAllowsMissingOptionalTables(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		for _, table := range []string{"reality_short_ids", "hysteria_settings"} {
			if _, err := db.Exec(`DROP TABLE ` + table); err != nil {
				return err
			}
		}
		return nil
	})
	if err := ValidateDatabase(snapshot); err != nil {
		t.Fatalf("ValidateDatabase() rejected an older database without optional tables: %v", err)
	}
}

func TestReadSettingsFromDatabaseDefaultsLogLevelForLegacySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-settings.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE settings (
		id INTEGER PRIMARY KEY, public_host TEXT NOT NULL, public_port INTEGER NOT NULL,
		xray_api_listen TEXT NOT NULL, internal_inbound_port INTEGER NOT NULL,
		reality_target TEXT NOT NULL, reality_sni TEXT NOT NULL,
		reality_private_key_enc TEXT NOT NULL, reality_public_key TEXT NOT NULL,
		client_fingerprint TEXT NOT NULL
	)`)
	if err == nil {
		_, err = db.Exec(`INSERT INTO settings VALUES(1,'vpn.example.test',443,'127.0.0.1:10085',8443,'front.example:443','front.example','encrypted','public','chrome')`)
	}
	closeErr := db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	settings, err := ReadSettingsFromDatabase(path)
	if err != nil || settings.LogLevel != "warning" || settings.PublicHost != "vpn.example.test" {
		t.Fatalf("ReadSettingsFromDatabase() = %+v, %v; want legacy warning default", settings, err)
	}
}

func TestRestoreFromSupportsProtocollessLegacyClients(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		for _, column := range []string{
			"protocol", "hysteria_auth", "vless_enabled", "vless_revoked",
			"hysteria_enabled", "hysteria_revoked", "vmess_enabled", "vmess_revoked",
			"shadowsocks_password_enc", "shadowsocks_enabled", "shadowsocks_revoked",
			"trojan_password_enc", "trojan_enabled", "trojan_revoked", "expires_at",
		} {
			if _, err := db.Exec(`ALTER TABLE clients DROP COLUMN ` + column); err != nil {
				return err
			}
		}
		return nil
	})
	destination := openRestoreDestination(t)
	if err := destination.RestoreFrom(snapshot); err != nil {
		t.Fatalf("RestoreFrom() failed for protocolless legacy clients: %v", err)
	}
	client, err := destination.GetClient(context.Background(), "phone")
	if err != nil || client.Protocol != domain.ProtocolLegacyDual || client.HysteriaAuth != client.UUID || !client.VLESSEnabled || !client.HysteriaEnabled || client.ExpiresAt != nil {
		t.Fatalf("restored protocolless client = %+v, %v", client, err)
	}
}

func TestRestoreFromRollsBackMalformedLegacySettings(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		_, err := db.Exec(`ALTER TABLE settings DROP COLUMN reality_target`)
		return err
	})
	destination := openRestoreDestination(t)
	before, err := destination.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = destination.RestoreFrom(snapshot)
	if err == nil || !strings.Contains(err.Error(), "restore table settings") {
		t.Fatalf("RestoreFrom() error = %v, want malformed-settings error", err)
	}
	after, err := destination.GetSettings(context.Background())
	if err != nil || after != before {
		t.Fatalf("failed restore changed destination settings: %+v, %v", after, err)
	}
}

func TestRestoreSettingsReportsMissingAttachedSource(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	err = restoreSettings(tx)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "restore_source") {
		t.Fatalf("restoreSettings() error = %v, want missing attached source", err)
	}
}

func TestRestoreSettingsDefaultsLogLevelForLegacySnapshot(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		_, err := db.Exec(`ALTER TABLE settings DROP COLUMN log_level`)
		return err
	})
	destination := openRestoreDestination(t)
	if err := destination.RestoreFrom(snapshot); err != nil {
		t.Fatalf("RestoreFrom() failed for legacy settings without log_level: %v", err)
	}
	settings, err := destination.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings.LogLevel != "warning" {
		t.Fatalf("restored legacy log level = %q, want warning", settings.LogLevel)
	}
}

func TestSeedReservedShortIDsRollsBackGenerationAndMarkerErrors(t *testing.T) {
	t.Run("generator", func(t *testing.T) {
		db, ctx := openTestStore(t, "seed-short-id-generator-error.db")
		if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version=3`); err != nil {
			t.Fatal(err)
		}
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "", errors.New("seed entropy unavailable") }); err == nil || !strings.Contains(err.Error(), "seed entropy unavailable") {
			t.Fatalf("SeedReservedShortIDs() error = %v", err)
		}
		if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 0 {
			t.Fatalf("failed seed left IDs: %v, %v", ids, err)
		}
	})

	t.Run("initialization marker", func(t *testing.T) {
		db, ctx := openTestStore(t, "seed-short-id-marker-error.db")
		if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version=3`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`CREATE TRIGGER reject_initial_short_id_marker BEFORE INSERT ON schema_migrations WHEN NEW.version=3 BEGIN SELECT RAISE(ABORT, 'short ID marker blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err == nil || !strings.Contains(err.Error(), "short ID marker blocked") {
			t.Fatalf("SeedReservedShortIDs() error = %v", err)
		}
		if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 0 {
			t.Fatalf("failed marker write left IDs: %v, %v", ids, err)
		}
	})

	t.Run("missing migration table", func(t *testing.T) {
		db, ctx := openTestStore(t, "seed-short-id-missing-migrations.db")
		if _, err := db.db.Exec(`DROP TABLE schema_migrations`); err != nil {
			t.Fatal(err)
		}
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err == nil {
			t.Fatal("SeedReservedShortIDs() succeeded without schema_migrations")
		}
	})
}

func TestApplyRevisionCommitFailureRollsBackSequence(t *testing.T) {
	db, ctx := openTestStore(t, "apply-revision-deferred-commit-error.db")
	if _, err := db.db.Exec(`CREATE TABLE commit_guard(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TABLE commit_guard_child(parent_id INTEGER REFERENCES commit_guard(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER violate_commit_guard AFTER INSERT ON apply_operations BEGIN INSERT INTO commit_guard_child(parent_id) VALUES(999); END`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, err := db.CreateApplyOperationWithNextRevision(ctx, ApplyOperation{ID: "commit-failure", State: "pending", CreatedAt: now, UpdatedAt: now})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Fatalf("CreateApplyOperationWithNextRevision() error = %v, want deferred foreign-key commit error", err)
	}
	if _, err := db.db.Exec(`DROP TRIGGER violate_commit_guard`); err != nil {
		t.Fatal(err)
	}
	revision, err := db.CreateApplyOperationWithNextRevision(ctx, ApplyOperation{ID: "after-rollback", State: "pending", CreatedAt: now, UpdatedAt: now})
	if err != nil || revision != 1 {
		t.Fatalf("revision after failed commit = %d, %v; want 1", revision, err)
	}
}

func TestFirstAdminReportsUninitializedDatabase(t *testing.T) {
	db, ctx := openTestStore(t, "first-admin-empty.db")
	if _, err := db.FirstAdmin(ctx); err == nil || !strings.Contains(err.Error(), "admin not found") {
		t.Fatalf("FirstAdmin() error = %v, want admin not found", err)
	}
}

func TestLegacyProtocolMigrationReportsSchemaAndMarkerFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		prepare   func(*testing.T, *sql.DB)
		wantError string
	}{
		{
			name: "replacement table already exists",
			prepare: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`CREATE TABLE clients_protocol_migration(id TEXT)`); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "create protocol-aware clients table",
		},
		{
			name: "copy violates new uniqueness constraints",
			prepare: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`INSERT INTO clients(id,name,uuid,email,short_id,created_at,updated_at) VALUES('a','A','duplicate','a@example.test','aaaaaaaaaaaaaaaa','now','now'),('b','B','duplicate','b@example.test','bbbbbbbbbbbbbbbb','now','now')`); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "copy existing profiles as legacy dual-protocol profiles",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "legacy.db")
			db, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.db.Exec(`CREATE TABLE clients_legacy(id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT, email TEXT, short_id TEXT, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec(`DROP TABLE clients`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec(`ALTER TABLE clients_legacy RENAME TO clients`); err != nil {
				t.Fatal(err)
			}
			test.prepare(t, db.db)
			if err := db.migrateClientProtocols(ctx); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("migrateClientProtocols() error = %v, want %q", err, test.wantError)
			}
		})
	}

	t.Run("migration marker write", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "legacy-marker.db")
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err := db.db.Exec(`CREATE TRIGGER reject_client_protocol_marker BEFORE INSERT ON schema_migrations WHEN NEW.version=4 BEGIN SELECT RAISE(ABORT, 'protocol marker blocked'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version=4`); err != nil {
			t.Fatal(err)
		}
		if err := db.markClientProtocolMigration(ctx); err == nil || !strings.Contains(err.Error(), "protocol marker blocked") {
			t.Fatalf("markClientProtocolMigration() error = %v", err)
		}
	})
}

func TestProtocolMigrationSnapshotReportsVacuumAndRenameFailures(t *testing.T) {
	t.Run("closed database", func(t *testing.T) {
		db, ctx := openTestStore(t, "closed-protocol-snapshot.db")
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := db.createProtocolMigrationSnapshot(ctx, filepath.Join(t.TempDir(), "snapshot.db")); err == nil {
			t.Fatal("createProtocolMigrationSnapshot() succeeded with a closed database")
		}
	})

	t.Run("rename into existing directory", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-snapshot-rename.db")
		destination := filepath.Join(t.TempDir(), "snapshot-directory")
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, "keep"), []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := db.createProtocolMigrationSnapshot(ctx, destination); err == nil {
			t.Fatal("createProtocolMigrationSnapshot() succeeded when rename destination was a nonempty directory")
		}
	})
}

func TestMigrateRollsBackWhenMigrationMarkersCannotBeInserted(t *testing.T) {
	for _, version := range []int{1, 2, 5, 6} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			db, ctx := openTestStore(t, fmt.Sprintf("migration-marker-%d.db", version))
			if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version=?`, version); err != nil {
				t.Fatal(err)
			}
			statement := fmt.Sprintf(`CREATE TRIGGER reject_migration_%d BEFORE INSERT ON schema_migrations WHEN NEW.version=%d BEGIN SELECT RAISE(ABORT, 'migration marker blocked'); END`, version, version)
			if _, err := db.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			if err := db.migrate(ctx); err == nil || !strings.Contains(err.Error(), "migration marker blocked") {
				t.Fatalf("migrate() error = %v, want marker failure for version %d", err, version)
			}
		})
	}
}

func TestRestoreFromAttachmentFailureForClosedStore(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, nil)
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "closed-restore.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.RestoreFrom(snapshot); err == nil {
		t.Fatal("RestoreFrom() succeeded after database closure")
	}
}

func TestRestoreFromReportsFailureCreatingDefaultHysteriaSettings(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		_, err := db.Exec(`DROP TABLE hysteria_settings`)
		return err
	})
	destination := openRestoreDestination(t)
	if _, err := destination.db.Exec(`CREATE TRIGGER reject_legacy_hysteria_default BEFORE INSERT ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'legacy Hysteria default blocked'); END`); err != nil {
		t.Fatal(err)
	}
	err := destination.RestoreFrom(snapshot)
	if err == nil || !strings.Contains(err.Error(), "restore default Hysteria 2 settings") || !strings.Contains(err.Error(), "legacy Hysteria default blocked") {
		t.Fatalf("RestoreFrom() error = %v, want default Hysteria settings failure", err)
	}
}
