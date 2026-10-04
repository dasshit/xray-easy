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

	cryptorand "crypto/rand"
)

func TestOpenPropagatesCanceledMigrationAndLegacyMigrationCompletes(t *testing.T) {
	t.Run("canceled schema migration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if db, err := Open(ctx, filepath.Join(t.TempDir(), "canceled.db")); err == nil {
			_ = db.Close()
			t.Fatal("Open succeeded with a canceled migration context")
		}
	})

	t.Run("successful legacy client migration", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "legacy.db")
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
		for _, statement := range []string{
			`DROP TABLE traffic_snapshots`,
			`DROP TABLE clients`,
			`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, short_id TEXT NOT NULL UNIQUE, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			`CREATE TABLE traffic_snapshots (client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE, raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0, total_upload INTEGER NOT NULL DEFAULT 0, total_download INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL DEFAULT '', last_polled_at TEXT NOT NULL)`,
			`INSERT INTO clients VALUES('legacy', 'Legacy phone', 'legacy-uuid', 'legacy@example.test', 'legacy-short', 'safari', 1, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
			`INSERT INTO traffic_snapshots(client_id, last_polled_at) VALUES('legacy', '2026-01-01T00:00:00Z')`,
			`DELETE FROM schema_migrations WHERE version=4`,
		} {
			if _, err := legacy.Exec(statement); err != nil {
				_ = legacy.Close()
				t.Fatalf("prepare legacy fixture with %q: %v", statement, err)
			}
		}
		if err := legacy.Close(); err != nil {
			t.Fatal(err)
		}
		migrated, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("migrate legacy client schema: %v", err)
		}
		defer migrated.Close()
		client, err := migrated.GetClient(ctx, "legacy")
		if err != nil || client.Protocol != "legacy_dual" || client.HysteriaAuth != client.UUID {
			t.Fatalf("migrated profile = %+v, %v", client, err)
		}
		if _, err := filepath.Glob(path + ".pre-protocol-profiles-*.db"); err != nil {
			t.Fatal(err)
		} else if snapshots, _ := filepath.Glob(path + ".pre-protocol-profiles-*.db"); len(snapshots) != 1 {
			t.Fatalf("pre-migration snapshots = %v; want exactly one", snapshots)
		}
	})
}

func TestInitializeRollsBackAdministratorWhenSettingsInsertFails(t *testing.T) {
	db, ctx := openTestStore(t, "initialize-settings-trigger.db")
	if _, err := db.db.Exec(`CREATE TRIGGER reject_initial_settings BEFORE INSERT ON settings BEGIN SELECT RAISE(ABORT, 'settings insert blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Initialize(ctx, "admin", "hash", "vpn.example.test", 443); err == nil || !strings.Contains(err.Error(), "settings insert blocked") {
		t.Fatalf("Initialize() error = %v", err)
	}
	status, err := db.SetupStatus(ctx)
	if err != nil || status.Initialized {
		t.Fatalf("failed initialize left an administrator: %+v, %v", status, err)
	}
}

func TestLegacyProtocolMigrationRequiresAnAvailableSnapshotLocation(t *testing.T) {
	for _, test := range []struct {
		name    string
		setPath func(*Store, string)
		want    string
	}{
		{name: "database path is empty", setPath: func(db *Store, _ string) { db.dbPath = "" }, want: "database path is required"},
		{name: "snapshot parent is missing", setPath: func(db *Store, root string) { db.dbPath = filepath.Join(root, "missing", "state.db") }, want: "create pre-migration database snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, ctx := openTestStore(t, "legacy-snapshot.db")
			if _, err := db.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{
				`DROP TABLE traffic_snapshots`,
				`DROP TABLE clients`,
				`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, short_id TEXT NOT NULL UNIQUE, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			} {
				if _, err := db.db.Exec(statement); err != nil {
					t.Fatalf("prepare legacy schema with %q: %v", statement, err)
				}
			}
			legacyPath := filepath.Join(t.TempDir(), "state.db")
			test.setPath(db, legacyPath)
			if err := db.migrateClientProtocols(ctx); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("migrateClientProtocols() error = %v, want %q", err, test.want)
			}
			var protocolColumnCount int
			if err := db.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name='protocol'`).Scan(&protocolColumnCount); err != nil {
				t.Fatal(err)
			}
			if protocolColumnCount != 0 {
				t.Fatal("failed migration changed the legacy clients table")
			}
		})
	}
}

func TestLegacyProtocolMigrationCompletesAndSkipsCurrentSchemas(t *testing.T) {
	t.Run("rebuilds legacy clients and snapshots the original database", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "legacy-success.db")
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
		if _, err := db.db.Exec(`INSERT INTO clients(id,name,uuid,email,short_id,created_at,updated_at) VALUES('legacy-id','legacy phone','legacy-uuid','legacy@example.test','1234567890abcdef','created','updated')`); err != nil {
			t.Fatal(err)
		}
		if err := db.migrateClientProtocols(ctx); err != nil {
			t.Fatalf("migrateClientProtocols() failed: %v", err)
		}
		var protocol, hysteriaAuth, uuid string
		var vlessEnabled, hysteriaEnabled bool
		if err := db.db.QueryRow(`SELECT protocol, hysteria_auth, uuid, vless_enabled, hysteria_enabled FROM clients WHERE id='legacy-id'`).Scan(&protocol, &hysteriaAuth, &uuid, &vlessEnabled, &hysteriaEnabled); err != nil {
			t.Fatal(err)
		}
		if protocol != string(domain.ProtocolLegacyDual) || hysteriaAuth != uuid || !vlessEnabled || !hysteriaEnabled {
			t.Fatalf("migrated legacy profile = protocol %q, hysteria auth %q, uuid %q, vless %t, hysteria %t", protocol, hysteriaAuth, uuid, vlessEnabled, hysteriaEnabled)
		}
		if err := db.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version=4`).Scan(new(int)); err != nil {
			t.Fatalf("protocol migration marker was not readable: %v", err)
		}
		snapshots, err := filepath.Glob(path + ".pre-protocol-profiles-*.db")
		if err != nil || len(snapshots) != 1 {
			t.Fatalf("legacy migration snapshot files = %v, %v", snapshots, err)
		}
	})

	t.Run("marks an already migrated schema", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-already-migrated.db")
		if err := db.migrateClientProtocols(ctx); err != nil {
			t.Fatalf("migrateClientProtocols() on current schema: %v", err)
		}
	})

	t.Run("reports database query error", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-query-error.db")
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := db.migrateClientProtocols(ctx); err == nil {
			t.Fatal("migrateClientProtocols() succeeded with a closed database")
		}
	})

	t.Run("rejects an orphaned foreign key after migration", func(t *testing.T) {
		ctx := context.Background()
		path := filepath.Join(t.TempDir(), "legacy-orphan.db")
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		db.db.SetMaxOpenConns(1)
		if _, err := db.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`INSERT INTO traffic_snapshots(client_id,last_polled_at) VALUES('missing-client','now')`); err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			`CREATE TABLE clients_legacy(id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT, email TEXT, short_id TEXT, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
			`DROP TABLE clients`,
			`ALTER TABLE clients_legacy RENAME TO clients`,
		} {
			if _, err := db.db.Exec(statement); err != nil {
				t.Fatalf("prepare legacy schema with %q: %v", statement, err)
			}
		}
		if err := db.migrateClientProtocols(ctx); err == nil || !strings.Contains(err.Error(), "foreign key check failed") {
			t.Fatalf("migrateClientProtocols() error = %v, want foreign-key check failure", err)
		}
	})
}

func TestLegacyProtocolMigrationRollsBackInjectedDatabaseFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		setup     []string
		legacyDDL string
		want      string
	}{
		{
			name:  "replacement table already exists",
			setup: []string{`CREATE TABLE clients_protocol_migration(id TEXT)`},
			want:  "create protocol-aware clients table",
		},
		{
			name: "legacy row cannot be copied",
			legacyDDL: `CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
				INSERT INTO clients VALUES('legacy-id','legacy','created','updated')`,
			want: "copy existing profiles",
		},
		{
			name:  "migration marker insert fails",
			setup: []string{`CREATE TRIGGER reject_protocol_migration_marker BEFORE INSERT ON schema_migrations WHEN NEW.version=4 BEGIN SELECT RAISE(ABORT, 'migration marker blocked'); END`},
			want:  "migration marker blocked",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, ctx := openTestStore(t, "legacy-failure.db")
			db.db.SetMaxOpenConns(1)
			if _, err := db.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
				t.Fatal(err)
			}
			for _, statement := range append(test.setup, `DROP TABLE traffic_snapshots`, `DROP TABLE clients`) {
				if _, err := db.db.Exec(statement); err != nil {
					t.Fatalf("prepare migration failure fixture with %q: %v", statement, err)
				}
			}
			legacyDDL := test.legacyDDL
			if legacyDDL == "" {
				legacyDDL = `CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, short_id TEXT NOT NULL UNIQUE, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`
			}
			if _, err := db.db.Exec(legacyDDL); err != nil {
				t.Fatalf("create legacy clients table: %v", err)
			}
			db.dbPath = filepath.Join(t.TempDir(), "state.db")
			if err := db.migrateClientProtocols(ctx); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("migrateClientProtocols() error = %v, want %q", err, test.want)
			}
			var hasProtocol int
			if err := db.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name='protocol'`).Scan(&hasProtocol); err != nil {
				t.Fatal(err)
			}
			if hasProtocol != 0 {
				t.Fatal("failed protocol migration did not roll back the legacy clients table")
			}
		})
	}
}

func TestCreateProtocolMigrationSnapshotCleansTemporaryFilesAfterFailures(t *testing.T) {
	db, _ := openTestStore(t, "snapshot-failure.db")
	t.Run("canceled vacuum", func(t *testing.T) {
		root := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := db.createProtocolMigrationSnapshot(ctx, filepath.Join(root, "snapshot.db")); err == nil {
			t.Fatal("snapshot succeeded with a canceled context")
		}
		entries, err := filepath.Glob(filepath.Join(root, ".protocol-migration-*"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed snapshot left temporary directories: %v, %v", entries, err)
		}
	})
	t.Run("rename target is a directory", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "snapshot.db")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := db.createProtocolMigrationSnapshot(context.Background(), target); err == nil {
			t.Fatal("snapshot replaced a directory target")
		}
		entries, err := filepath.Glob(filepath.Join(root, ".protocol-migration-*"))
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed snapshot rename left temporary directories: %v, %v", entries, err)
		}
	})
}

func TestStoreReturnsInjectedRandomIDFailuresWithoutPartialWrites(t *testing.T) {
	db, ctx := openTestStore(t, "random-id-transactions.db")
	admin := initTestAdmin(t, db, ctx)
	previous := cryptorand.Reader
	cryptorand.Reader = failingCryptoReader{}
	t.Cleanup(func() { cryptorand.Reader = previous })

	if err := db.SetTOTP(ctx, admin.ID, "encrypted", []string{"hash"}); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("SetTOTP entropy error = %v", err)
	}
	if token, err := db.CreateSession(ctx, admin.ID, time.Hour); err == nil || token != "" || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("CreateSession entropy error = token %q, err %v", token, err)
	}
	if err := db.ReplaceRecoveryCodes(ctx, admin.ID, []string{"hash"}); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("ReplaceRecoveryCodes entropy error = %v", err)
	}
	if err := db.AddAudit(ctx, admin.ID, "test", "admin", admin.ID, "safe"); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("AddAudit entropy error = %v", err)
	}
	if count, err := db.RecoveryCodeCount(ctx, admin.ID); err != nil || count != 0 {
		t.Fatalf("random ID failures wrote recovery rows: %d, %v", count, err)
	}
}

type failingCryptoReader struct{}

func (failingCryptoReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestGetApplyOperationRejectsMalformedPersistedTimestamps(t *testing.T) {
	db, ctx := openTestStore(t, "malformed-apply-times.db")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := db.CreateApplyOperation(ctx, ApplyOperation{ID: "created-invalid", Revision: 1, State: "pending", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		column string
		value  string
		want   string
	}{
		{column: "created_at", value: "invalid", want: "creation time"},
		{column: "updated_at", value: "invalid", want: "update time"},
	} {
		t.Run(test.column, func(t *testing.T) {
			if _, err := db.db.Exec(`UPDATE apply_operations SET created_at=?, updated_at=? WHERE id='created-invalid'`, now, now); err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec(fmt.Sprintf(`UPDATE apply_operations SET %s=? WHERE id='created-invalid'`, test.column), test.value); err != nil {
				t.Fatal(err)
			}
			if _, err := db.GetApplyOperation(ctx, "created-invalid"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("GetApplyOperation() error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := db.db.Exec(`UPDATE apply_operations SET created_at=?, updated_at=? WHERE id='created-invalid'`, now, now); err != nil {
		t.Fatal(err)
	}
}
