package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func makeRestoreSnapshot(t *testing.T, mutate func(*sql.DB) error) string {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "source.db")
	source, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Initialize(ctx, "admin", "hash", "source.example.test", 443); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if err := source.CreateClient(ctx, domain.Client{ID: "phone", Name: "phone", Enabled: true}, "phone-uuid", "phone@example.test", "0123456789abcdef"); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if mutate != nil {
		if err := mutate(source.db); err != nil {
			_ = source.Close()
			t.Fatal(err)
		}
	}
	snapshot := filepath.Join(t.TempDir(), "source.snapshot.db")
	if err := source.BackupTo(snapshot); err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func openRestoreDestination(t *testing.T) *Store {
	t.Helper()
	destination, err := Open(context.Background(), filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.Initialize(context.Background(), "destination", "hash", "destination.example.test", 443); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	return destination
}

func TestRestoreFromSupportsSnapshotsBeforeOptionalSchemaMigrations(t *testing.T) {
	snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
		for _, table := range []string{"reality_short_ids", "hysteria_settings"} {
			if _, err := db.Exec(`DROP TABLE ` + table); err != nil {
				return err
			}
		}
		if _, err := db.Exec(`ALTER TABLE settings DROP COLUMN log_level`); err != nil {
			return err
		}
		if _, err := db.Exec(`ALTER TABLE clients DROP COLUMN expires_at`); err != nil {
			return err
		}
		return nil
	})
	destination := openRestoreDestination(t)
	if err := destination.RestoreFrom(snapshot); err != nil {
		t.Fatalf("restore legacy snapshot: %v", err)
	}
	settings, err := destination.GetSettings(context.Background())
	if err != nil || settings.LogLevel != "warning" {
		t.Fatalf("legacy settings log level = %q, %v; want warning", settings.LogLevel, err)
	}
	client, err := destination.GetClient(context.Background(), "phone")
	if err != nil || client.ExpiresAt != nil {
		t.Fatalf("legacy client expiry = %v, %v; want nil", client.ExpiresAt, err)
	}
	hysteria, err := destination.GetHysteriaSettings(context.Background())
	if err != nil || hysteria.Enabled || hysteria.TLSMode != domain.HysteriaTLSLegacy {
		t.Fatalf("default Hysteria settings after legacy restore = %+v, %v", hysteria, err)
	}
}

func TestRestoreFromRollsBackWhenCompatibilityMarkerWritesFail(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    int
		want       string
		triggerSQL string
	}{
		{name: "protocol marker", version: 4, want: "restore client protocol migration marker"},
		{name: "VMess marker", version: 5, want: "restore VMess migration marker"},
		{name: "expiry marker", version: 6, want: "restore profile expiry migration marker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := makeRestoreSnapshot(t, func(db *sql.DB) error {
				_, err := db.Exec(`DELETE FROM schema_migrations WHERE version=?`, test.version)
				return err
			})
			destination := openRestoreDestination(t)
			if _, err := destination.db.Exec(fmt.Sprintf(`CREATE TRIGGER reject_migration_marker BEFORE INSERT ON schema_migrations WHEN NEW.version=%d BEGIN SELECT RAISE(ABORT, 'marker blocked'); END`, test.version)); err != nil {
				t.Fatal(err)
			}
			before, err := destination.GetSettings(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = destination.RestoreFrom(snapshot)
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "marker blocked") {
				t.Fatalf("RestoreFrom() error = %v; want %q and trigger error", err, test.want)
			}
			after, err := destination.GetSettings(context.Background())
			if err != nil || after.PublicHost != before.PublicHost {
				t.Fatalf("failed marker restore changed settings: %+v, %v", after, err)
			}
		})
	}
}

func TestRestoreFromReportsMissingSourceConnectionAndHighWaterMarkErrors(t *testing.T) {
	t.Run("closed destination", func(t *testing.T) {
		snapshot := makeRestoreSnapshot(t, nil)
		destination := openRestoreDestination(t)
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
		if err := destination.RestoreFrom(snapshot); err == nil {
			t.Fatal("RestoreFrom succeeded with a closed destination store")
		}
	})

	t.Run("revision high-water update trigger", func(t *testing.T) {
		snapshot := makeRestoreSnapshot(t, nil)
		destination := openRestoreDestination(t)
		if _, err := destination.db.Exec(`CREATE TRIGGER reject_revision_high_water BEFORE UPDATE ON apply_revision_sequence BEGIN SELECT RAISE(ABORT, 'revision update blocked'); END`); err != nil {
			t.Fatal(err)
		}
		err := destination.RestoreFrom(snapshot)
		if err == nil || !strings.Contains(err.Error(), "preserve apply revision high-water mark") || !strings.Contains(err.Error(), "revision update blocked") {
			t.Fatalf("RestoreFrom high-water error = %v", err)
		}
	})
}
