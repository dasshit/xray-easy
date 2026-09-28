package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListAndVerifyReportMalformedBackupArtifacts(t *testing.T) {
	t.Run("malformed metadata in list", func(t *testing.T) {
		manager, _ := newTestManager(t)
		broken := filepath.Join(manager.BackupDir(), "backup-broken")
		if err := os.MkdirAll(broken, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(broken, "metadata.json"), []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.List(); err == nil || !strings.Contains(err.Error(), "metadata") {
			t.Fatalf("List accepted malformed metadata: %v", err)
		}
	})

	t.Run("valid manifest with invalid SQLite", func(t *testing.T) {
		manager, _ := newTestManager(t)
		name := "backup-invalid-database"
		root := filepath.Join(manager.BackupDir(), name)
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "state.db"), []byte("not sqlite"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config.redacted.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		meta, err := json.Marshal(metadata{FormatVersion: formatVersion, CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "metadata.json"), meta, 0o600); err != nil {
			t.Fatal(err)
		}
		files, err := hashFiles(root, []string{"state.db", "config.redacted.json", "metadata.json"})
		if err != nil {
			t.Fatal(err)
		}
		unsigned := manifest{FormatVersion: formatVersion, Files: files}
		unsignedBytes, err := json.Marshal(unsigned)
		if err != nil {
			t.Fatal(err)
		}
		signed := unsigned
		signed.HMACSHA256 = hmacSHA256(manager.MasterKey, unsignedBytes)
		manifestBytes, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), manifestBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Verify(name); err == nil || !strings.Contains(err.Error(), "backup database validation") {
			t.Fatalf("Verify accepted invalid SQLite: %v", err)
		}
	})
}

func TestBackupFilesystemHelpersReportMissingInputs(t *testing.T) {
	manager, _ := newTestManager(t)
	if err := os.MkdirAll(manager.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFiles(t.TempDir(), []string{"missing.file"}); err == nil {
		t.Fatal("hashFiles accepted missing file")
	}
	if err := writeFile(filepath.Join(t.TempDir(), "missing", "artifact"), []byte("x"), 0o600); err == nil {
		t.Fatal("writeFile accepted missing directory")
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDir accepted missing directory")
	}
	if err := os.Mkdir(filepath.Join(manager.ConfigDir, "active.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.writeRedactedConfig(filepath.Join(t.TempDir(), "redacted.json")); err == nil {
		t.Fatal("writeRedactedConfig accepted active config directory")
	}
	if err := os.WriteFile(manager.BackupDir(), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.List(); err == nil {
		t.Fatal("List accepted backup path that is a regular file")
	}
}

func TestCreateCleansTemporaryDirectoryWhenSQLiteSnapshotFails(t *testing.T) {
	manager, db := newTestManager(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create("closed-database"); err == nil || !strings.Contains(err.Error(), "backup SQLite") {
		t.Fatalf("Create with closed database = %v", err)
	}
	entries, err := os.ReadDir(manager.BackupDir())
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary backup was not cleaned after snapshot failure: entries=%v err=%v", entries, err)
	}

	blocked := *manager
	if err := os.Remove(manager.BackupDir()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.DataDir, "backups"), []byte("file instead of directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Create("unwritable"); err == nil {
		t.Fatal("Create accepted a regular file at the backup directory path")
	}
}
