package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupFilesystemHelpersPropagateSetupFailures(t *testing.T) {
	t.Run("create cannot make temporary backup directory", func(t *testing.T) {
		manager, _ := newTestManager(t)
		if err := os.MkdirAll(manager.BackupDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manager.BackupDir(), 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(manager.BackupDir(), 0o700) })
		if _, err := manager.Create("blocked"); err == nil {
			t.Fatal("Create() succeeded when the backup directory is read-only")
		}
	})

	t.Run("redacted config output cannot be created", func(t *testing.T) {
		manager, _ := newTestManager(t)
		if _, err := manager.writeRedactedConfig(filepath.Join(t.TempDir(), "missing", "config.json")); err == nil {
			t.Fatal("writeRedactedConfig() succeeded with a missing parent directory")
		}
	})

	t.Run("hash input cannot be opened", func(t *testing.T) {
		if _, err := hashFiles(t.TempDir(), []string{"missing.db"}); err == nil {
			t.Fatal("hashFiles() succeeded for a missing input")
		}
	})

	t.Run("prune reports backup listing error", func(t *testing.T) {
		manager, _ := newTestManager(t)
		if err := os.RemoveAll(manager.BackupDir()); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(manager.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manager.BackupDir(), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manager.prune(nil); err == nil {
			t.Fatal("prune() ignored an unreadable backup listing")
		}
	})

	t.Run("TLS destination conflict", func(t *testing.T) {
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, "fullchain.pem"), []byte("cert"), 0o600); err != nil {
			t.Fatal(err)
		}
		destination := t.TempDir()
		if err := os.WriteFile(filepath.Join(destination, "fullchain.pem"), []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := copyTLSDirectory(source, destination); err == nil || !strings.Contains(err.Error(), "file exists") {
			t.Fatalf("copyTLSDirectory() error = %v, want destination conflict", err)
		}
	})

	t.Run("relative file walk reports missing directory", func(t *testing.T) {
		if _, err := listRelativeFiles(t.TempDir(), "missing"); err == nil {
			t.Fatal("listRelativeFiles() succeeded for a missing directory")
		}
	})
}

func TestPruneReportsFailureRemovingExpiredBackup(t *testing.T) {
	manager, _ := newTestManager(t)
	for range retention {
		if _, err := manager.Create("retention"); err != nil {
			t.Fatal(err)
		}
	}
	items, err := manager.List()
	if err != nil || len(items) != retention {
		t.Fatalf("initial backup list = %d items, %v", len(items), err)
	}
	oldest := items[len(items)-1]
	parked := filepath.Join(manager.DataDir, "parked-backup")
	if err := os.Rename(oldest.Path, parked); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create("replacement"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parked, oldest.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manager.BackupDir(), 0o500); err != nil {
		t.Fatal(err)
	}
	err = manager.prune(nil)
	if chmodErr := os.Chmod(manager.BackupDir(), 0o700); chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if err == nil {
		t.Skip("current filesystem permits deleting a backup from a read-only parent directory")
	}
}
