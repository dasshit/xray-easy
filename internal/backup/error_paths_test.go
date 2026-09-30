package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type failingBackupTempFile struct {
	*os.File
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
}

func (f *failingBackupTempFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *failingBackupTempFile) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.Write(data)
}

func (f *failingBackupTempFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *failingBackupTempFile) Close() error {
	actualErr := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return actualErr
}

func TestWriteFilePropagatesAtomicPersistenceFailuresAndCleansTemporaryFiles(t *testing.T) {
	for _, failure := range []string{"chmod", "write", "sync", "close", "rename"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "artifact")
			wantErr := errors.New("injected " + failure + " failure")
			file := &failingBackupTempFile{}
			err := writeFileWith(path, []byte("backup contents"), 0o600,
				func(dir, pattern string) (backupTempFile, error) {
					created, err := os.CreateTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					file.File = created
					switch failure {
					case "chmod":
						file.chmodErr = wantErr
					case "write":
						file.writeErr = wantErr
					case "sync":
						file.syncErr = wantErr
					case "close":
						file.closeErr = wantErr
					}
					return file, nil
				}, os.Remove,
				func(source, destination string) error {
					if failure == "rename" {
						return wantErr
					}
					return os.Rename(source, destination)
				})
			if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
				t.Fatalf("writeFileWith() error = %v, want %q", err, wantErr)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed write left an artifact behind: entries=%v err=%v", entries, err)
			}
		})
	}
}

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

func TestListRelativeFilesRejectsSymlinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "tls")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "regular.pem")
	if err := os.WriteFile(regular, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, filepath.Join(directory, "linked.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := listRelativeFiles(root, "tls"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("listRelativeFiles accepted symlink: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, "linked.pem")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(directory, "pipe"), 0o600); err != nil {
		t.Skipf("cannot create FIFO on this filesystem: %v", err)
	}
	if _, err := listRelativeFiles(root, "tls"); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("listRelativeFiles accepted FIFO: %v", err)
	}
}

func TestCreateRejectsInvalidAmneziaWGSnapshots(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "empty", data: []byte{}, want: "empty snapshot"},
		{name: "too large", data: make([]byte, maxAWGSnapshot+1), want: "size limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, _ := newTestManager(t)
			manager.AWG = &awgBackupStub{current: test.data}
			if _, err := manager.Create(test.name); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Create() with %s AWG snapshot = %v", test.name, err)
			}
		})
	}
}

func TestCopyTLSDirectoryRejectsUnsafeEntriesAndPreservesModes(t *testing.T) {
	root := t.TempDir()
	if copied, err := copyTLSDirectory(filepath.Join(root, "missing"), filepath.Join(root, "missing-copy")); err != nil || copied {
		t.Fatalf("copy missing TLS directory = %v, %v", copied, err)
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := copyTLSDirectory(regular, filepath.Join(root, "file-copy")); err == nil {
		t.Fatal("TLS copier accepted a regular file as the source directory")
	}

	source := filepath.Join(root, "tls")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, filepath.Join(source, "certificate-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := copyTLSDirectory(source, filepath.Join(root, "symlink-copy")); err == nil {
		t.Fatal("TLS copier accepted a symlink")
	}
	if err := os.Remove(filepath.Join(source, "certificate-link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(source, "pipe"), 0o600); err != nil {
		t.Skipf("cannot create FIFO on this filesystem: %v", err)
	}
	if _, err := copyTLSDirectory(source, filepath.Join(root, "fifo-copy")); err == nil {
		t.Fatal("TLS copier accepted a non-regular entry")
	}
	if err := os.Remove(filepath.Join(source, "pipe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "versions"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"fullchain.pem": "certificate", "privkey.pem": "private key"} {
		if err := os.WriteFile(filepath.Join(source, "versions", name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(root, "copy")
	copied, err := copyTLSDirectory(source, destination)
	if err != nil || !copied {
		t.Fatalf("copy valid TLS tree = %v, %v", copied, err)
	}
	privateInfo, err := os.Stat(filepath.Join(destination, "versions", "privkey.pem"))
	if err != nil || privateInfo.Mode().Perm() != 0o400 {
		t.Fatalf("copied private key permissions = %v, %v", privateInfo, err)
	}
	publicInfo, err := os.Stat(filepath.Join(destination, "versions", "fullchain.pem"))
	if err != nil || publicInfo.Mode().Perm() != 0o444 {
		t.Fatalf("copied certificate permissions = %v, %v", publicInfo, err)
	}
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

func TestRestoreStateRejectsUnavailableDependenciesAndUnsafeStagePaths(t *testing.T) {
	t.Run("missing store", func(t *testing.T) {
		manager, _ := newTestManager(t)
		manager.Store = nil
		if err := manager.RestoreStateContext(t.Context(), Info{}); err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Fatalf("restore without Store = %v", err)
		}
	})

	t.Run("AWG backup required when service enabled", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("without-awg")
		if err != nil {
			t.Fatal(err)
		}
		manager.AWG = &awgBackupStub{current: []byte("live")}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "backup does not contain AmneziaWG state") {
			t.Fatalf("restore without expected AWG snapshot = %v", err)
		}
	})

	t.Run("live AWG snapshot error", func(t *testing.T) {
		manager, _ := newTestManager(t)
		awg := &awgBackupStub{current: []byte("before")}
		manager.AWG = awg
		info, err := manager.Create("snapshot-error")
		if err != nil {
			t.Fatal(err)
		}
		awg.exportErr = errors.New("service unavailable")
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "snapshot current AmneziaWG") {
			t.Fatalf("restore with AWG snapshot failure = %v", err)
		}
		if len(awg.restored) != 0 {
			t.Fatalf("AWG restore began before the live state could be snapshotted: %+v", awg.restored)
		}
	})

	t.Run("data directory replaced by a file", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("blocked-stage")
		if err != nil {
			t.Fatal(err)
		}
		movedData := manager.DataDir + ".saved"
		if err := os.Rename(manager.DataDir, movedData); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manager.DataDir, []byte("blocked"), 0o600); err != nil {
			t.Fatal(err)
		}
		info.Path = filepath.Join(movedData, "backups", info.Name)
		info.StatePath = filepath.Join(info.Path, "state.db")
		if err := manager.RestoreState(info); err == nil {
			t.Fatal("restore created a stage beside a regular-file data directory")
		}
	})
}

func TestRestoreStateReportsTLSStagingAndSQLiteSnapshotFailures(t *testing.T) {
	t.Run("unsafe TLS backup entry", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("unsafe-tls")
		if err != nil {
			t.Fatal(err)
		}
		tlsRoot := filepath.Join(info.Path, "hysteria-tls")
		if err := os.Mkdir(tlsRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(tlsRoot, "privkey.pem")); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "prepare Hysteria 2 TLS restore") {
			t.Fatalf("restore accepted an unsafe TLS entry: %v", err)
		}
	})

	t.Run("closed database", func(t *testing.T) {
		manager, db := newTestManager(t)
		info, err := manager.Create("closed-database")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "snapshot current SQLite state") {
			t.Fatalf("restore with closed database = %v", err)
		}
	})
}
