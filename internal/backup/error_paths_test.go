package backup

import (
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestCreateRejectsMalformedConfigAndUnsafeTLSDirectory(t *testing.T) {
	t.Run("malformed active config", func(t *testing.T) {
		manager, _ := newTestManager(t)
		if err := os.WriteFile(filepath.Join(manager.ConfigDir, "active.json"), []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Create("malformed-config"); err == nil || !strings.Contains(err.Error(), "parse active config") {
			t.Fatalf("Create accepted malformed active config: %v", err)
		}
		entries, err := os.ReadDir(manager.BackupDir())
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed config backup left artifacts: %v, %v", entries, err)
		}
	})

	t.Run("symlink in TLS directory", func(t *testing.T) {
		manager, _ := newTestManager(t)
		tlsRoot := filepath.Join(manager.DataDir, "hysteria-tls")
		if err := os.MkdirAll(tlsRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "missing.pem"), filepath.Join(tlsRoot, "privkey.pem")); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Create("unsafe-tls"); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("Create accepted symlinked TLS data: %v", err)
		}
		entries, err := os.ReadDir(manager.BackupDir())
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed TLS backup left artifacts: %v, %v", entries, err)
		}
	})

	t.Run("active config cannot be read", func(t *testing.T) {
		manager, _ := newTestManager(t)
		if err := os.Mkdir(filepath.Join(manager.ConfigDir, "active.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Create("unreadable-config"); err == nil || !strings.Contains(err.Error(), "read active config") {
			t.Fatalf("Create accepted a directory in place of active.json: %v", err)
		}
	})
}

func TestCreateAndRestoreReportClosedSQLiteStoreFailures(t *testing.T) {
	t.Run("create backup", func(t *testing.T) {
		manager, db := newTestManager(t)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Create("closed-store"); err == nil || !strings.Contains(err.Error(), "backup SQLite") {
			t.Fatalf("Create with a closed store error = %v", err)
		}
		entries, err := os.ReadDir(manager.BackupDir())
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed SQLite backup left artifacts: %v, %v", entries, err)
		}
	})

	t.Run("restore snapshot current state", func(t *testing.T) {
		manager, db := newTestManager(t)
		info, err := manager.Create("closed-store")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "snapshot current SQLite state") {
			t.Fatalf("RestoreState with a closed store error = %v", err)
		}
	})
}

type failedRandomReader struct{ err error }

func (r failedRandomReader) Read([]byte) (int, error) { return 0, r.err }

type backupReadCloser struct {
	io.Reader
	closeErr error
}

func (r backupReadCloser) Close() error { return r.closeErr }

type backupWriteCloser struct {
	*strings.Builder
	writeErr error
	closeErr error
}

func (w backupWriteCloser) Write(data []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.Builder.Write(data)
}

func (w backupWriteCloser) Close() error { return w.closeErr }

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

func TestRandomSuffixPropagatesEntropyFailure(t *testing.T) {
	previous := cryptorand.Reader
	cryptorand.Reader = failedRandomReader{err: errors.New("entropy unavailable")}
	t.Cleanup(func() { cryptorand.Reader = previous })

	if _, err := randomSuffix(); err == nil || !strings.Contains(err.Error(), "entropy unavailable") {
		t.Fatalf("randomSuffix error = %v, want entropy failure", err)
	}
}

func TestCreatePropagatesRandomSuffixEntropyFailure(t *testing.T) {
	manager, _ := newTestManager(t)
	previous := cryptorand.Reader
	cryptorand.Reader = failedRandomReader{err: errors.New("backup entropy unavailable")}
	t.Cleanup(func() { cryptorand.Reader = previous })
	if _, err := manager.Create("entropy-failure"); err == nil || !strings.Contains(err.Error(), "backup entropy unavailable") {
		t.Fatalf("Create() error = %v, want entropy failure", err)
	}
	if entries, err := os.ReadDir(manager.BackupDir()); err != nil || len(entries) != 0 {
		t.Fatalf("failed random suffix left backup artifacts: %v, %v", entries, err)
	}
}

func TestRestoreStateReportsSymlinkLoopWhileInspectingAWGBackup(t *testing.T) {
	manager, _ := newTestManager(t)
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	err := manager.RestoreState(Info{Path: loop})
	if err == nil || !strings.Contains(err.Error(), "inspect AmneziaWG backup") {
		t.Fatalf("RestoreState() error = %v, want AWG backup inspection error", err)
	}
}

func TestRestoreStateReportsUnreadableAWGBackupAndInvalidTLSRoot(t *testing.T) {
	t.Run("AWG archive cannot be read", func(t *testing.T) {
		manager, _ := newTestManager(t)
		manager.AWG = &awgBackupStub{current: []byte("snapshot")}
		info, err := manager.Create("unreadable-awg")
		if err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(info.Path, "amneziawg.tar.gz")
		if err := os.Chmod(archive, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(archive, 0o600) })
		if _, err := os.ReadFile(archive); err == nil {
			t.Skip("current user can read a file with mode 000")
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "read AmneziaWG backup") {
			t.Fatalf("RestoreState() with unreadable AWG archive = %v", err)
		}
	})

	t.Run("TLS backup root is not a directory", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("invalid-tls-root")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(info.Path, "hysteria-tls"), []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "prepare Hysteria 2 TLS restore") {
			t.Fatalf("RestoreState() with invalid TLS root = %v", err)
		}
	})
}

func TestCopyAndCloseTLSFileReturnsCopyAndCloseErrorsInOrder(t *testing.T) {
	for _, test := range []struct {
		name      string
		readerErr error
		inputErr  error
		writeErr  error
		outputErr error
		wantErr   error
	}{
		{name: "success"},
		{name: "copy failure takes precedence", readerErr: errors.New("read failed"), inputErr: errors.New("input close failed"), outputErr: errors.New("output close failed"), wantErr: errors.New("read failed")},
		{name: "input close failure", inputErr: errors.New("input close failed"), outputErr: errors.New("output close failed"), wantErr: errors.New("input close failed")},
		{name: "output close failure", outputErr: errors.New("output close failed"), wantErr: errors.New("output close failed")},
		{name: "write failure", writeErr: errors.New("write failed"), wantErr: errors.New("write failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := backupReadCloser{Reader: strings.NewReader("certificate"), closeErr: test.inputErr}
			if test.readerErr != nil {
				input.Reader = failedRandomReader{err: test.readerErr}
			}
			output := backupWriteCloser{Builder: &strings.Builder{}, writeErr: test.writeErr, closeErr: test.outputErr}
			err := copyAndCloseTLSFile(input, output)
			if (err == nil) != (test.wantErr == nil) || err != nil && err.Error() != test.wantErr.Error() {
				t.Fatalf("copyAndCloseTLSFile() error = %v, want %v", err, test.wantErr)
			}
			if test.name == "success" && output.String() != "certificate" {
				t.Fatalf("copied TLS file = %q", output.String())
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

	t.Run("AWG metadata disagrees with archive", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("unexpected-awg")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(info.Path, "amneziawg.tar.gz"), []byte("unexpected"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Verify(info.Name); err == nil || !strings.Contains(err.Error(), "AmneziaWG metadata") {
			t.Fatalf("Verify() accepted mismatched AWG metadata: %v", err)
		}
	})
}

func TestPruneReturnsBackupListingErrors(t *testing.T) {
	manager, _ := newTestManager(t)
	broken := filepath.Join(manager.BackupDir(), "backup-broken")
	if err := os.MkdirAll(broken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "metadata.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.prune(nil); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("prune() ignored invalid backup metadata: %v", err)
	}
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
	blockedDestination := filepath.Join(root, "blocked-copy")
	if err := os.WriteFile(blockedDestination, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := copyTLSDirectory(source, blockedDestination); err == nil {
		t.Fatal("TLS copier accepted a file as its destination directory")
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
	if _, err := copyTLSDirectory(source, destination); err == nil {
		t.Fatal("TLS copier overwrote files in an existing destination tree")
	}
}

func TestCopyTLSDirectoryReportsPermissionFailures(t *testing.T) {
	t.Run("source lookup denied", func(t *testing.T) {
		root := t.TempDir()
		parent := filepath.Join(root, "private")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(parent, "tls")
		if err := os.Mkdir(source, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		if _, err := os.Stat(source); err == nil {
			t.Skip("current user can access a directory with mode 000")
		}
		if _, err := copyTLSDirectory(source, filepath.Join(root, "copy")); err == nil {
			t.Fatal("copyTLSDirectory ignored a source lookup permission error")
		}
	})

	t.Run("source file open denied", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "tls")
		if err := os.Mkdir(source, 0o700); err != nil {
			t.Fatal(err)
		}
		privateKey := filepath.Join(source, "privkey.pem")
		if err := os.WriteFile(privateKey, []byte("private key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(privateKey, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(privateKey, 0o600) })
		file, err := os.Open(privateKey)
		if err == nil {
			_ = file.Close()
			t.Skip("current user can open a file with mode 000")
		}
		if _, err := copyTLSDirectory(source, filepath.Join(root, "copy")); err == nil {
			t.Fatal("copyTLSDirectory ignored a source file open error")
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
	directoryRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(directoryRoot, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := hashFiles(directoryRoot, []string{"directory"}); err == nil {
		t.Fatal("hashFiles accepted a directory as a regular file")
	}
	if _, err := listRelativeFiles(t.TempDir(), "missing-tls"); err == nil {
		t.Fatal("listRelativeFiles accepted a missing TLS directory")
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

func TestRestoreStateRejectsAWGBackupWhenServiceIsDisabled(t *testing.T) {
	manager, _ := newTestManager(t)
	manager.AWG = &awgBackupStub{current: []byte("awg-state")}
	info, err := manager.Create("awg-enabled")
	if err != nil {
		t.Fatal(err)
	}
	manager.AWG = nil
	if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "enable the AmneziaWG Compose profile") {
		t.Fatalf("RestoreState() with AWG state and no AWG adapter = %v", err)
	}
}

func TestRestoreDisablesHysteriaTransactionallyWhenTLSMaterialIsAbsent(t *testing.T) {
	manager, db := newTestManager(t)
	settings := domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSCustom, CertificateID: "0123456789abcdef0123456789abcdef", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.InitializeHysteriaSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create("hysteria-without-tls")
	if err != nil {
		t.Fatal(err)
	}
	current, err := db.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	current.PublicHost = "live.example.test"
	if err := db.UpdateSettings(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	triggerDB, err := sql.Open("sqlite", "file:"+filepath.Join(filepath.Dir(manager.DataDir), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer triggerDB.Close()
	if _, err := triggerDB.Exec(`CREATE TRIGGER reject_restored_hysteria_disable BEFORE UPDATE ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'disable rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "disable Hysteria 2 after restore") {
		t.Fatalf("RestoreState() error = %v, want Hysteria disable failure", err)
	}
	restored, err := db.GetSettings(t.Context())
	if err != nil || restored.PublicHost != "live.example.test" {
		t.Fatalf("failed restore did not roll SQLite back to the live state: %+v, %v", restored, err)
	}
}

func TestBackupDoesNotRecordAnEmptyHysteriaTLSDirectory(t *testing.T) {
	manager, _ := newTestManager(t)
	tlsDir := filepath.Join(manager.DataDir, "hysteria-tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create("empty-tls")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(info.Path, "hysteria-tls")); !os.IsNotExist(err) {
		t.Fatalf("backup retained an empty Hysteria TLS directory: stat error = %v", err)
	}
	verified, err := manager.Verify(info.Name)
	if err != nil || verified.Name != info.Name {
		t.Fatalf("verify backup without TLS files = %+v, %v", verified, err)
	}
}

func TestRestoreAcceptsAnEmptyTLSDirectoryAndMissingHysteriaSettings(t *testing.T) {
	manager, _ := newTestManager(t)
	info, err := manager.Create("empty-tls-restore")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(info.Path, "hysteria-tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreState(info); err != nil {
		t.Fatalf("RestoreState() rejected an empty TLS directory or absent optional Hysteria settings: %v", err)
	}
}

func TestRestoreReportsTLSStatFailures(t *testing.T) {
	t.Run("backup TLS path is a symlink loop", func(t *testing.T) {
		manager, _ := newTestManager(t)
		info, err := manager.Create("backup-tls-loop")
		if err != nil {
			t.Fatal(err)
		}
		tlsPath := filepath.Join(info.Path, "hysteria-tls")
		loop := filepath.Join(t.TempDir(), "loop")
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(loop, tlsPath); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "too many levels of symbolic links") {
			t.Fatalf("RestoreState() error = %v, want backup TLS stat error", err)
		}
	})

	t.Run("live TLS path is a symlink loop", func(t *testing.T) {
		manager, _ := newTestManager(t)
		liveTLS := filepath.Join(manager.DataDir, "hysteria-tls")
		if err := os.MkdirAll(liveTLS, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, contents := range map[string]string{"fullchain.pem": "certificate", "privkey.pem": "private key"} {
			if err := os.WriteFile(filepath.Join(liveTLS, name), []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		info, err := manager.Create("live-tls-loop")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(liveTLS); err != nil {
			t.Fatal(err)
		}
		loop := filepath.Join(t.TempDir(), "loop")
		if err := os.Symlink(loop, loop); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(loop, liveTLS); err != nil {
			t.Fatal(err)
		}
		if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "too many levels of symbolic links") {
			t.Fatalf("RestoreState() error = %v, want live TLS stat error", err)
		}
	})
}

func TestRestoreKeepsLiveDatabaseWhenBackupStateIsMissing(t *testing.T) {
	manager, db := newTestManager(t)
	info, err := manager.Create("missing-state")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "live.example.test"
	if err := db.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	info.StatePath = filepath.Join(t.TempDir(), "missing.db")
	if err := manager.RestoreStateContext(t.Context(), info); err == nil {
		t.Fatal("restore accepted a missing SQLite snapshot")
	}
	current, err := db.GetSettings(t.Context())
	if err != nil || current.PublicHost != "live.example.test" {
		t.Fatalf("failed restore changed live settings = %+v, %v", current, err)
	}
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
