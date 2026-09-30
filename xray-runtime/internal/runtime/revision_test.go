package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRevisionFenceRejectsInvalidStaleConflictingAndChangedRequests(t *testing.T) {
	fence, err := NewRevisionFence("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Begin(0, "op", "apply", "fingerprint"); err == nil {
		t.Fatal("zero revision was accepted")
	}
	if _, err := fence.Begin(1, " ", "apply", "fingerprint"); err == nil {
		t.Fatal("empty operation was accepted")
	}
	if _, err := fence.Begin(1, "op", "apply", ""); err == nil {
		t.Fatal("empty fingerprint was accepted")
	}
	if replay, err := fence.Begin(1, "op", "apply", "fingerprint"); err != nil || replay {
		t.Fatalf("begin = %v, %v", replay, err)
	}
	if err := fence.Commit(1, "op", "apply", "fingerprint"); err != nil {
		t.Fatal(err)
	}
	if replay, err := fence.Begin(1, "op", "apply", "fingerprint"); err != nil || !replay {
		t.Fatalf("committed replay = %v, %v", replay, err)
	}
	if _, err := fence.Begin(1, "op", "apply", "different"); err == nil {
		t.Fatal("changed payload was accepted")
	}
	if _, err := fence.Begin(1, "other-op", "apply", "fingerprint"); err == nil {
		t.Fatal("revision reuse by a different operation was accepted")
	}
	if _, err := fence.Begin(0, "old", "apply", "fingerprint"); err == nil {
		t.Fatal("stale revision was accepted")
	}
	if _, err := fence.Begin(1, "op", "rollback:apply", "fingerprint"); err == nil {
		t.Fatal("rollback key on a non-compensation operation was accepted")
	}
}

func TestRevisionFenceLatestNilMutationLimitAndInvalidCommits(t *testing.T) {
	var nilFence *RevisionFence
	if nilFence.Latest() != 0 {
		t.Fatalf("nil fence latest revision = %d", nilFence.Latest())
	}
	if err := nilFence.Commit(1, "op", "apply", "fingerprint"); err == nil {
		t.Fatal("nil fence committed a mutation")
	}
	fence, err := NewRevisionFence("")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxRevisionMutations; index++ {
		key := "mutation-" + strconv.Itoa(index)
		if _, err := fence.Begin(1, "op", key, "fingerprint"); err != nil {
			t.Fatalf("begin mutation %d: %v", index, err)
		}
	}
	if _, err := fence.Begin(1, "op", "over-limit", "fingerprint"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("mutation limit error = %v", err)
	}
	for _, test := range []struct {
		name, operation, key, fingerprint string
		revision                          int64
	}{
		{"wrong revision", "op", "mutation-0", "fingerprint", 2},
		{"wrong operation", "other", "mutation-0", "fingerprint", 1},
		{"wrong fingerprint", "op", "mutation-0", "changed", 1},
		{"missing mutation", "op", "missing", "fingerprint", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := fence.Commit(test.revision, test.operation, test.key, test.fingerprint); !errors.Is(err, ErrRevisionConflict) {
				t.Fatalf("commit error = %v", err)
			}
		})
	}
	if err := fence.Commit(1, "op", "mutation-0", "fingerprint"); err != nil {
		t.Fatal(err)
	}
	if err := fence.Commit(1, "op", "mutation-0", "fingerprint"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("duplicate commit error = %v", err)
	}
}

func TestRevisionFenceRejectsInvalidJournalShapesAndReadFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.json")
	invalidRecords := []string{
		`{"version":2}`,
		`{"version":1,"revision":0,"operation_id":"unexpected","mutations":{}}`,
		`{"version":1,"revision":1,"operation_id":"","mutations":{"apply":{"fingerprint":"x","state":"pending"}}}`,
		`{"version":1,"revision":1,"operation_id":"op","mutations":{}}`,
		`{"version":1,"revision":1,"operation_id":"op","mutations":{"":{"fingerprint":"x","state":"pending"}}}`,
		`{"version":1,"revision":1,"operation_id":"op","mutations":{"apply":{"fingerprint":"","state":"pending"}}}`,
		`{"version":1,"revision":1,"operation_id":"op","mutations":{"apply":{"fingerprint":"x","state":"unknown"}}}`,
	}
	for _, contents := range invalidRecords {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRevisionFence(path); err == nil {
			t.Errorf("invalid revision journal was accepted: %s", contents)
		}
	}
	if _, err := NewRevisionFence(t.TempDir()); err == nil {
		t.Fatal("revision journal directory was read as a file")
	}
}

func TestRevisionFenceAllowsMultipleMutationsAndRollbackReplay(t *testing.T) {
	fence, err := NewRevisionFence("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Begin(9, "op-9", "replace:a", "one"); err != nil {
		t.Fatal(err)
	}
	if err := fence.Commit(9, "op-9", "replace:a", "one"); err != nil {
		t.Fatal(err)
	}
	if replay, err := fence.Begin(9, "op-9", "replace:b", "two"); err != nil || replay {
		t.Fatalf("second mutation begin = %v, %v", replay, err)
	}
	if err := fence.Commit(9, "op-9", "replace:b", "two"); err != nil {
		t.Fatal(err)
	}
	if _, err := fence.Begin(9, "op-9-rollback", "replace:c", "bad"); err == nil {
		t.Fatal("rollback without rollback key was accepted")
	}
	if _, err := fence.Begin(9, "op-9-rollback", "rollback:replace:a", "restore"); err != nil {
		t.Fatal(err)
	}
	if err := fence.Commit(9, "op-9-rollback", "rollback:replace:a", "restore"); err != nil {
		t.Fatal(err)
	}
	if replay, err := fence.Begin(9, "op-9", "replace:a", "one"); err != nil || replay {
		t.Fatalf("original operation after rollback = %v, %v; want pending", replay, err)
	}
}

func TestRevisionFencePersistsOnlyHashedMutationMetadataAndReplaysOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "revision.json")
	fence, err := NewRevisionFence(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "credential-super-secret"
	email := "private-device@example.test"
	fingerprint := payloadFingerprint(email, secret)
	key := "add-user:" + payloadFingerprint(email)
	if _, err := fence.Begin(4, "operation-4", key, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := fence.Commit(4, "operation-4", key, fingerprint); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("revision file permissions = %o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), email) {
		t.Fatalf("revision file contains sensitive user fields: %s", data)
	}
	restarted, err := NewRevisionFence(path)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Latest() != 4 {
		t.Fatalf("restored revision = %d, want 4", restarted.Latest())
	}
	if replay, err := restarted.Begin(4, "operation-4", key, fingerprint); err != nil || replay {
		t.Fatalf("restart replay = %v, %v; want pending", replay, err)
	}
}

func TestRevisionFenceRejectsCorruptOrInvalidJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRevisionFence(path); err == nil {
		t.Fatal("corrupt journal was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"revision":-1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRevisionFence(path); err == nil {
		t.Fatal("invalid revision record was accepted")
	}
}

func TestRevisionFenceReportsPersistenceFailure(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	fence, err := NewRevisionFence(filepath.Join(path, "revision.json"))
	if err != nil {
		t.Fatal(err)
	}
	fence.path = directory
	if _, err := fence.Begin(1, "op", "apply", "fingerprint"); err == nil {
		t.Fatal("failed journal replacement was ignored")
	}
}

func TestRevisionFencePersistenceFailureBranches(t *testing.T) {
	for _, failure := range []string{"mkdir", "create", "chmod", "write", "file-sync", "close", "rename", "open-directory", "directory-sync"} {
		t.Run(failure, func(t *testing.T) {
			fence, err := NewRevisionFence("")
			if err != nil {
				t.Fatal(err)
			}
			fence.path = filepath.Join(t.TempDir(), "revision.json")
			fence.fileSystem = failingRevisionFileSystem{revisionFileSystem: osRevisionFileSystem{}, fail: failure}
			if _, err := fence.Begin(1, "operation", "apply", "fingerprint"); !errors.Is(err, ErrRevisionIO) {
				t.Fatalf("persistence failure %q returned %v", failure, err)
			}
		})
	}
}

type failingRevisionFileSystem struct {
	revisionFileSystem
	fail string
}

func (fs failingRevisionFileSystem) MkdirAll(path string, mode os.FileMode) error {
	if fs.fail == "mkdir" {
		return errors.New("injected mkdir failure")
	}
	return fs.revisionFileSystem.MkdirAll(path, mode)
}

func (fs failingRevisionFileSystem) CreateTemp(directory, pattern string) (revisionTempFile, error) {
	if fs.fail == "create" {
		return nil, errors.New("injected temporary-file failure")
	}
	temporary, err := fs.revisionFileSystem.CreateTemp(directory, pattern)
	if err != nil {
		return nil, err
	}
	return failingRevisionTempFile{revisionTempFile: temporary, fail: fs.fail}, nil
}

func (fs failingRevisionFileSystem) Rename(oldPath, newPath string) error {
	if fs.fail == "rename" {
		return errors.New("injected rename failure")
	}
	return fs.revisionFileSystem.Rename(oldPath, newPath)
}

func (fs failingRevisionFileSystem) OpenDirectory(path string) (revisionDirectoryHandle, error) {
	if fs.fail == "open-directory" {
		return nil, errors.New("injected directory-open failure")
	}
	directory, err := fs.revisionFileSystem.OpenDirectory(path)
	if err != nil {
		return nil, err
	}
	return failingRevisionDirectory{revisionDirectoryHandle: directory, fail: fs.fail}, nil
}

type failingRevisionTempFile struct {
	revisionTempFile
	fail string
}

func (file failingRevisionTempFile) Chmod(mode os.FileMode) error {
	if file.fail == "chmod" {
		return errors.New("injected chmod failure")
	}
	return file.revisionTempFile.Chmod(mode)
}

func (file failingRevisionTempFile) Write(data []byte) (int, error) {
	if file.fail == "write" {
		return 0, errors.New("injected write failure")
	}
	return file.revisionTempFile.Write(data)
}

func (file failingRevisionTempFile) Sync() error {
	if file.fail == "file-sync" {
		return errors.New("injected file-sync failure")
	}
	return file.revisionTempFile.Sync()
}

func (file failingRevisionTempFile) Close() error {
	if file.fail == "close" {
		_ = file.revisionTempFile.Close()
		return errors.New("injected close failure")
	}
	return file.revisionTempFile.Close()
}

type failingRevisionDirectory struct {
	revisionDirectoryHandle
	fail string
}

func (directory failingRevisionDirectory) Sync() error {
	if directory.fail == "directory-sync" {
		return errors.New("injected directory-sync failure")
	}
	return directory.revisionDirectoryHandle.Sync()
}
