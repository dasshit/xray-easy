package runtime

import (
	"os"
	"path/filepath"
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
