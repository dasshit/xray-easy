package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevisionFenceOrdersOperationsAndResumesAfterRestart(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	active := writeTestConfig(t, configDir, "active.json", "active")
	candidate := writeTestConfig(t, configDir, "candidates/revision-5.json", "candidate")
	if err := s.applyRevisionContext(context.Background(), candidate, "operation-5", 5); err != nil {
		t.Fatalf("apply revision 5: %v", err)
	}
	state := snapshotProcess(s)
	applyMutation := "apply"
	if state.state != "running" || s.revisions.latest.Revision != 5 || s.revisions.latest.Mutations[applyMutation].State != "committed" {
		t.Fatalf("committed revision state = %+v / %+v", state, s.revisions.latest)
	}
	if err := s.applyRevisionContext(context.Background(), candidate, "operation-5", 5); err != nil {
		t.Fatalf("exact committed replay should be a no-op: %v", err)
	}
	if got := snapshotProcess(s).restartCount; got != state.restartCount {
		t.Fatalf("committed replay restarted Xray: count %d -> %d", state.restartCount, got)
	}
	if err := s.applyRevisionContext(context.Background(), active, "operation-5", 5); err == nil {
		t.Fatal("same revision and operation with a different candidate was accepted")
	}
	if err := s.applyRevisionContext(context.Background(), active, "different-operation", 5); err == nil {
		t.Fatal("same revision with another operation was accepted")
	}
	if err := s.applyRevisionContext(context.Background(), active, "stale-operation", 4); err == nil {
		t.Fatal("stale revision was accepted")
	}

	// A replacement supervisor reads the same durable fence. Committed runtime
	// mutations become resumable because Xray is relaunched from active.json.
	restarted := newSupervisor(s.cfg)
	t.Cleanup(restarted.stopChild)
	if restarted.revisions.err != nil {
		t.Fatalf("load revision state after restart: %v", restarted.revisions.err)
	}
	if restarted.revisions.latest.Mutations[applyMutation].State != "pending" {
		t.Fatalf("revision was not made resumable after process restart: %+v", restarted.revisions.latest)
	}
	if err := restarted.startInitial(); err != nil {
		t.Fatalf("start replacement supervisor: %v", err)
	}
	if err := restarted.applyRevisionContext(context.Background(), candidate, "operation-5", 5); err != nil {
		t.Fatalf("resume same revision after restart: %v", err)
	}
	if err := os.WriteFile(candidate, []byte("changed candidate under reused path"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restarted.applyRevisionContext(context.Background(), candidate, "operation-5", 5); err == nil {
		t.Fatal("same operation replay with changed config contents was accepted")
	}
	if err := restarted.applyRevisionContext(context.Background(), active, "stale-operation", 4); err == nil {
		t.Fatal("stale revision was accepted after supervisor restart")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.cfg.revisionState), "revision.json")); err != nil {
		t.Fatalf("durable revision state missing: %v", err)
	}
}

func TestRevisionFenceAllowsRetryOfFailedApplyAtSameRevision(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	active := writeTestConfig(t, configDir, "active.json", "valid-active")
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	waitForSupervisorState(t, s, "running")
	candidate := writeTestConfig(t, configDir, "candidates/retry.json", "START_FAIL")
	firstErr := s.applyRevisionContext(context.Background(), candidate, "retry-operation", 8)
	if firstErr == nil || !strings.Contains(firstErr.Error(), "exit status 7") {
		t.Fatalf("first failed revision apply = %v", firstErr)
	}
	if got := s.revisions.latest.Mutations["apply"].State; got != "pending" {
		t.Fatalf("failed mutation state = %q, want pending", got)
	}
	secondErr := s.applyRevisionContext(context.Background(), candidate, "retry-operation", 8)
	if secondErr == nil || !strings.Contains(secondErr.Error(), "exit status 7") {
		t.Fatalf("retry of failed revision was rejected before apply: %v", secondErr)
	}
	if err := s.applyRevisionContext(context.Background(), active, "older-operation", 7); err == nil {
		t.Fatal("older revision was accepted after a failed higher revision")
	}
	higher := writeTestConfig(t, configDir, "candidates/higher.json", "valid-higher")
	if err := s.applyRevisionContext(context.Background(), higher, "higher-operation", 9); err != nil {
		t.Fatalf("higher revision did not supersede failed pending operation: %v", err)
	}
}

func TestRevisionFenceSupportsMultipleInboundMutationsAtOneRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.json")
	fence := newRevisionFence(path)
	for _, mutation := range []string{"replace:vless-reality", "replace:vmess-tls"} {
		complete, err := fence.begin(7, "settings-operation", mutation, "candidate-"+mutation)
		if err != nil || complete {
			t.Fatalf("begin %s = %v, %v", mutation, complete, err)
		}
		if err := fence.commit(7, "settings-operation", mutation, "candidate-"+mutation); err != nil {
			t.Fatalf("commit %s: %v", mutation, err)
		}
	}
	if got := len(fence.latest.Mutations); got != 2 {
		t.Fatalf("same-revision mutations = %d, want 2", got)
	}
}

func TestRevisionFenceRollbackKeepsRevisionAndMakesOriginalMutationResumable(t *testing.T) {
	fence := newRevisionFence(filepath.Join(t.TempDir(), "revision.json"))
	complete, err := fence.begin(12, "operation", "apply", "candidate-hash")
	if err != nil || complete {
		t.Fatalf("begin apply = %v, %v", complete, err)
	}
	if err := fence.commit(12, "operation", "apply", "candidate-hash"); err != nil {
		t.Fatal(err)
	}
	complete, err = fence.begin(12, "operation-rollback", "rollback:apply", "active-hash")
	if err != nil || complete {
		t.Fatalf("begin rollback = %v, %v", complete, err)
	}
	if err := fence.commit(12, "operation-rollback", "rollback:apply", "active-hash"); err != nil {
		t.Fatal(err)
	}
	if fence.latest.Revision != 12 || fence.latest.Mutations["apply"].State != "pending" {
		t.Fatalf("rollback changed the revision fence or left the original complete: %+v", fence.latest)
	}
	complete, err = fence.begin(12, "operation", "apply", "candidate-hash")
	if err != nil || complete {
		t.Fatalf("original mutation did not become resumable after rollback: %v, %v", complete, err)
	}
}

func TestRevisionFenceRejectsCorruptStateAndCreatesStateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.json")
	if err := os.WriteFile(path, []byte(`{"revision":7,"operation_id":"op","mutations":{"apply":{"fingerprint":"x","state":"unknown"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if fence := newRevisionFence(path); fence.err == nil {
		t.Fatal("invalid persisted mutation state was accepted")
	}
	fence := newRevisionFence(filepath.Join(t.TempDir(), "missing-parent", "revision.json"))
	if _, err := fence.begin(1, "op", "apply", "candidate"); err != nil {
		t.Fatalf("initial revision reservation: %v", err)
	}
}

func TestRevisionFenceRejectsInvalidPathsRecordsAndMutationMetadata(t *testing.T) {
	if fence := newRevisionFence("  "); fence.err == nil {
		t.Fatal("empty revision state path accepted")
	}
	directory := t.TempDir()
	if fence := newRevisionFence(directory); fence.err == nil {
		t.Fatal("directory was accepted as revision state file")
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{"invalid JSON", "{"},
		{"negative revision", `{"revision":-1}`},
		{"zero revision with operation", `{"revision":0,"operation_id":"op"}`},
		{"positive revision without mutations", `{"revision":1,"operation_id":"op"}`},
		{"positive revision without operation", `{"revision":1,"mutations":{"apply":{"fingerprint":"hash","state":"pending"}}}`},
		{"invalid mutation state", `{"revision":1,"operation_id":"op","mutations":{"apply":{"fingerprint":"hash","state":"unknown"}}}`},
		{"empty mutation key", `{"revision":1,"operation_id":"op","mutations":{"":{"fingerprint":"hash","state":"pending"}}}`},
		{"empty mutation fingerprint", `{"revision":1,"operation_id":"op","mutations":{"apply":{"state":"pending"}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "revision.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if fence := newRevisionFence(path); fence.err == nil {
				t.Fatalf("invalid state accepted: %s", test.data)
			}
		})
	}
}

func TestRevisionFenceRejectsInvalidBeginAndCommitIdentities(t *testing.T) {
	broken := newRevisionFence("")
	if _, err := broken.begin(1, "op", "apply", "hash"); err == nil {
		t.Fatal("begin ignored initialization error")
	}
	if err := broken.commit(1, "op", "apply", "hash"); err == nil {
		t.Fatal("commit ignored initialization error")
	}

	fence := revisionFence{path: filepath.Join(t.TempDir(), "revision.json"), latest: revisionRecord{Revision: 5, OperationID: "owner", Mutations: map[string]revisionMutation{"apply": {Fingerprint: "old", State: "pending"}}}}
	for _, test := range []struct {
		name                        string
		revision                    int64
		operation, key, fingerprint string
	}{
		{"zero revision", 0, "owner", "apply", "hash"},
		{"empty operation", 5, " ", "apply", "hash"},
		{"empty mutation key", 5, "owner", " ", "hash"},
		{"empty fingerprint", 5, "owner", "apply", ""},
		{"stale revision", 4, "owner", "apply", "hash"},
		{"other operation owns revision", 5, "other", "apply", "hash"},
		{"rollback key without rollback operation", 5, "owner", "rollback:apply", "hash"},
		{"changed fingerprint", 5, "owner", "apply", "new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fence.begin(test.revision, test.operation, test.key, test.fingerprint); err == nil {
				t.Fatal("invalid mutation identity accepted")
			}
		})
	}
	for _, test := range []struct {
		name                        string
		revision                    int64
		operation, key, fingerprint string
	}{
		{"wrong revision", 4, "owner", "apply", "old"},
		{"wrong operation", 5, "other", "apply", "old"},
		{"missing mutation", 5, "owner", "missing", "old"},
		{"changed fingerprint", 5, "owner", "apply", "different"},
	} {
		t.Run("commit "+test.name, func(t *testing.T) {
			if err := fence.commit(test.revision, test.operation, test.key, test.fingerprint); err == nil {
				t.Fatal("invalid commit accepted")
			}
		})
	}
	committed := fence
	committed.latest.Mutations = map[string]revisionMutation{"apply": {Fingerprint: "old", State: "committed"}}
	if err := committed.commit(5, "owner", "apply", "old"); err == nil {
		t.Fatal("already committed mutation committed twice")
	}
}

func TestRevisionFenceInitializesMutationMapAndPersistsFailures(t *testing.T) {
	root := t.TempDir()
	fence := revisionFence{path: filepath.Join(root, "revision.json"), latest: revisionRecord{Revision: 8, OperationID: "same"}}
	complete, err := fence.begin(8, "same", "new-mutation", "hash")
	if err != nil || complete || fence.latest.Mutations["new-mutation"].State != "pending" {
		t.Fatalf("begin with absent mutation map = %v, %v, %+v", complete, err, fence.latest)
	}
	if err := fence.commit(8, "same", "new-mutation", "hash"); err != nil {
		t.Fatalf("commit newly added mutation: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	blockedPath := filepath.Join(blocker, "revision.json")
	blocked := revisionFence{path: blockedPath}
	if _, err := blocked.begin(1, "op", "apply", "hash"); err == nil {
		t.Fatal("persist succeeded below a regular file")
	}
	pending := revisionRecord{Revision: 1, OperationID: "op", Mutations: map[string]revisionMutation{"apply": {Fingerprint: "hash", State: "pending"}}}
	blockedCommit := revisionFence{path: blockedPath, latest: pending}
	if err := blockedCommit.commit(1, "op", "apply", "hash"); err == nil {
		t.Fatal("commit persisted below a regular file")
	}
}

type failingRevisionTempFile struct {
	name     string
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
	closed   bool
}

func (f *failingRevisionTempFile) Name() string            { return f.name }
func (f *failingRevisionTempFile) Chmod(os.FileMode) error { return f.chmodErr }
func (f *failingRevisionTempFile) Write([]byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return 1, nil
}
func (f *failingRevisionTempFile) Sync() error  { return f.syncErr }
func (f *failingRevisionTempFile) Close() error { f.closed = true; return f.closeErr }

type failingRevisionDirectory struct {
	syncErr error
	closed  bool
}

func (d *failingRevisionDirectory) Sync() error  { return d.syncErr }
func (d *failingRevisionDirectory) Close() error { d.closed = true; return nil }

func TestRevisionFencePersisterReportsAtomicWriteFailures(t *testing.T) {
	injected := errors.New("injected filesystem failure")
	tests := []struct {
		name      string
		configure func(*revisionFileSystem)
	}{
		{"create directory", func(fs *revisionFileSystem) { fs.mkdirAll = func(string, os.FileMode) error { return injected } }},
		{"encode state", func(fs *revisionFileSystem) { fs.marshal = func(any) ([]byte, error) { return nil, injected } }},
		{"create temporary file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) { return nil, injected }
		}},
		{"secure temporary file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary", chmodErr: injected}, nil
			}
		}},
		{"write temporary file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary", writeErr: injected}, nil
			}
		}},
		{"sync temporary file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary", syncErr: injected}, nil
			}
		}},
		{"close temporary file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary", closeErr: injected}, nil
			}
		}},
		{"replace state file", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary"}, nil
			}
			fs.rename = func(string, string) error { return injected }
		}},
		{"open state directory", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary"}, nil
			}
			fs.openDir = func(string) (revisionDirectory, error) { return nil, injected }
		}},
		{"sync state directory", func(fs *revisionFileSystem) {
			fs.createTemp = func(string, string) (revisionTempFile, error) {
				return &failingRevisionTempFile{name: "temporary"}, nil
			}
			fs.openDir = func(string) (revisionDirectory, error) { return &failingRevisionDirectory{syncErr: injected}, nil }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileSystem := defaultRevisionFileSystem()
			test.configure(fileSystem)
			fence := revisionFence{path: filepath.Join(t.TempDir(), "revision.json"), fileSystem: fileSystem}
			if err := fence.persist(revisionRecord{Revision: 1, OperationID: "op"}); err == nil {
				t.Fatal("injected filesystem error was ignored")
			}
		})
	}
}

func TestRevisionFenceSurfacesPersistenceFailuresDuringReservationAndRestart(t *testing.T) {
	injected := errors.New("cannot create temporary revision file")
	fileSystem := defaultRevisionFileSystem()
	fileSystem.createTemp = func(string, string) (revisionTempFile, error) { return nil, injected }
	path := filepath.Join(t.TempDir(), "revision.json")
	if err := os.WriteFile(path, []byte(`{"revision":3,"operation_id":"op","mutations":{"apply":{"fingerprint":"hash","state":"committed"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if fence := newRevisionFenceWithFileSystem(path, fileSystem); fence.err == nil || !strings.Contains(fence.err.Error(), "reset revision mutation state") {
		t.Fatalf("restart persistence error = %v", fence.err)
	}
	newFence := revisionFence{path: filepath.Join(t.TempDir(), "new.json"), fileSystem: fileSystem}
	if _, err := newFence.begin(1, "op", "apply", "hash"); err == nil || !strings.Contains(err.Error(), "temporary file") {
		t.Fatalf("reservation persistence error = %v", err)
	}
}
