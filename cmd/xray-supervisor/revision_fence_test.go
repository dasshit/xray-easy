package main

import (
	"context"
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
