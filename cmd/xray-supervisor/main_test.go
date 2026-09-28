package main

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newProcessTestSupervisor(t *testing.T) (*supervisor, string) {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "xray")
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-xray")
	script := `#!/bin/sh
if [ "$2" = "-test" ]; then
  if grep -q VALIDATION_FAIL "$4"; then
    echo 'validation password="bad-secret"'
    exit 2
  fi
  exit 0
fi
if grep -q START_FAIL "$3"; then
  echo 'start token=bad-secret' >&2
  exit 7
fi
trap 'exit 0' INT TERM
echo 'privateKey=process-secret'
while :; do sleep 0.02; done
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(root, "supervisor.token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config{configDir: configDir, xrayBinary: binary, tokenFile: tokenFile, grace: 250 * time.Millisecond, logSize: 3}
	s := newSupervisor(cfg)
	t.Cleanup(s.stopChild)
	return s, configDir
}

func writeTestConfig(t *testing.T, configDir, name, content string) string {
	t.Helper()
	path := filepath.Join(configDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func canonicalTestPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func waitForSupervisorState(t *testing.T, value *supervisor, state string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		value.mu.Lock()
		got := value.state
		value.mu.Unlock()
		if got == state {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	t.Fatalf("supervisor state = %q, want %q (error=%q exit=%q)", value.state, state, value.lastError, value.lastExit)
}

type processState struct {
	configPath   string
	state        string
	lastError    string
	lastExit     string
	restartCount int
	startedAt    time.Time
}

func snapshotProcess(value *supervisor) processState {
	value.mu.Lock()
	defer value.mu.Unlock()
	return processState{configPath: value.configPath, state: value.state, lastError: value.lastError, lastExit: value.lastExit, restartCount: value.restartCount, startedAt: value.startedAt}
}

func TestLogBufferBoundsCopiesAndRedactsEntries(t *testing.T) {
	buffer := newLogBuffer(2)
	buffer.add(`password="one-secret"`)
	buffer.add("second")
	buffer.add("token=third-secret")
	lines := buffer.all()
	if len(lines) != 2 || lines[0] != "second" || strings.Contains(lines[1], "third-secret") || !strings.Contains(lines[1], "[REDACTED]") {
		t.Fatalf("bounded redacted log = %q", lines)
	}
	lines[0] = "mutated"
	if got := buffer.all()[0]; got != "second" {
		t.Fatalf("all exposed internal slice: %q", got)
	}
	if got := newLogBuffer(0); got.limit != 100 {
		t.Fatalf("default log buffer limit = %d", got.limit)
	}
}

func TestStartInitialAndStopChild(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	if got := snapshotProcess(s).state; got != "no-config" {
		t.Fatalf("state without initial config = %q", got)
	}
	active := writeTestConfig(t, configDir, "active.json", "valid")
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	waitForSupervisorState(t, s, "running")
	state := snapshotProcess(s)
	if state.configPath != canonicalTestPath(t, active) || state.restartCount != 1 || state.startedAt.IsZero() {
		t.Fatalf("initial process state path=%q restarts=%d started=%v", state.configPath, state.restartCount, state.startedAt)
	}
	logs := s.log.all()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(strings.Join(logs, "\n"), "[REDACTED]") {
			break
		}
		time.Sleep(10 * time.Millisecond)
		logs = s.log.all()
	}
	foundRedacted := false
	for _, line := range logs {
		if strings.Contains(line, "process-secret") {
			t.Fatalf("Xray secret leaked into log: %q", line)
		}
		if strings.Contains(line, "[REDACTED]") {
			foundRedacted = true
		}
	}
	if !foundRedacted {
		t.Fatalf("captured child output was not redacted: %q", logs)
	}
	s.stopChild()
	waitForSupervisorState(t, s, "stopped")
	s.stopChild() // stopping with no child is safe
}

func TestValidateUsesPinnedBinaryAndRedactsFailureOutput(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	valid := writeTestConfig(t, configDir, "candidates/valid.json", "valid")
	if err := s.validate(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	invalid := writeTestConfig(t, configDir, "candidates/invalid.json", "VALIDATION_FAIL")
	err := s.validate(invalid)
	if err == nil || !strings.Contains(err.Error(), "config validation failed") || strings.Contains(err.Error(), "bad-secret") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("validation failure was not safely reported: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.validate(outside); err == nil || !strings.Contains(err.Error(), "inside config directory") {
		t.Fatalf("outside path validation error = %v", err)
	}
	if err := s.validate(""); err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("empty path validation error = %v", err)
	}
	if err := s.validate(filepath.Join(configDir, "missing.json")); err == nil {
		t.Fatal("missing config path validated")
	}
}

func TestSafePathResolvesSymlinksBeforeCheckingBoundary(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	inside := writeTestConfig(t, configDir, "candidates/valid.json", "valid")
	resolved, err := s.safePath(inside)
	if err != nil || resolved != canonicalTestPath(t, inside) {
		t.Fatalf("safe path = %q, %v", resolved, err)
	}
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(configDir, "candidates", "escape.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.safePath(link); err == nil || !strings.Contains(err.Error(), "inside config directory") {
		t.Fatalf("symlink escape accepted: %v", err)
	}
}

func TestApplyPreservesCurrentProcessOnValidationFailureAndRollsBackStartupFailure(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	active := writeTestConfig(t, configDir, "active.json", "valid-active")
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	waitForSupervisorState(t, s, "running")
	invalid := writeTestConfig(t, configDir, "candidates/invalid.json", "VALIDATION_FAIL")
	if err := s.apply(invalid); err == nil {
		t.Fatal("invalid candidate applied")
	}
	state := snapshotProcess(s)
	if state.state != "running" || state.configPath != canonicalTestPath(t, active) {
		t.Fatalf("validation failure disturbed active process: state=%q path=%q", state.state, state.configPath)
	}

	crashing := writeTestConfig(t, configDir, "candidates/crashing.json", "START_FAIL")
	err := s.apply(crashing)
	if err == nil || !strings.Contains(err.Error(), "exited during startup") && !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("startup failure error = %v", err)
	}
	waitForSupervisorState(t, s, "running")
	state = snapshotProcess(s)
	if state.configPath != canonicalTestPath(t, active) {
		t.Fatalf("rollback restored %q, want %q", state.configPath, active)
	}
	if state.restartCount != 3 {
		t.Fatalf("restart count after rollback = %d, want 3", state.restartCount)
	}
	logs := strings.Join(s.log.all(), "\n")
	if strings.Contains(logs, "bad-secret") || strings.Contains(logs, "process-secret") {
		t.Fatalf("secret leaked through apply/rollback logs: %s", logs)
	}

	working := writeTestConfig(t, configDir, "candidates/working.json", "valid-new")
	if err := s.apply(working); err != nil {
		t.Fatalf("valid candidate failed to apply: %v", err)
	}
	state = snapshotProcess(s)
	if state.state != "running" || state.configPath != canonicalTestPath(t, working) {
		t.Fatalf("successful apply state=%q path=%q", state.state, state.configPath)
	}
	s.stopChild()
	waitForSupervisorState(t, s, "stopped")
}

func TestRollbackDegradesWhenNoPreviousConfigOrRestartFails(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	s.rollback(filepath.Join(configDir, "missing-active.json"), errors.New("candidate failed"))
	state := snapshotProcess(s)
	if state.state != "degraded" || state.lastError != "candidate failed" {
		t.Fatalf("rollback without previous config = %q / %q", state.state, state.lastError)
	}
	active := writeTestConfig(t, configDir, "active.json", "valid")
	s.cfg.xrayBinary = filepath.Join(t.TempDir(), "missing-xray")
	s.rollback(active, errors.New("candidate failed"))
	state = snapshotProcess(s)
	if state.state != "degraded" || !strings.Contains(state.lastError, "rollback failed") {
		t.Fatalf("rollback startup failure = %q / %q", state.state, state.lastError)
	}
}

func TestRedactAndWriteJSON(t *testing.T) {
	if got := redact(`password="secret"`); strings.Contains(got, "secret") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("redact() = %q", got)
	}
	response := httptest.NewRecorder()
	writeJSON(response, 202, map[string]string{"ok": "yes"})
	if response.Code != 202 || response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), `"ok":"yes"`) {
		t.Fatalf("writeJSON response = %d %q %q", response.Code, response.Header(), response.Body.String())
	}
	writeError(response, 400, fmt.Errorf(`invalid password="secret"`))
	if strings.Contains(response.Body.String(), "secret") || !strings.Contains(response.Body.String(), "[REDACTED]") {
		t.Fatalf("writeError leaked secret: %q", response.Body.String())
	}
}

func TestFormatExit(t *testing.T) {
	if got := formatExit(nil); got != "clean exit" {
		t.Fatalf("formatExit(nil) = %q", got)
	}
	err := exec.Command("/bin/sh", "-c", "exit 7").Run()
	if got := formatExit(err); got != "exit status 7" {
		t.Fatalf("formatExit(exit 7) = %q", got)
	}
	if got := formatExit(errors.New("wait failed")); got != "wait failed" {
		t.Fatalf("formatExit(other error) = %q", got)
	}
}
