package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newReplaceTestSupervisor(t *testing.T) (*supervisor, string, string, string) {
	t.Helper()
	s, configDir := newProcessTestSupervisor(t)
	logPath := filepath.Join(t.TempDir(), "api-calls")
	t.Setenv("XRAY_EASY_TEST_API_LOG", logPath)
	binary := filepath.Join(t.TempDir(), "fake-xray-api")
	script := `#!/bin/sh
if [ "$1" = "api" ]; then
  printf '%s\n' "$2" >> "$XRAY_EASY_TEST_API_LOG"
  if [ "$2" = "rmi" ] && [ -f "$XRAY_EASY_TEST_API_LOG.fail-remove" ]; then exit 2; fi
  if [ "$2" = "adi" ] && [ -f "$XRAY_EASY_TEST_API_LOG.fail-once-add" ]; then
    rm "$XRAY_EASY_TEST_API_LOG.fail-once-add"
    exit 2
  fi
  if [ "$2" = "adi" ] && [ -f "$XRAY_EASY_TEST_API_LOG.fail-add" ]; then
    echo 'privateKey=do-not-log' >&2
    exit 2
  fi
  exit 0
fi
if [ "$2" = "-test" ]; then exit 0; fi
trap 'exit 0' INT TERM
while :; do sleep 0.02; done
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s.cfg.xrayBinary = binary
	s.cfg.xrayAPI = "127.0.0.1:10085"
	previous := writeTestConfig(t, configDir, "active.json", `{"inbounds":[{"tag":"vless-reality","protocol":"vless","settings":{"clients":[]}}]}`)
	candidate := writeTestConfig(t, configDir, "candidates/next.json", `{"inbounds":[{"tag":"vless-reality","protocol":"vless","settings":{"clients":[{"id":"new"}]}}]}`)
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	return s, candidate, previous, logPath
}

func TestReplaceInboundUsesXrayAPIWithoutRestartingProcess(t *testing.T) {
	s, candidate, previous, logPath := newReplaceTestSupervisor(t)
	child := s.child
	req := replaceInboundRequest{CandidatePath: candidate, PreviousPath: previous, Tag: "vless-reality", OperationID: "op-1"}
	if err := s.replaceInbound(req); err != nil {
		t.Fatal(err)
	}
	if s.child != child || s.state != "running" {
		t.Fatal("inbound replacement restarted the Xray process")
	}
	calls, err := os.ReadFile(logPath)
	if err != nil || string(calls) != "rmi\nadi\n" {
		t.Fatalf("Xray API calls = %q, %v", calls, err)
	}
}

func TestReplaceInboundRestoresPreviousInboundAfterAddFailure(t *testing.T) {
	s, candidate, previous, logPath := newReplaceTestSupervisor(t)
	if err := os.WriteFile(logPath+".fail-add", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	request := replaceInboundRequest{CandidatePath: candidate, PreviousPath: previous, Tag: "vless-reality", OperationID: "op-2"}
	if err := s.replaceInbound(request); err == nil || !strings.Contains(err.Error(), "could not be restored") {
		t.Fatalf("failed replacement and rollback = %v", err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil || string(calls) != "rmi\nadi\nadi\n" {
		t.Fatalf("rollback API calls = %q, %v", calls, err)
	}
	if err := os.Remove(logPath + ".fail-add"); err != nil {
		t.Fatal(err)
	}
	if err := s.runXrayAPI(context.Background(), "rmi", "vless-reality"); err != nil {
		t.Fatalf("usable Xray API after failure: %v", err)
	}
}

func TestReplaceInboundAddsAndRemovesOptionalInbound(t *testing.T) {
	s, _, previous, logPath := newReplaceTestSupervisor(t)
	withoutHysteria := writeTestConfig(t, s.cfg.configDir, "candidates/no-hysteria.json", `{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	withHysteria := writeTestConfig(t, s.cfg.configDir, "candidates/with-hysteria.json", `{"inbounds":[{"tag":"vless-reality","protocol":"vless"},{"tag":"hysteria2","protocol":"hysteria"}]}`)
	if err := s.replaceInbound(replaceInboundRequest{CandidatePath: withHysteria, PreviousPath: previous, Tag: "hysteria2", OperationID: "enable"}); err != nil {
		t.Fatalf("add optional inbound: %v", err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil || string(calls) != "adi\n" {
		t.Fatalf("AddInbound calls = %q, %v", calls, err)
	}
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.replaceInbound(replaceInboundRequest{CandidatePath: withoutHysteria, PreviousPath: withHysteria, Tag: "hysteria2", OperationID: "disable"}); err != nil {
		t.Fatalf("remove optional inbound: %v", err)
	}
	calls, err = os.ReadFile(logPath)
	if err != nil || string(calls) != "rmi\n" {
		t.Fatalf("RemoveInbound calls = %q, %v", calls, err)
	}
}

func TestReplaceInboundReportsRemovalFailureAndSuccessfulRollback(t *testing.T) {
	s, candidate, previous, logPath := newReplaceTestSupervisor(t)
	request := replaceInboundRequest{CandidatePath: candidate, PreviousPath: previous, Tag: "vless-reality", OperationID: "op-rollback"}
	if err := os.WriteFile(logPath+".fail-remove", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.replaceInbound(request); err == nil || !strings.Contains(err.Error(), "RemoveInbound") {
		t.Fatalf("failed RemoveInbound = %v", err)
	}
	if err := os.Remove(logPath + ".fail-remove"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".fail-once-add", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.replaceInbound(request); err == nil || !strings.Contains(err.Error(), "previous inbound restored") {
		t.Fatalf("successful rollback after AddInbound failure = %v", err)
	}
	if _, err := os.Stat(logPath + ".fail-once-add"); !os.IsNotExist(err) {
		t.Fatalf("one-time AddInbound failure marker remains: %v", err)
	}
	s.mu.Lock()
	s.state = "degraded"
	s.mu.Unlock()
	if err := s.replaceInbound(request); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("replacement on stopped runtime = %v", err)
	}
}

func TestReplaceInboundRejectsInvalidStateAndInput(t *testing.T) {
	s, candidate, previous, _ := newReplaceTestSupervisor(t)
	request := replaceInboundRequest{CandidatePath: candidate, PreviousPath: previous, Tag: "vless-reality", OperationID: "op-3"}
	for _, testcase := range []struct {
		name   string
		mutate func()
	}{
		{"missing API address", func() { s.cfg.xrayAPI = "" }},
		{"invalid tag", func() { request.Tag = "bad/tag" }},
		{"candidate outside config directory", func() { request.CandidatePath = filepath.Join(t.TempDir(), "other.json") }},
		{"inbound missing in both configs", func() {
			request.Tag = "hysteria2"
			request.CandidatePath = writeTestConfig(t, s.cfg.configDir, "candidates/no-hysteria.json", `{"inbounds":[{"tag":"other"}]}`)
			request.PreviousPath = writeTestConfig(t, s.cfg.configDir, "candidates/no-hysteria-active.json", `{"inbounds":[{"tag":"other"}]}`)
		}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			originalRequest, originalAPI := request, s.cfg.xrayAPI
			testcase.mutate()
			if err := s.replaceInbound(request); err == nil {
				t.Fatal("replacement accepted invalid input")
			}
			request, s.cfg.xrayAPI = originalRequest, originalAPI
		})
	}
}

func TestInboundOnlyFileRejectsMissingMalformedAndWrongInbound(t *testing.T) {
	root := t.TempDir()
	for _, testcase := range []struct {
		name    string
		content string
	}{
		{"invalid JSON", `{"inbounds":`},
		{"invalid inbound", `{"inbounds":[42]}`},
		{"missing tag", `{"inbounds":[{"tag":"other"}]}`},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			path := filepath.Join(root, strings.ReplaceAll(testcase.name, " ", "-"))
			if err := os.WriteFile(path, []byte(testcase.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if selected, err := inboundOnlyFile(path, "vless-reality"); err == nil {
				_ = os.Remove(selected)
				t.Fatal("invalid inbound was accepted")
			}
		})
	}
	if _, err := inboundOnlyFile(filepath.Join(root, "missing.json"), "vless-reality"); err == nil {
		t.Fatal("missing config was accepted")
	}
}
