package main

import (
	"bufio"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSupervisorHealthcheckEntrypointReportsMissingToken(t *testing.T) {
	if os.Getenv("XRAY_EASY_HEALTHCHECK_CHILD") == "1" {
		os.Args = []string{"xray-supervisor", "healthcheck", "--token-file", os.Getenv("XRAY_EASY_TEST_MISSING_TOKEN")}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisorHealthcheckEntrypointReportsMissingToken$")
	cmd.Env = append(os.Environ(), "XRAY_EASY_HEALTHCHECK_CHILD=1", "XRAY_EASY_TEST_MISSING_TOKEN="+filepath.Join(t.TempDir(), "missing-token"))
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "read token:") {
		t.Fatalf("missing token healthcheck = %v, %s", err, output)
	}
}

func TestSupervisorMainSubprocessHandlesListenerFailureAndShutdown(t *testing.T) {
	if os.Getenv("XRAY_EASY_SUPERVISOR_MAIN_CHILD") == "1" {
		os.Args = []string{"xray-supervisor", "--config-dir", os.Getenv("XRAY_EASY_TEST_CONFIG_DIR"), "--xray-bin", os.Getenv("XRAY_EASY_TEST_XRAY_BIN"), "--token-file", os.Getenv("XRAY_EASY_TEST_TOKEN_FILE"), "--listen", "bad-address", "--grace-period", "100ms"}
		main()
		return
	}
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "xray")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 26.7.28'; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile :; do sleep 0.02; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisorMainSubprocessHandlesListenerFailureAndShutdown$")
	cmd.Env = append(os.Environ(), "XRAY_EASY_SUPERVISOR_MAIN_CHILD=1", "XRAY_EASY_TEST_CONFIG_DIR="+configDir, "XRAY_EASY_TEST_XRAY_BIN="+binary, "XRAY_EASY_TEST_TOKEN_FILE="+token)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "supervisor API stopped") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("supervisor exited before reporting its listener error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not report its listener error")
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("supervisor shutdown: %v", err)
	}
}

func TestSupervisorEntrypointReturnsAfterSignalWithNoConfig(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousArgs := os.Args
	os.Args = []string{"xray-supervisor", "--config-dir", configDir, "--xray-bin", filepath.Join(root, "missing-xray"), "--token-file", token, "--listen", "bad-address", "--grace-period", "10ms"}
	defer func() { os.Args = previousArgs }()
	shield := make(chan os.Signal, 10)
	signal.Notify(shield, syscall.SIGTERM)
	defer signal.Stop(shield)
	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
		case <-deadline:
			t.Fatal("supervisor did not stop after SIGTERM")
		}
	}
}
