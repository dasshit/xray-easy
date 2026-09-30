package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"
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
	if err == nil || !strings.Contains(string(output), "read supervisor token:") {
		t.Fatalf("missing token healthcheck = %v, %s", err, output)
	}
}

func TestSupervisorMainSubprocessReportsListenerFailure(t *testing.T) {
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestSupervisorMainSubprocessReportsListenerFailure$")
	cmd.Env = append(os.Environ(), "XRAY_EASY_SUPERVISOR_MAIN_CHILD=1", "XRAY_EASY_TEST_CONFIG_DIR="+configDir, "XRAY_EASY_TEST_XRAY_BIN="+binary, "XRAY_EASY_TEST_TOKEN_FILE="+token)
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "listen for supervisor gRPC") {
		t.Fatalf("listener failure = %v, output=%s", err, output)
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
	if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte("valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Use the same fake child used by process lifecycle tests so startup and
	// graceful shutdown are both exercised without a real Xray process.
	binary := filepath.Join(root, "xray")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray test'; exit 0; fi\ntrap 'exit 0' INT TERM\nwhile :; do sleep 0.02; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	listener := bufconn.Listen(1024)
	cfg := &config{configDir: configDir, xrayBinary: binary, tokenFile: token, listen: "bufconn", grace: 250 * time.Millisecond, logSize: 10, listenFunc: func(string, string) (net.Listener, error) { return listener, nil }}
	if err := runSupervisor(cfg, signals); err != nil {
		t.Fatalf("runSupervisor graceful shutdown: %v", err)
	}
}
