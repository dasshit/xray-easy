package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/supervisor"
	"xray-easy/internal/xrayapi"
)

type doctorSupervisorStub struct {
	status       supervisor.Status
	healthErr    error
	statusErr    error
	validateErr  error
	probeErr     error
	validatePath string
	validateCall int
	probeCall    int
}

func (s *doctorSupervisorStub) Health(context.Context) error { return s.healthErr }

func (s *doctorSupervisorStub) Status(context.Context) (supervisor.Status, error) {
	return s.status, s.statusErr
}

func (s *doctorSupervisorStub) Validate(_ context.Context, path, _ string) error {
	s.validateCall++
	s.validatePath = path
	return s.validateErr
}

func (s *doctorSupervisorStub) ProbeTarget(context.Context, string, string) error {
	s.probeCall++
	return s.probeErr
}

type doctorHandlerStub struct {
	err   error
	calls int
}

func (s *doctorHandlerStub) Users(context.Context) ([]string, error) {
	s.calls++
	return nil, s.err
}

type doctorStatsStub struct {
	err   error
	calls int
}

func (s *doctorStatsStub) Poll(context.Context) ([]xrayapi.UserStats, error) {
	s.calls++
	return nil, s.err
}

func TestDoctorPassesFreshInstallAndWarnsSetupPending(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, false)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	tokenPath := writeDoctorToken(t, 0o400)
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", tokenPath)
	sup := &doctorSupervisorStub{status: supervisor.Status{State: "running"}}
	handler := &doctorHandlerStub{}
	stats := &doctorStatsStub{}
	var output bytes.Buffer

	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, handler, stats)
	if err != nil {
		t.Fatalf("doctor failed on a fresh installation: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "WARN  Application setup: initial Web UI setup is still pending") || !strings.Contains(output.String(), "Result: PASS (") {
		t.Fatalf("fresh installation output did not report pending setup as a warning: %s", output.String())
	}
	if handler.calls != 0 || stats.calls != 0 {
		t.Fatalf("Xray profile APIs were called before setup: handler=%d stats=%d", handler.calls, stats.calls)
	}
	if sup.validateCall != 1 || sup.validatePath != filepath.Join(configDir, "active.json") {
		t.Fatalf("active config validation calls = %d path=%q", sup.validateCall, sup.validatePath)
	}
	for _, directory := range []string{dataDir, configDir, filepath.Join(configDir, "candidates")} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".xray-easy-doctor-") {
				t.Fatalf("doctor left a temporary probe file in %s", directory)
			}
		}
	}
}

func TestDoctorTreatsUnsupportedStatsAsWarning(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	tokenPath := writeDoctorToken(t, 0o400)
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", tokenPath)
	sup := &doctorSupervisorStub{status: supervisor.Status{State: "running"}}
	handler := &doctorHandlerStub{}
	stats := &doctorStatsStub{err: errors.New("unknown method GetUsersStats")}
	var output bytes.Buffer

	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, handler, stats)
	if err != nil {
		t.Fatalf("unsupported statistics RPC should not fail installation: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "WARN  Xray statistics API: GetUsersStats is unavailable") || !strings.Contains(output.String(), "Result: PASS (2 warning(s))") {
		t.Fatalf("unsupported stats API was not reported as a warning: %s", output.String())
	}
	if handler.calls != 1 || stats.calls != 1 {
		t.Fatalf("Xray API calls = handler:%d stats:%d", handler.calls, stats.calls)
	}
	if sup.probeCall != 1 {
		t.Fatalf("REALITY target probe count = %d", sup.probeCall)
	}
	if strings.Contains(output.String(), "unknown method") {
		t.Fatal("raw gRPC error was exposed in doctor output")
	}
}

func TestDoctorFailureDoesNotPrintSecrets(t *testing.T) {
	dataDir, configDir, _ := prepareDoctorState(t, false)
	secretValue := "private-master-key-material"
	t.Setenv("XRAY_EASY_MASTER_KEY", secretValue)
	tokenPath := writeDoctorToken(t, 0o600)
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", tokenPath)
	sup := &doctorSupervisorStub{status: supervisor.Status{State: "running"}}
	var output bytes.Buffer

	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{})
	if err == nil {
		t.Fatal("invalid master key and secret permissions should fail doctor")
	}
	if strings.Contains(output.String(), secretValue) || strings.Contains(output.String(), "supervisor-secret-should-not-leak") {
		t.Fatalf("doctor output leaked secret material: %s", output.String())
	}
	if strings.Contains(output.String(), "mode is 0400") || !strings.Contains(output.String(), "expected mode 0400") {
		t.Fatalf("incorrect supervisor secret mode was not diagnosed: %s", output.String())
	}
}

func TestDoctorFailsWhenRealityTargetCannotBeReached(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", writeDoctorToken(t, 0o400))
	sup := &doctorSupervisorStub{
		status:   supervisor.Status{State: "running"},
		probeErr: errors.New("target hostname and connection details are private diagnostic data"),
	}
	var output bytes.Buffer
	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{})
	if err == nil || !strings.Contains(output.String(), "FAIL  REALITY target") {
		t.Fatalf("unreachable REALITY target did not fail doctor: %v\n%s", err, output.String())
	}
	if strings.Contains(output.String(), "private diagnostic data") {
		t.Fatalf("raw probe error leaked into doctor output: %s", output.String())
	}
}

func TestDoctorRejectsUnexpectedArguments(t *testing.T) {
	if err := runDoctorCLI(context.Background(), []string{"--unknown"}, t.TempDir(), t.TempDir(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("unexpected doctor argument error = %v", err)
	}
}

func TestDoctorFailsInvalidPublicPort(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, false)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", writeDoctorToken(t, 0o400))
	t.Setenv("XRAY_PUBLIC_PORT", "not-a-port")
	var output bytes.Buffer
	err := runDoctor(context.Background(), dataDir, configDir, &output, &doctorSupervisorStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
	if err == nil || !strings.Contains(output.String(), "FAIL  Public TCP port") {
		t.Fatalf("invalid public port did not fail doctor: %v\n%s", err, output.String())
	}
}

func prepareDoctorState(t *testing.T, configured bool) (string, string, []byte) {
	t.Helper()
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	dataDir := t.TempDir()
	configDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte(`{"log":{"loglevel":"warning"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if configured {
		if _, err := db.Initialize(context.Background(), "admin", "hash", "vpn.example.com", 443); err != nil {
			t.Fatal(err)
		}
		settings, err := db.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityTarget = "example.com:443"
		settings.RealitySNI = "example.com"
		settings.RealityPrivateKeyEnc, err = secret.Seal(key, "private-x25519-key", "reality_private_key")
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityPublicKey = "public-key"
		settings.XrayAPIListen = "127.0.0.1:10085"
		if err := db.UpdateSettings(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dataDir, configDir, key
}

func writeDoctorToken(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray_supervisor_token")
	if err := os.WriteFile(path, []byte("supervisor-secret-should-not-leak\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

var _ doctorSupervisor = (*doctorSupervisorStub)(nil)
var _ doctorHandler = (*doctorHandlerStub)(nil)
var _ doctorStats = (*doctorStatsStub)(nil)
