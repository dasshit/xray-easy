package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/xrayapi"
)

type doctorXrayRuntimeStub struct {
	status       domain.XrayRuntimeStatus
	healthErr    error
	statusErr    error
	validateErr  error
	probeErr     error
	ipv6Err      error
	validatePath string
	validateID   string
	validateRev  int64
	validateCall int
	probeCall    int
	ipv6Call     int
	logs         []string
	logsErr      error
}

func TestDoctorAmneziaWGChecksOnlyWhenConfigured(t *testing.T) {
	dataDir, configDir := t.TempDir(), t.TempDir()
	t.Setenv("AWG_PUBLIC_HOST", "89.169.13.234")
	t.Setenv("AWG_PUBLIC_PORT", "51821")
	checks := collectDoctorChecksWithAWG(
		context.Background(), dataDir, configDir,
		&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "stopped"}},
		&doctorHandlerStub{}, &doctorStatsStub{},
		&doctorAWGStub{
			status: domain.AmneziaWGStatus{Running: true},
			peers:  []domain.AmneziaWGPeer{{Name: "phone"}},
		}, nil,
	)
	if !hasDoctorCheck(checks, "AmneziaWG service", doctorPass) {
		t.Fatalf("configured healthy AWG was not reported as passing: %+v", checks)
	}
	if check := findDoctorCheck(checks, "AmneziaWG UDP firewall"); check == nil || check.level != doctorWarn || !strings.Contains(check.hint, "UDP 51821") {
		t.Fatalf("configured AWG firewall warning = %+v", check)
	}

	checks = collectDoctorChecksWithAWG(
		context.Background(), dataDir, configDir,
		&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "stopped"}},
		&doctorHandlerStub{}, &doctorStatsStub{}, nil, errors.New("token path unavailable"),
	)
	if !hasDoctorCheck(checks, "AmneziaWG control API", doctorFail) {
		t.Fatalf("missing AWG client was not reported as failure: %+v", checks)
	}
}

func TestDoctorOmitsAmneziaWGChecksWhenDisabled(t *testing.T) {
	t.Setenv("AWG_PUBLIC_HOST", "")
	checks := collectDoctorChecksWithAWG(
		context.Background(), t.TempDir(), t.TempDir(),
		&doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{},
		&doctorAWGStub{status: domain.AmneziaWGStatus{Running: true}}, nil,
	)
	if findDoctorCheck(checks, "AmneziaWG service") != nil || findDoctorCheck(checks, "AmneziaWG UDP firewall") != nil {
		t.Fatalf("disabled AmneziaWG produced checks: %+v", checks)
	}
}

func TestDoctorReportsPendingProfileExpirationForXrayAndAmneziaWG(t *testing.T) {
	dataDir, configDir, _ := prepareDoctorState(t, true)
	expiresAt := time.Now().UTC().Add(-time.Minute)
	db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	client := domain.Client{ID: "expired-client", Name: "expired-phone", Email: "expired@xray-easy", Enabled: true, ExpiresAt: &expiresAt}
	if err := db.CreateClient(context.Background(), client, "uuid-expired", client.Email, "short-expired"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_EASY_MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	checks := collectDoctorChecks(context.Background(), dataDir, configDir, &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
	if check := findDoctorCheck(checks, "Profile expiry"); check == nil || check.level != doctorWarn || !strings.Contains(check.detail, "1 expired Xray profile") {
		t.Fatalf("pending Xray expiry diagnostic = %+v", check)
	}

	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	checks = collectDoctorChecksWithAWG(context.Background(), dataDir, configDir, &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{}, &doctorAWGStub{
		status: domain.AmneziaWGStatus{Running: true},
		peers:  []domain.AmneziaWGPeer{{Name: "awg-phone", ExpiresAt: &expiresAt}},
	}, nil)
	if check := findDoctorCheck(checks, "AmneziaWG profile expiry"); check == nil || check.level != doctorWarn || !strings.Contains(check.detail, "1 expired peer") {
		t.Fatalf("pending AWG expiry diagnostic = %+v", check)
	}
}

func TestDoctorLeaseServiceChecksAreConditionalAndReportHealth(t *testing.T) {
	t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "false")
	t.Setenv("COMPOSE_PROFILES", "")
	checks := collectDoctorChecks(context.Background(), t.TempDir(), t.TempDir(), &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
	if findDoctorCheck(checks, "Xray lease service") != nil {
		t.Fatalf("disabled lease service produced checks: %+v", checks)
	}
	t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "true")
	previousProbe := leaseHealthProbe
	t.Cleanup(func() { leaseHealthProbe = previousProbe })
	var address string
	leaseHealthProbe = func(_ context.Context, got string) (leaseHealthStatus, error) {
		address = got
		return leaseHealthStatus{Ready: true}, nil
	}
	checks = collectDoctorChecks(context.Background(), t.TempDir(), t.TempDir(), &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Xray lease service", doctorPass) || address != "172.31.242.4:8091" {
		t.Fatalf("healthy lease service check/address = %+v, %q", findDoctorCheck(checks, "Xray lease service"), address)
	}
	leaseHealthProbe = func(context.Context, string) (leaseHealthStatus, error) {
		return leaseHealthStatus{}, nil
	}
	checks = collectDoctorChecks(context.Background(), t.TempDir(), t.TempDir(), &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "no-config"}}, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Xray lease service", doctorWarn) {
		t.Fatalf("lease service awaiting first-run setup was not a warning: %+v", findDoctorCheck(checks, "Xray lease service"))
	}
	leaseHealthProbe = func(context.Context, string) (leaseHealthStatus, error) {
		return leaseHealthStatus{}, nil
	}
	dataDir, configDir, _ := prepareDoctorState(t, true)
	checks = collectDoctorChecks(context.Background(), dataDir, configDir, &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Xray lease service", doctorFail) || !doctorCheckContains(checks, "Xray lease service", "telemetry is not ready") {
		notReady := findDoctorCheck(checks, "Xray lease service")
		if notReady == nil || !strings.Contains(notReady.detail, "not ready") {
			t.Fatalf("unready lease telemetry was not a failure: %+v", notReady)
		}
	}
	leaseHealthProbe = func(context.Context, string) (leaseHealthStatus, error) {
		return leaseHealthStatus{}, errors.New("connection refused")
	}
	checks = collectDoctorChecks(context.Background(), t.TempDir(), t.TempDir(), &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Xray lease service", doctorFail) {
		t.Fatalf("disconnected lease service was not a failure: %+v", findDoctorCheck(checks, "Xray lease service"))
	}
}

func TestLeaseServiceEnabledFromEnvironmentRecognizesComposeProfile(t *testing.T) {
	t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "false")
	for _, profiles := range []string{"lease", "awg,lease", "awg, lease ,custom"} {
		t.Setenv("COMPOSE_PROFILES", profiles)
		if !leaseServiceEnabledFromEnvironment() {
			t.Errorf("lease profile %q was not recognized", profiles)
		}
	}
	t.Setenv("COMPOSE_PROFILES", "awg,custom")
	if leaseServiceEnabledFromEnvironment() {
		t.Fatal("disabled service was enabled without the lease Compose profile")
	}
	t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "TRUE")
	if !leaseServiceEnabledFromEnvironment() {
		t.Fatal("enabled environment flag was ignored")
	}
}

func TestProbeLeaseServiceUsesGRPCReadiness(t *testing.T) {
	if _, err := probeLeaseService(context.Background(), "invalid"); err == nil || !strings.Contains(err.Error(), "address is invalid") {
		t.Fatalf("invalid health gRPC address error = %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	defer server.Stop()
	provider := health.NewServer()
	healthpb.RegisterHealthServer(server, provider)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Error("health gRPC server did not stop")
		}
	})
	provider.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	status, err := probeLeaseService(context.Background(), listener.Addr().String())
	if err != nil || !status.Ready {
		t.Fatalf("serving lease health=%+v error=%v", status, err)
	}
	provider.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	status, err = probeLeaseService(context.Background(), listener.Addr().String())
	if err != nil || status.Ready {
		t.Fatalf("not-serving lease health=%+v error=%v", status, err)
	}
}

func TestLeasePolicyFromEnvironmentValidatesAllDurations(t *testing.T) {
	t.Setenv("XRAY_LEASE_MAX_ACTIVE", "2")
	t.Setenv("XRAY_LEASE_GRACE", "30s")
	t.Setenv("XRAY_LEASE_RETRY_DELAY", "1s")
	config, err := leasePolicyFromEnvironment()
	if err != nil || config.MaxActiveLeases != 2 || config.GracePeriod != 30*time.Second {
		t.Fatalf("lease policy = %+v, %v", config, err)
	}
}

func TestLeasePolicyFromEnvironmentReturnsEachParseError(t *testing.T) {
	for _, test := range []struct {
		name  string
		key   string
		value string
	}{
		{name: "maximum active leases", key: "XRAY_LEASE_MAX_ACTIVE", value: "many"},
		{name: "grace period", key: "XRAY_LEASE_GRACE", value: "soon"},
		{name: "retry delay", key: "XRAY_LEASE_RETRY_DELAY", value: "later"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("XRAY_LEASE_MAX_ACTIVE", "2")
			t.Setenv("XRAY_LEASE_GRACE", "30s")
			t.Setenv("XRAY_LEASE_RETRY_DELAY", "1s")
			t.Setenv(test.key, test.value)
			if _, err := leasePolicyFromEnvironment(); err == nil {
				t.Fatalf("lease policy accepted invalid %s value %q", test.key, test.value)
			}
		})
	}
}

func TestDoctorRequiresEnabledTrojanInboundInActiveAndRuntimeState(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "10443")
	runtime := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}
	checks := collectDoctorChecks(context.Background(), dataDir, configDir, runtime, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Trojan inbound", doctorFail) {
		t.Fatalf("doctor accepted an enabled but missing Trojan inbound: %+v", checks)
	}
	if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte(`{"inbounds":[{"tag":"trojan-tls","protocol":"trojan"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.status.InboundTags = []string{"trojan-tls"}
	checks = collectDoctorChecks(context.Background(), dataDir, configDir, runtime, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Trojan inbound", doctorPass) {
		t.Fatalf("doctor rejected the enabled Trojan inbound present in active and runtime state: %+v", checks)
	}
}

func TestDoctorDefersTrojanInboundCheckUntilInitialSetup(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, false)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	checks := collectDoctorChecks(context.Background(), dataDir, configDir, &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "no-config"}}, &doctorHandlerStub{}, &doctorStatsStub{})
	if !hasDoctorCheck(checks, "Trojan inbound", doctorWarn) {
		t.Fatalf("doctor should defer Trojan validation until setup: %+v", checks)
	}
}

func hasDoctorCheck(checks []doctorCheck, name string, level doctorLevel) bool {
	return findDoctorCheck(checks, name) != nil && findDoctorCheck(checks, name).level == level
}

func findDoctorCheck(checks []doctorCheck, name string) *doctorCheck {
	for index := range checks {
		if checks[index].name == name {
			return &checks[index]
		}
	}
	return nil
}

func (s *doctorXrayRuntimeStub) Health(context.Context) error { return s.healthErr }

func (s *doctorXrayRuntimeStub) Status(context.Context) (domain.XrayRuntimeStatus, error) {
	return s.status, s.statusErr
}

func (s *doctorXrayRuntimeStub) Validate(ctx context.Context, path, operationID string) error {
	s.validateCall++
	s.validatePath = path
	s.validateID = operationID
	s.validateRev = interaction.StateRevision(ctx)
	return s.validateErr
}

func (s *doctorXrayRuntimeStub) ProbeTarget(context.Context, string, string) error {
	s.probeCall++
	return s.probeErr
}

func (s *doctorXrayRuntimeStub) ProbeIPv6(context.Context) error {
	s.ipv6Call++
	return s.ipv6Err
}

func (s *doctorXrayRuntimeStub) Logs(context.Context) ([]string, error) {
	return s.logs, s.logsErr
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

type doctorAWGStub struct {
	status    domain.AmneziaWGStatus
	peers     []domain.AmneziaWGPeer
	statusErr error
	peersErr  error
}

func (s *doctorAWGStub) Status(context.Context) (domain.AmneziaWGStatus, error) {
	return s.status, s.statusErr
}

func (s *doctorAWGStub) ListPeers(context.Context) ([]domain.AmneziaWGPeer, error) {
	return s.peers, s.peersErr
}

func (s *doctorStatsStub) Poll(context.Context) ([]xrayapi.UserStats, error) {
	s.calls++
	return nil, s.err
}

func TestDoctorPassesFreshInstallAndWarnsSetupPending(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, false)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_EASY_VERSION", "0.4.1-abc123")
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	tokenPath := writeControllerToken(t, 0o400)
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	sup := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}
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
	if !strings.Contains(output.String(), "Xray-easy build: 0.4.1-abc123 (XRAY_EASY_VERSION)") || !strings.Contains(output.String(), "Xray image: 26.7.28 (XRAY_VERSION)") || !strings.Contains(output.String(), "Xray public TCP: 443 -> container TCP 8443") || !strings.Contains(output.String(), "Web UI loopback: 8080 -> container TCP 8080") {
		t.Fatalf("doctor header omitted active versions or ports: %s", output.String())
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

func TestDoctorHeaderRejectsInvalidEnvironmentText(t *testing.T) {
	t.Setenv("XRAY_EASY_VERSION", "secret\nInjected output")
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("XRAY_PUBLIC_PORT", "443\nXRAY_EASY_MASTER_KEY=secret")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	var output bytes.Buffer
	writeDoctorHeader(&output)
	if strings.Contains(output.String(), "Injected output") || strings.Contains(output.String(), "XRAY_EASY_MASTER_KEY=secret") || !strings.Contains(output.String(), "Xray-easy build: invalid") || !strings.Contains(output.String(), "Xray public TCP: invalid") {
		t.Fatalf("doctor header included unsafe environment text: %s", output.String())
	}
}

func TestDoctorBundleContainsRedactedReportStatusLogsAndConfig(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, false)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_EASY_VERSION", "v0.4.1-12-gabc123")
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("XRAY_PUBLIC_PORT", "4443")
	t.Setenv("XRAY_EASY_UI_PORT", "9080")
	activeConfig := `{"inbounds":[{"port":8443,"settings":{"clients":[{"id":"123e4567-e89b-12d3-a456-426614174000","email":"private-device-name","flow":"xtls-rprx-vision"}]},"streamSettings":{"realitySettings":{"privateKey":"raw-private-key","shortIds":["raw-short-id"]}}}]}`
	if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte(activeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	sup := &doctorXrayRuntimeStub{
		status: domain.XrayRuntimeStatus{State: "running", LastError: "privateKey=raw-status-secret"},
		logs:   []string{`level=error privateKey=raw-log-secret id=123e4567-e89b-12d3-a456-426614174000`},
	}
	var output bytes.Buffer
	if err := runDoctorBundle(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err != nil {
		t.Fatalf("create doctor bundle: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "Xray-easy build: v0.4.1-12-gabc123") || !strings.Contains(output.String(), "Xray public TCP: 4443") || !strings.Contains(output.String(), "Web UI loopback: 9080") {
		t.Fatalf("bundle report omitted configured metadata: %s", output.String())
	}
	path := strings.TrimSpace(strings.Split(output.String(), "Bundle saved: ")[1])
	if lineEnd := strings.IndexByte(path, '\n'); lineEnd >= 0 {
		path = path[:lineEnd]
	}
	archive, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	info, err := archive.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %o, want 600", info.Mode().Perm())
	}
	gz, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tarReader := tar.NewReader(gz)
	entries := make(map[string]string)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = string(contents)
	}
	for _, name := range []string{"doctor-report.txt", "xray-status.json", "xray-errors.log", "active-config.redacted.json"} {
		if _, ok := entries[name]; !ok {
			t.Errorf("bundle is missing %s", name)
		}
	}
	for _, rawSecret := range []string{"raw-private-key", "raw-short-id", "raw-status-secret", "raw-log-secret", "123e4567-e89b-12d3-a456-426614174000", "private-device-name"} {
		for name, contents := range entries {
			if strings.Contains(contents, rawSecret) {
				t.Errorf("bundle file %s leaked %q", name, rawSecret)
			}
		}
	}
	var redactedConfig map[string]any
	if err := json.Unmarshal([]byte(entries["active-config.redacted.json"]), &redactedConfig); err != nil {
		t.Fatalf("redacted active config is invalid JSON: %v", err)
	}
}

func TestDoctorReportsUnavailableEmbeddedTelemetryAsWarning(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_VERSION", "26.7.28")
	tokenPath := writeControllerToken(t, 0o400)
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	sup := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28"}}
	handler := &doctorHandlerStub{}
	stats := &doctorStatsStub{err: errors.New("runtime telemetry unavailable")}
	var output bytes.Buffer

	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, handler, stats)
	if err != nil {
		t.Fatalf("unsupported statistics RPC should not fail installation: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "WARN  Embedded Xray telemetry: runtime telemetry could not be read") || !strings.Contains(output.String(), "Result: PASS (") {
		t.Fatalf("unavailable runtime telemetry was not reported as a warning: %s", output.String())
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

func TestDoctorReportsEmbeddedRuntimeDiagnostics(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("AWG_PUBLIC_HOST", "")
	activeConfig := `{"inbounds":[{"tag":"vless-reality","protocol":"vless"},{"tag":"vmess-tls","protocol":"vmess"},{"tag":"ignored","protocol":"dokodemo-door"}]}`
	if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte(activeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	sup := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{
		Protocol: "embedded-core", XrayVersion: "Xray 26.7.28", State: "running",
		ActiveRevision: 12, InboundTags: []string{"vmess-tls", "vless-reality"}, StatsAvailable: true,
	}}
	var output bytes.Buffer
	if err := runDoctor(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err != nil {
		t.Fatalf("runDoctor() = %v\n%s", err, output.String())
	}
	for _, check := range []string{"PASS  Embedded Xray runtime", "PASS  Embedded config revision", "PASS  Embedded inbound tags", "PASS  Embedded statistics capability"} {
		if !strings.Contains(output.String(), check) {
			t.Errorf("doctor output omits %q:\n%s", check, output.String())
		}
	}
	if len(sup.validateID) != 32 {
		t.Fatalf("config validation operation ID has length %d, want a 128-bit hex ID", len(sup.validateID))
	}
	if _, err := hex.DecodeString(sup.validateID); err != nil {
		t.Fatalf("config validation operation ID is not hexadecimal: %q", sup.validateID)
	}
	if sup.validateRev != 12 {
		t.Fatalf("config validation revision = %d, want active revision 12", sup.validateRev)
	}
	sup.status.ActiveRevision = 0
	var legacyOutput bytes.Buffer
	if err := runDoctor(context.Background(), dataDir, configDir, &legacyOutput, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err != nil {
		t.Fatalf("runDoctor() with a runtime that has no revision: %v\n%s", err, legacyOutput.String())
	}
	if sup.validateRev != 1 {
		t.Fatalf("config validation revision without an active revision = %d, want positive sentinel 1", sup.validateRev)
	}
}

func TestMatchEmbeddedInboundTags(t *testing.T) {
	for _, test := range []struct {
		name          string
		configuration string
		runtimeTags   []string
		wantError     bool
	}{
		{name: "matching supported tags", configuration: `{"inbounds":[{"tag":"vless","protocol":"vless"},{"tag":"vmess","protocol":"vmess"},{"tag":"hysteria","protocol":"hysteria"},{"tag":"shadowsocks","protocol":"shadowsocks"},{"tag":"trojan-tls","protocol":"trojan"},{"tag":"ignored","protocol":"dokodemo-door"}]}`, runtimeTags: []string{"hysteria", "vless", "vmess", "shadowsocks", "trojan-tls"}},
		{name: "different tags", configuration: `{"inbounds":[{"tag":"vless","protocol":"vless"}]}`, runtimeTags: []string{"wrong"}, wantError: true},
		{name: "duplicate configured tag", configuration: `{"inbounds":[{"tag":"vless","protocol":"vless"},{"tag":"vless","protocol":"vmess"}]}`, runtimeTags: []string{"vless"}, wantError: true},
		{name: "duplicate runtime tag", configuration: `{"inbounds":[{"tag":"vless","protocol":"vless"}]}`, runtimeTags: []string{"vless", "vless"}, wantError: true},
		{name: "empty supported tag", configuration: `{"inbounds":[{"protocol":"vless"}]}`, wantError: true},
		{name: "invalid json", configuration: `{`, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "active.json")
			if err := os.WriteFile(path, []byte(test.configuration), 0o600); err != nil {
				t.Fatal(err)
			}
			err := matchEmbeddedInboundTags(path, test.runtimeTags)
			if (err != nil) != test.wantError {
				t.Fatalf("matchEmbeddedInboundTags() error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
	if err := matchEmbeddedInboundTags(filepath.Join(t.TempDir(), "missing.json"), nil); err == nil {
		t.Fatal("missing active config was accepted")
	}
}

func TestActiveConfigHasInbound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"tag":"trojan-tls","protocol":"trojan"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		protocol string
		tag      string
		want     bool
	}{{"trojan", "trojan-tls", true}, {"trojan", "wrong", false}, {"vless", "trojan-tls", false}} {
		got, err := activeConfigHasInbound(path, test.protocol, test.tag)
		if err != nil || got != test.want {
			t.Errorf("activeConfigHasInbound(%q, %q) = %t, %v; want %t", test.protocol, test.tag, got, err, test.want)
		}
	}
	if _, err := activeConfigHasInbound(filepath.Join(t.TempDir(), "missing.json"), "trojan", "trojan-tls"); err == nil {
		t.Fatal("missing active config was accepted")
	}
}

func TestXrayVersionVerifiedRequiresConfiguredAndRunningBinary(t *testing.T) {
	if !xrayVersionVerified("Xray 26.7.28 (Xray, Penetrates Everything.)", "26.7.28") {
		t.Fatal("verified runtime and configured version were marked experimental")
	}
	for _, versions := range [][2]string{{"Xray 26.7.28", "26.9.8"}, {"Xray 26.9.8", "26.7.28"}, {"unknown", "26.7.28"}} {
		if xrayVersionVerified(versions[0], versions[1]) {
			t.Errorf("runtime=%q configured=%q were marked verified", versions[0], versions[1])
		}
	}
}

func TestDoctorReportsIPv6EgressFailureAsWarning(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	sup := &doctorXrayRuntimeStub{
		status:  domain.XrayRuntimeStatus{State: "running"},
		ipv6Err: errors.New("private network diagnostic detail"),
	}
	var output bytes.Buffer
	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{})
	if err != nil {
		t.Fatalf("IPv6 egress failure must remain a warning: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "WARN  IPv6 egress: outbound IPv6 TCP probe failed") || strings.Contains(output.String(), "private network diagnostic detail") {
		t.Fatalf("IPv6 warning was missing or leaked details: %s", output.String())
	}
	if sup.ipv6Call != 1 {
		t.Fatalf("IPv6 probe count = %d, want 1", sup.ipv6Call)
	}
}

func TestDoctorReportsIPv6PublicHostType(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "2001:db8::1"
	if err := db.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	var output bytes.Buffer
	if err := runDoctor(context.Background(), dataDir, configDir, &output, &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}, &doctorHandlerStub{}, &doctorStatsStub{}); err != nil {
		t.Fatalf("doctor failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "PASS  Public host: IPv6 literal configured") {
		t.Fatalf("doctor omitted the IPv6 public-host type: %s", output.String())
	}
}

func TestDoctorFailureDoesNotPrintSecrets(t *testing.T) {
	dataDir, configDir, _ := prepareDoctorState(t, false)
	secretValue := "private-master-key-material"
	t.Setenv("XRAY_EASY_MASTER_KEY", secretValue)
	tokenPath := writeControllerToken(t, 0o600)
	t.Setenv("XRAY_CONTROLLER_ADDR", "controller.test:10088")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	sup := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}
	var output bytes.Buffer

	err := runDoctor(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{})
	if err == nil {
		t.Fatal("invalid master key and secret permissions should fail doctor")
	}
	if strings.Contains(output.String(), secretValue) || strings.Contains(output.String(), "controller-secret-should-not-leak") {
		t.Fatalf("doctor output leaked secret material: %s", output.String())
	}
	if strings.Contains(output.String(), "mode is 0400") || !strings.Contains(output.String(), "expected mode 0400") {
		t.Fatalf("incorrect Controller secret mode was not diagnosed: %s", output.String())
	}
}

func TestDoctorFailsWhenRealityTargetCannotBeReached(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	sup := &doctorXrayRuntimeStub{
		status:   domain.XrayRuntimeStatus{State: "running"},
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
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_PUBLIC_PORT", "not-a-port")
	var output bytes.Buffer
	err := runDoctor(context.Background(), dataDir, configDir, &output, &doctorXrayRuntimeStub{}, &doctorHandlerStub{}, &doctorStatsStub{})
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

func writeControllerToken(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(path, []byte("controller-secret-should-not-leak\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

var _ doctorXrayRuntime = (*doctorXrayRuntimeStub)(nil)
var _ doctorHandler = (*doctorHandlerStub)(nil)
var _ doctorStats = (*doctorStatsStub)(nil)
