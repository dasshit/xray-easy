package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	"xray-easy/internal/lease"
)

type fakeHealthProvider struct {
	ready bool
}

func (f fakeHealthProvider) Ready() bool { return f.ready }

type fakeLeaseWorker struct {
	run func(context.Context) error
}

func (fakeLeaseWorker) Ready() bool { return false }
func (f fakeLeaseWorker) Run(ctx context.Context) error {
	return f.run(ctx)
}

func TestReadConfigDefaultsAndOverrides(t *testing.T) {
	for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
		t.Setenv(name, "")
	}
	config, err := readConfig()
	if err != nil || config.MaxActiveLeases != 2 || config.GracePeriod != 30*time.Second || config.RetryDelay != time.Second {
		t.Fatalf("default config = %+v, %v", config, err)
	}
	t.Setenv("XRAY_LEASE_MAX_ACTIVE", "2")
	t.Setenv("XRAY_LEASE_GRACE", "45s")
	t.Setenv("XRAY_LEASE_RETRY_DELAY", "2s")
	config, err = readConfig()
	if err != nil || config.GracePeriod != 45*time.Second || config.RetryDelay != 2*time.Second {
		t.Fatalf("overridden config = %+v, %v", config, err)
	}
}

func TestReadConfigRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"max active", "3", "maximum active leases must be 2"},
		{"bad max active", "two", "XRAY_LEASE_MAX_ACTIVE"},
		{"bad grace", "soon", "XRAY_LEASE_GRACE"},
		{"bad retry delay", "again", "XRAY_LEASE_RETRY_DELAY"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
				t.Setenv(name, "")
			}
			name := "XRAY_LEASE_GRACE"
			switch test.name {
			case "max active", "bad max active":
				name = "XRAY_LEASE_MAX_ACTIVE"
			case "bad retry delay":
				name = "XRAY_LEASE_RETRY_DELAY"
			}
			t.Setenv(name, test.value)
			if _, err := readConfig(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readConfig error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestUpdateLeaseReadinessOnlyServesUsableSnapshots(t *testing.T) {
	server := health.NewServer()
	for _, test := range []struct {
		name  string
		owner healthProvider
		want  healthpb.HealthCheckResponse_ServingStatus
	}{
		{name: "nil worker", want: healthpb.HealthCheckResponse_NOT_SERVING},
		{name: "connected without a usable snapshot", owner: fakeHealthProvider{}, want: healthpb.HealthCheckResponse_NOT_SERVING},
		{name: "ready", owner: fakeHealthProvider{ready: true}, want: healthpb.HealthCheckResponse_SERVING},
	} {
		t.Run(test.name, func(t *testing.T) {
			updateLeaseReadiness(test.owner, server)
			response, err := server.Check(context.Background(), &healthpb.HealthCheckRequest{})
			if err != nil || response.GetStatus() != test.want {
				t.Fatalf("gRPC health = %v, %v; want %v", response.GetStatus(), err, test.want)
			}
		})
	}
}

func TestRunRejectsUnknownArgumentsAndEnvOr(t *testing.T) {
	if err := run([]string{"unexpected"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("invalid command error = %v", err)
	}
	t.Setenv("XRAY_LEASE_TEST_VALUE", " configured ")
	if got := envOr("XRAY_LEASE_TEST_VALUE", "fallback"); got != "configured" {
		t.Fatalf("envOr configured = %q", got)
	}
	t.Setenv("XRAY_LEASE_TEST_VALUE", "  ")
	if got := envOr("XRAY_LEASE_TEST_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOr fallback = %q", got)
	}
}

func TestRunReportsControllerTokenAndConfigurationErrors(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_ADDR", "127.0.0.1:10088")
	t.Setenv("XRAY_LEASE_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-token"))
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "read Controller token") {
		t.Fatalf("missing token error = %v", err)
	}
	tokenPath := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(tokenPath, []byte("lease-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LEASE_TOKEN_FILE", tokenPath)
	t.Setenv("XRAY_LEASE_MAX_ACTIVE", "3")
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "maximum active leases must be 2") {
		t.Fatalf("invalid policy error = %v", err)
	}
}

func TestRunHealthcheckAndMainDispatch(t *testing.T) {
	previousProbe := leaseHealthCheck
	previousArgs := os.Args
	previousLogger := slog.Default()
	previousExit := exitProcess
	t.Cleanup(func() {
		leaseHealthCheck = previousProbe
		os.Args = previousArgs
		slog.SetDefault(previousLogger)
		exitProcess = previousExit
	})
	called := ""
	leaseHealthCheck = func(address string) error {
		called = address
		return nil
	}
	if err := run([]string{"healthcheck"}); err != nil || called != defaultHealthCheck {
		t.Fatalf("healthcheck dispatch address=%q error=%v", called, err)
	}
	leaseHealthCheck = func(string) error { return errors.New("unhealthy") }
	if err := run([]string{"healthcheck"}); err == nil || err.Error() != "unhealthy" {
		t.Fatalf("healthcheck error=%v", err)
	}
	leaseHealthCheck = func(string) error { return nil }
	os.Args = []string{"xray-lease-service", "healthcheck"}
	exitCode := 0
	exitProcess = func(code int) { exitCode = code }
	main()
	if exitCode != 0 {
		t.Fatalf("successful main exit code = %d", exitCode)
	}
	os.Args = []string{"xray-lease-service", "unexpected"}
	main()
	if exitCode != 1 {
		t.Fatalf("failed main exit code = %d", exitCode)
	}
}

func TestRunReturnsHealthListenerFailureAndCheckHealthUsesGRPC(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(tokenPath, []byte("lease-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///127.0.0.1:10088")
	t.Setenv("XRAY_LEASE_TOKEN_FILE", tokenPath)
	t.Setenv("XRAY_LEASE_GRPC_LISTEN", "invalid address")
	for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
		t.Setenv(name, "")
	}
	err := run(nil)
	if err == nil || !strings.Contains(err.Error(), "listen for lease health gRPC") {
		t.Fatalf("health listener failure = %v", err)
	}
	if err := checkHealth("invalid"); err == nil || !strings.Contains(err.Error(), "address is invalid") {
		t.Fatalf("invalid health gRPC address error = %v", err)
	}
}

func TestCheckHealthFollowsStandardGRPCReadiness(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Error("health gRPC server did not stop")
		}
	})
	address := listener.Addr().String()
	if err := checkHealth(address); err == nil || !strings.Contains(err.Error(), "NOT_SERVING") {
		t.Fatalf("not-serving health check = %v", err)
	}
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	if err := checkHealth(address); err != nil {
		t.Fatalf("serving health check = %v", err)
	}
}

func configureLeaseRun(t *testing.T) {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(tokenPath, []byte("lease-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///127.0.0.1:10088")
	t.Setenv("XRAY_LEASE_TOKEN_FILE", tokenPath)
	t.Setenv("XRAY_LEASE_GRPC_LISTEN", "127.0.0.1:0")
	for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
		t.Setenv(name, "")
	}
}

func TestRunCoversWorkerFactoryAndWorkerExitResults(t *testing.T) {
	previousFactory, previousServer, previousListener := newLeaseWorker, runLeaseHealthServer, listenLeaseHealth
	previousSignal := leaseSignalContext
	t.Cleanup(func() {
		newLeaseWorker, runLeaseHealthServer, listenLeaseHealth, leaseSignalContext = previousFactory, previousServer, previousListener, previousSignal
	})
	configureLeaseRun(t)

	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return nil, errors.New("worker initialization failed")
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "initialize lease policy") {
		t.Fatalf("worker initialization failure = %v", err)
	}

	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return fakeLeaseWorker{run: func(context.Context) error { return errors.New("worker crashed") }}, nil
	}
	listenLeaseHealth = func(string, string) (net.Listener, error) { return bufconn.Listen(1024), nil }
	runLeaseHealthServer = func(*grpc.Server, net.Listener) error {
		return errors.New("injected serve failure")
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "worker crashed") {
		t.Fatalf("worker failure = %v", err)
	}

	runLeaseHealthServer = func(*grpc.Server, net.Listener) error { return grpc.ErrServerStopped }
	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return fakeLeaseWorker{run: func(context.Context) error { return context.Canceled }}, nil
	}
	if err := run(nil); err != nil {
		t.Fatalf("worker cancellation = %v", err)
	}

	for _, test := range []struct {
		name string
		in   error
		want string
	}{
		{name: "unexpected nil", want: "stopped unexpectedly"},
		{name: "canceled", in: context.Canceled},
		{name: "failure", in: errors.New("failed"), want: "lease policy worker stopped"},
	} {
		t.Run("worker exit "+test.name, func(t *testing.T) {
			err := leaseWorkerExitError(test.in)
			if test.want == "" && err != nil || test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("leaseWorkerExitError(%v) = %v, want %q", test.in, err, test.want)
			}
		})
	}
}

func TestRunCoversHealthServerClosedAndSignalShutdown(t *testing.T) {
	previousFactory, previousServer, previousListener := newLeaseWorker, runLeaseHealthServer, listenLeaseHealth
	previousSignal := leaseSignalContext
	t.Cleanup(func() {
		newLeaseWorker, runLeaseHealthServer, listenLeaseHealth, leaseSignalContext = previousFactory, previousServer, previousListener, previousSignal
	})
	configureLeaseRun(t)
	listenLeaseHealth = func(string, string) (net.Listener, error) { return bufconn.Listen(1024), nil }
	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return fakeLeaseWorker{run: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}}, nil
	}
	runLeaseHealthServer = func(*grpc.Server, net.Listener) error { return grpc.ErrServerStopped }
	if err := run(nil); err != nil {
		t.Fatalf("closed health server = %v", err)
	}

	leaseSignalContext = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	runLeaseHealthServer = func(*grpc.Server, net.Listener) error { return grpc.ErrServerStopped }
	if err := run(nil); err != nil {
		t.Fatalf("signal shutdown = %v", err)
	}
}

func TestDefaultLeaseAdapters(t *testing.T) {
	if _, err := defaultNewLeaseWorker(nil, lease.DefaultConfig(), slog.Default()); err == nil {
		t.Fatal("default worker factory accepted a missing Controller client")
	}
	ctx, cancel := defaultLeaseSignalContext()
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal context did not cancel")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := defaultRunLeaseHealthServer(grpc.NewServer(), listener); err == nil {
		t.Fatal("default gRPC health server accepted a closed listener")
	}
}
