package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/lease"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type fakeHealthProvider struct {
	ready     bool
	connected bool
}

func (f fakeHealthProvider) Ready() bool           { return f.ready }
func (f fakeHealthProvider) StreamConnected() bool { return f.connected }

type fakeLeaseWorker struct {
	run func(context.Context) error
}

func (fakeLeaseWorker) Ready() bool           { return false }
func (fakeLeaseWorker) StreamConnected() bool { return true }
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

func TestHealthHandlerReportsStreamReadinessAndRejectsOtherRequests(t *testing.T) {
	tests := []struct {
		name       string
		provider   healthProvider
		method     string
		path       string
		statusCode int
		body       string
	}{
		{"ready", fakeHealthProvider{ready: true, connected: true}, http.MethodGet, "/healthz", http.StatusOK, `"ready":true`},
		{"connected while awaiting first Xray config", fakeHealthProvider{connected: true}, http.MethodGet, "/healthz", http.StatusOK, `"controllerStreamConnected":true`},
		{"controller disconnected", fakeHealthProvider{}, http.MethodGet, "/healthz", http.StatusServiceUnavailable, `"controllerStreamConnected":false`},
		{"wrong path", fakeHealthProvider{connected: true}, http.MethodGet, "/other", http.StatusNotFound, ""},
		{"wrong method", fakeHealthProvider{connected: true}, http.MethodPost, "/healthz", http.StatusNotFound, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()
			newHealthHandler(test.provider).ServeHTTP(response, request)
			if response.Code != test.statusCode || !strings.Contains(response.Body.String(), test.body) {
				t.Fatalf("health response = %d %q", response.Code, response.Body.String())
			}
		})
	}
}

func TestCheckHealthWithClient(t *testing.T) {
	for _, test := range []struct {
		name         string
		statusCode   int
		body         string
		transportErr error
		want         string
	}{
		{name: "healthy", statusCode: http.StatusOK},
		{name: "unhealthy", statusCode: http.StatusServiceUnavailable, body: "controller down", want: "controller down"},
		{name: "transport failure", transportErr: errors.New("offline"), want: "health request failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				return &http.Response{StatusCode: test.statusCode, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}
			err := checkHealthWithClient("127.0.0.1:8091", client)
			if test.want == "" && err != nil {
				t.Fatalf("health check error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("health check error = %v, want %q", err, test.want)
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

func TestRunReturnsHealthServerFailureAndCheckHealthUsesHTTP(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(tokenPath, []byte("lease-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///127.0.0.1:10088")
	t.Setenv("XRAY_LEASE_TOKEN_FILE", tokenPath)
	t.Setenv("XRAY_LEASE_HEALTH_ADDR", "invalid address")
	for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
		t.Setenv(name, "")
	}
	err := run(nil)
	if err == nil || !strings.Contains(err.Error(), "lease service health server") {
		t.Fatalf("health server failure = %v", err)
	}
	if err := checkHealth("127.0.0.1:0"); err == nil || !strings.Contains(err.Error(), "health request failed") {
		t.Fatalf("unreachable health endpoint error = %v", err)
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
	t.Setenv("XRAY_LEASE_HEALTH_ADDR", "127.0.0.1:0")
	for _, name := range []string{"XRAY_LEASE_MAX_ACTIVE", "XRAY_LEASE_GRACE", "XRAY_LEASE_RETRY_DELAY"} {
		t.Setenv(name, "")
	}
}

func TestRunCoversWorkerFactoryAndWorkerExitResults(t *testing.T) {
	previousFactory, previousServer := newLeaseWorker, runLeaseHealthServer
	previousSignal := leaseSignalContext
	t.Cleanup(func() {
		newLeaseWorker, runLeaseHealthServer, leaseSignalContext = previousFactory, previousServer, previousSignal
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
	runLeaseHealthServer = func(*http.Server) error {
		time.Sleep(20 * time.Millisecond)
		return http.ErrServerClosed
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "worker crashed") {
		t.Fatalf("worker failure = %v", err)
	}

	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return fakeLeaseWorker{run: func(context.Context) error { return context.Canceled }}, nil
	}
	if err := run(nil); err != nil {
		t.Fatalf("worker cancellation = %v", err)
	}
}

func TestRunCoversHealthServerClosedAndSignalShutdown(t *testing.T) {
	previousFactory, previousServer := newLeaseWorker, runLeaseHealthServer
	previousSignal := leaseSignalContext
	t.Cleanup(func() {
		newLeaseWorker, runLeaseHealthServer, leaseSignalContext = previousFactory, previousServer, previousSignal
	})
	configureLeaseRun(t)
	newLeaseWorker = func(lease.Controller, lease.Config, *slog.Logger) (leaseServiceWorker, error) {
		return fakeLeaseWorker{run: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}}, nil
	}
	runLeaseHealthServer = func(*http.Server) error { return http.ErrServerClosed }
	if err := run(nil); err != nil {
		t.Fatalf("closed health server = %v", err)
	}

	leaseSignalContext = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	runLeaseHealthServer = func(*http.Server) error {
		time.Sleep(20 * time.Millisecond)
		return http.ErrServerClosed
	}
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
	if err := defaultRunLeaseHealthServer(&http.Server{Addr: "invalid address"}); err == nil {
		t.Fatal("default health server accepted an invalid address")
	}
}
