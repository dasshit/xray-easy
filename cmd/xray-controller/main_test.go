package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"xray-easy/internal/controller"
	"xray-easy/internal/supervisor"
)

type fakeHealthClient struct{ err error }

func (f *fakeHealthClient) Health(context.Context) error { return f.err }
func (*fakeHealthClient) Close() error                   { return nil }

type fakeAWGRuntime struct {
	controller.AmneziaWGRuntime
	closed bool
}

func (f *fakeAWGRuntime) Close() error { f.closed = true; return nil }

type fakeEmbeddedXray struct {
	controller.XrayRuntime
	controller.XrayHandlerRuntime
	controller.XrayStatsRuntime
	closed bool
}

func (f *fakeEmbeddedXray) Close() error { f.closed = true; return nil }

func TestRunDispatchAndHealthcheck(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("serve unexpectedly returned nil without setup")
	}
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("unknown command was accepted")
	}
	oldDial := dialHealthClient
	dialHealthClient = func(address, token string) (healthClient, error) {
		if address != defaultListenAddr || token != defaultControllerToken {
			t.Fatalf("healthcheck config = %q %q", address, token)
		}
		return &fakeHealthClient{}, nil
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", "")
	if err := run([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	dialHealthClient = func(string, string) (healthClient, error) { return nil, errors.New("unavailable") }
	if err := run([]string{"healthcheck"}); err == nil {
		t.Fatal("healthcheck dial error was ignored")
	}
	dialHealthClient = oldDial
}

func TestReadToken(t *testing.T) {
	if _, err := readToken(" "); err == nil {
		t.Fatal("empty token path accepted")
	}
	if _, err := readToken(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing token accepted")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("blank token accepted")
	}
	if err := os.WriteFile(path, []byte(" token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readToken(path); err != nil || got != "token" {
		t.Fatalf("readToken() = %q, %v", got, err)
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("CONTROLLER_TEST_VALUE", "  chosen ")
	if got := envOr("CONTROLLER_TEST_VALUE", "fallback"); got != "chosen" {
		t.Fatalf("envOr() = %q", got)
	}
	t.Setenv("CONTROLLER_TEST_VALUE", "  ")
	if got := envOr("CONTROLLER_TEST_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOr(empty) = %q", got)
	}
}

func TestServeValidationListenerAndShutdown(t *testing.T) {
	dir := t.TempDir()
	controllerToken := filepath.Join(dir, "controller-token")
	if err := os.WriteFile(controllerToken, []byte("controller-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", controllerToken)
	t.Setenv("XRAY_ADAPTER", "supervisor")
	t.Setenv("XRAY_SUPERVISOR_ADDR", "127.0.0.1:10086")
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", filepath.Join(dir, "supervisor-token"))
	t.Setenv("XRAY_CONTROLLER_LISTEN", "127.0.0.1:0")
	oldListener, oldSignals, oldServe := listenController, controllerSignalContext, serveController
	defer func() { listenController, controllerSignalContext, serveController = oldListener, oldSignals, oldServe }()
	listenController = func(string, string) (net.Listener, error) { return nil, errors.New("listen failure") }
	if err := serve(); err == nil {
		t.Fatal("listener failure was ignored")
	}
	listenController = func(string, string) (net.Listener, error) { return bufconn.Listen(1024), nil }
	controllerSignalContext = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	if err := serve(); err != nil {
		t.Fatalf("serve graceful shutdown: %v", err)
	}
	serveController = func(*grpc.Server, net.Listener) error { return grpc.ErrServerStopped }
	controllerSignalContext = func() (context.Context, context.CancelFunc) { return context.Background(), func() {} }
	if err := serve(); err != nil {
		t.Fatalf("serve stopped server: %v", err)
	}
	serveController = func(*grpc.Server, net.Listener) error { return errors.New("serve failure") }
	if err := serve(); err == nil {
		t.Fatal("serve error was ignored")
	}
}

func TestServeRejectsInvalidSupervisorAddress(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "controller-token")
	if err := os.WriteFile(token, []byte("controller-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", token)
	t.Setenv("XRAY_ADAPTER", "supervisor")
	t.Setenv("XRAY_SUPERVISOR_ADDR", "invalid")
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", filepath.Join(dir, "supervisor-token"))
	if err := serve(); err == nil {
		t.Fatal("invalid supervisor address accepted")
	}
}

func TestServeRejectsMissingControllerToken(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if err := serve(); err == nil {
		t.Fatal("missing Controller token was accepted")
	}
}

func TestServeRejectsSupervisorAndAWGAdapterFailures(t *testing.T) {
	dir := t.TempDir()
	controllerToken := filepath.Join(dir, "controller-token")
	supervisorToken := filepath.Join(dir, "supervisor-token")
	for path, value := range map[string]string{controllerToken: "controller-secret", supervisorToken: "supervisor-secret"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", controllerToken)
	t.Setenv("XRAY_ADAPTER", "supervisor")
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", supervisorToken)
	t.Setenv("XRAY_SUPERVISOR_ADDR", "127.0.0.1:10086")
	oldDialSupervisor, oldDialAWG := dialSupervisor, dialAWG
	defer func() { dialSupervisor, dialAWG = oldDialSupervisor, oldDialAWG }()
	dialSupervisor = func(string, string) (*supervisor.Client, error) { return nil, errors.New("supervisor unavailable") }
	if err := serve(); err == nil {
		t.Fatal("supervisor adapter failure was ignored")
	}
	dialSupervisor = oldDialSupervisor
	dialAWG = func(string, string) (closeableAWGRuntime, error) { return nil, errors.New("AWG unavailable") }
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	if err := serve(); err == nil {
		t.Fatal("AWG adapter failure was ignored")
	}
}

func TestServeClosesConfiguredAWGAdapterOnShutdown(t *testing.T) {
	dir := t.TempDir()
	controllerToken := filepath.Join(dir, "controller-token")
	supervisorToken := filepath.Join(dir, "supervisor-token")
	for path, value := range map[string]string{controllerToken: "controller-secret", supervisorToken: "supervisor-secret"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", controllerToken)
	t.Setenv("XRAY_ADAPTER", "supervisor")
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", supervisorToken)
	t.Setenv("XRAY_SUPERVISOR_ADDR", "127.0.0.1:10086")
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	oldListener, oldSignals, oldAWG := listenController, controllerSignalContext, dialAWG
	defer func() { listenController, controllerSignalContext, dialAWG = oldListener, oldSignals, oldAWG }()
	listener := bufconn.Listen(1024)
	listenController = func(string, string) (net.Listener, error) { return listener, nil }
	controllerSignalContext = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	adapter := &fakeAWGRuntime{}
	dialAWG = func(string, string) (closeableAWGRuntime, error) { return adapter, nil }
	if err := serve(); err != nil {
		t.Fatalf("serve with optional AWG adapter: %v", err)
	}
	if !adapter.closed {
		t.Fatal("Controller did not close its AWG adapter")
	}
}

func TestServeUsesEmbeddedXrayAdapterAndClosesItOnShutdown(t *testing.T) {
	dir := t.TempDir()
	controllerToken := filepath.Join(dir, "controller-token")
	runtimeToken := filepath.Join(dir, "xray-runtime-token")
	for path, value := range map[string]string{controllerToken: "controller-secret", runtimeToken: "runtime-secret"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", controllerToken)
	t.Setenv("XRAY_ADAPTER", "embedded")
	t.Setenv("XRAY_RUNTIME_ADDR", "127.0.0.1:10086")
	t.Setenv("XRAY_RUNTIME_TOKEN_FILE", runtimeToken)
	t.Setenv("XRAY_CONFIG_DIR", filepath.Join(dir, "config"))
	oldListener, oldSignals, oldDial := listenController, controllerSignalContext, dialEmbeddedXray
	defer func() { listenController, controllerSignalContext, dialEmbeddedXray = oldListener, oldSignals, oldDial }()
	listenController = func(string, string) (net.Listener, error) { return bufconn.Listen(1024), nil }
	controllerSignalContext = func() (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, cancel
	}
	adapter := &fakeEmbeddedXray{}
	dialEmbeddedXray = func(address, token, configDir string) (closeableXrayRuntime, error) {
		if address != "127.0.0.1:10086" || token != runtimeToken || configDir != filepath.Join(dir, "config") {
			t.Fatalf("embedded Xray adapter config = %q %q %q", address, token, configDir)
		}
		return adapter, nil
	}
	if err := serve(); err != nil {
		t.Fatalf("serve with embedded Xray adapter: %v", err)
	}
	if !adapter.closed {
		t.Fatal("Controller did not close the embedded Xray adapter")
	}
}

func TestServeRejectsUnknownXrayAdapter(t *testing.T) {
	token := filepath.Join(t.TempDir(), "controller-token")
	if err := os.WriteFile(token, []byte("controller-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", token)
	t.Setenv("XRAY_ADAPTER", "unknown")
	if err := serve(); err == nil {
		t.Fatal("unknown Xray adapter was accepted")
	}
}

func TestMainExitBehavior(t *testing.T) {
	oldArgs, oldExit := os.Args, exitProcess
	defer func() { os.Args, exitProcess = oldArgs, oldExit }()
	exitCode := 0
	exitProcess = func(code int) { exitCode = code }
	os.Args = []string{"xray-controller", "invalid"}
	main()
	if exitCode != 1 {
		t.Fatalf("main error exit code = %d", exitCode)
	}
	exitCode = 0
	oldDial := dialHealthClient
	dialHealthClient = func(string, string) (healthClient, error) { return &fakeHealthClient{}, nil }
	defer func() { dialHealthClient = oldDial }()
	os.Args = []string{"xray-controller", "healthcheck"}
	main()
	if exitCode != 0 {
		t.Fatalf("main success exit code = %d", exitCode)
	}
}
