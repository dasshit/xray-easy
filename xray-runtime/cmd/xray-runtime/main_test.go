package main

import (
	"bytes"
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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"xray-easy/internal/interaction"
	"xray-easy/internal/runtimeauth"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
	runtime "xray-easy/xray-runtime/internal/runtime"
)

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	if err := run([]string{"unexpected"}); err == nil {
		t.Fatal("run accepted an unexpected argument")
	}
	if err := run([]string{"--not-an-option"}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
	if err := run([]string{"validate-candidate", "one", "two"}); err == nil {
		t.Fatal("validate-candidate accepted too many arguments")
	}
}

func TestMainReportsErrorAndExits(t *testing.T) {
	previousArgs := os.Args
	os.Args = []string{"xray-runtime", "--not-an-option"}
	defer func() { os.Args = previousArgs }()
	previousExit := exitProcess
	defer func() { exitProcess = previousExit }()
	exitProcess = func(code int) { panic(code) }
	defer func() {
		if code := recover(); code != 1 {
			t.Fatalf("main exit code = %v, want 1", code)
		}
	}()
	main()
}

func TestValidateCandidateCommand(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "candidate.json")
	valid := `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`
	if err := os.WriteFile(validPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate-candidate", validPath}); err != nil {
		t.Fatalf("validate valid candidate: %v", err)
	}
	if err := run([]string{"validate-candidate", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing candidate was accepted")
	}
	invalidPath := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidPath, []byte(`{"inbounds":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate-candidate", invalidPath}); err == nil {
		t.Fatal("invalid candidate was accepted")
	}
	oldStdin := os.Stdin
	stdinFile, err := os.CreateTemp(t.TempDir(), "candidate-stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdinFile.WriteString(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := stdinFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	os.Stdin = stdinFile
	if err := validateCandidate(""); err != nil {
		t.Fatalf("validate stdin candidate: %v", err)
	}
	if err := stdinFile.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = oldStdin

	emptyFile, err := os.CreateTemp(t.TempDir(), "empty-candidate-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := emptyFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateCandidate(emptyFile.Name()); err == nil {
		t.Fatal("empty candidate was accepted")
	}
}

func TestReadTokenValidatesPathAndLength(t *testing.T) {
	if _, err := readToken(" "); err == nil {
		t.Fatal("empty token path was accepted")
	}
	if _, err := readToken(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing token file was accepted")
	}
	shortPath := filepath.Join(t.TempDir(), "short-token")
	if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(shortPath); err == nil {
		t.Fatal("short token was accepted")
	}
	validPath := filepath.Join(t.TempDir(), "token")
	want := strings.Repeat("x", 32)
	if err := os.WriteFile(validPath, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readToken(validPath)
	if err != nil || string(got) != want {
		t.Fatalf("read token = %q, %v", got, err)
	}
}

func TestReadOptionalConfig(t *testing.T) {
	if data, err := readOptionalConfig(filepath.Join(t.TempDir(), "missing")); err != nil || data != nil {
		t.Fatalf("missing optional config = %q, %v", data, err)
	}
	path := filepath.Join(t.TempDir(), "active.json")
	want := []byte(`{"outbounds":[]}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readOptionalConfig(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("read optional config = %q, %v", got, err)
	}
	if _, err := readOptionalConfig(t.TempDir()); err == nil {
		t.Fatal("directory was accepted as config file")
	}
}

func TestAllowedRuntimeCallUsesServiceIdentity(t *testing.T) {
	tests := []struct {
		method, identity string
		want             bool
	}{
		{xrayruntimev1.Runtime_Health_FullMethodName, "healthcheck", true},
		{xrayruntimev1.Runtime_GetStatus_FullMethodName, "healthcheck", false},
		{xrayruntimev1.Runtime_GetStatus_FullMethodName, "control-plane", true},
		{"other/Health", "control-plane", false},
		{xrayruntimev1.Runtime_GetStatus_FullMethodName, "unknown", false},
	}
	for _, test := range tests {
		if got := allowedRuntimeCall(test.method, test.identity); got != test.want {
			t.Errorf("allowedRuntimeCall(%q, %q) = %v, want %v", test.method, test.identity, got, test.want)
		}
	}
}

func TestRuntimeLoggingInterceptorDoesNotLogPayload(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previousLogger)
	called := false
	response, err := runtimeLoggingInterceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/service/Method"}, func(ctx context.Context, request any) (any, error) {
		called = true
		return "private-payload", errors.New("expected failure")
	})
	if !called || response != "private-payload" || err == nil {
		t.Fatalf("interceptor result = %v, %v, called %v", response, err, called)
	}
	if strings.Contains(output.String(), "private-payload") || strings.Contains(output.String(), "expected failure") {
		t.Fatalf("RPC log contains payload/error detail: %s", output.String())
	}
	response, err = runtimeLoggingInterceptor(context.Background(), &emptypb.Empty{}, &grpc.UnaryServerInfo{FullMethod: "/service/Method"}, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil || response != "ok" {
		t.Fatalf("successful interceptor result = %v, %v", response, err)
	}
}

type runtimeLoggingTestStream struct{ ctx context.Context }

func (s *runtimeLoggingTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *runtimeLoggingTestStream) SendHeader(metadata.MD) error { return nil }
func (s *runtimeLoggingTestStream) SetTrailer(metadata.MD)       {}
func (s *runtimeLoggingTestStream) Context() context.Context     { return s.ctx }
func (s *runtimeLoggingTestStream) SendMsg(any) error            { return nil }
func (s *runtimeLoggingTestStream) RecvMsg(any) error            { return nil }

func TestRuntimeStreamLoggingInterceptorAddsTraceAndLogsCancellation(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previousLogger)
	requestID := "abcdef0123456789abcdef0123456789"
	operationID := "0123456789abcdef0123456789abcdef"
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", requestID, "x-controller-operation-id", operationID))
	stream := &runtimeLoggingTestStream{ctx: ctx}
	err := runtimeStreamLoggingInterceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: xrayruntimev1.Runtime_WatchTelemetry_FullMethodName}, func(_ any, wrapped grpc.ServerStream) error {
		if got := interaction.RequestID(wrapped.Context()); got != requestID {
			t.Errorf("stream request ID = %q, want %q", got, requestID)
		}
		if got := interaction.OperationID(wrapped.Context()); got != operationID {
			t.Errorf("stream operation ID = %q, want %q", got, operationID)
		}
		return context.Canceled
	})
	if err != context.Canceled {
		t.Fatalf("runtime stream interceptor error = %v", err)
	}
	for _, expected := range []string{requestID, operationID, "grpc interaction", "canceled"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("stream log %q does not contain %q", output.String(), expected)
		}
	}
}

func TestHealthcheckAuthenticatesUsingSeparateIdentity(t *testing.T) {
	token := strings.Repeat("t", 32)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := runtime.NewService(nil, "health-test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := runtimeauth.NewAuthenticator([]byte(token), allowedRuntimeCall)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(authenticator.UnaryServerInterceptor()))
	xrayruntimev1.RegisterRuntimeServer(server, service)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	defer listener.Close()
	oldDial := newHealthConnection
	newHealthConnection = func(string) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		)
	}
	defer func() { newHealthConnection = oldDial }()
	if err := healthcheck("bufconn", tokenPath); err != nil {
		t.Fatalf("authenticated healthcheck: %v", err)
	}
	t.Setenv("XRAY_RUNTIME_ADDR", "ignored-by-test-dialer")
	t.Setenv("XRAY_RUNTIME_TOKEN_FILE", tokenPath)
	if err := run([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthcheck CLI command: %v", err)
	}
	if err := healthcheck("bufconn", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("healthcheck accepted a missing token")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServeReportsTokenAndConfigReadErrors(t *testing.T) {
	if err := serve("127.0.0.1:0", "", filepath.Join(t.TempDir(), "no-token"), ""); err == nil || !strings.Contains(err.Error(), "authentication token") {
		t.Fatalf("missing token error = %v", err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serve("127.0.0.1:0", t.TempDir(), tokenPath, ""); err == nil || !strings.Contains(err.Error(), "active Xray configuration") {
		t.Fatalf("config read error = %v", err)
	}
	invalidConfig := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidConfig, []byte(`{"inbounds":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serve("127.0.0.1:0", invalidConfig, tokenPath, ""); err == nil || !strings.Contains(err.Error(), "load active Xray configuration") {
		t.Fatalf("invalid active config error = %v", err)
	}
}

func TestServeReportsListenErrorAndStopsOnContextCancellation(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := serve(occupied.Addr().String(), filepath.Join(directory, "missing-config"), tokenPath, ""); err == nil || !strings.Contains(err.Error(), "listen for Xray runtime") {
		t.Fatalf("listen error = %v", err)
	}
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- serveContext(ctx, address, filepath.Join(directory, "missing-config"), tokenPath, filepath.Join(directory, "revision.json"))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("runtime listener did not start: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serve after graceful shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime server did not stop after context cancellation")
	}
}

func TestEnvOrUsesTrimmedEnvironmentOrFallback(t *testing.T) {
	t.Setenv("XRAY_RUNTIME_TEST_ENV", "  configured  ")
	if got := envOr("XRAY_RUNTIME_TEST_ENV", "fallback"); got != "configured" {
		t.Fatalf("configured env = %q", got)
	}
	t.Setenv("XRAY_RUNTIME_TEST_ENV", "  ")
	if got := envOr("XRAY_RUNTIME_TEST_ENV", "fallback"); got != "fallback" {
		t.Fatalf("fallback env = %q", got)
	}
}

func TestWaitForServeReportsFailureAndRuntimeFatal(t *testing.T) {
	tests := []struct {
		name     string
		serveErr error
		fatal    bool
		wantErr  string
	}{
		{name: "unexpected server error", serveErr: errors.New("listener failed"), wantErr: "serve Xray runtime gRPC"},
		{name: "expected stopped server", serveErr: grpc.ErrServerStopped},
		{name: "fatal runtime", fatal: true, wantErr: "must restart"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := grpc.NewServer()
			serveErrors := make(chan error, 1)
			fatalErrors := make(chan error, 1)
			if test.fatal {
				fatalErrors <- errors.New("private xray error")
			} else {
				serveErrors <- test.serveErr
			}
			err := waitForServe(context.Background(), server, serveErrors, fatalErrors)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("wait result = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantErr) || strings.Contains(err.Error(), "private xray error") {
				t.Fatalf("wait error = %v", err)
			}
		})
	}
}

type blockingHealthServer struct {
	xrayruntimev1.UnimplementedRuntimeServer
	entered chan struct{}
}

func (s blockingHealthServer) Health(ctx context.Context, _ *xrayruntimev1.HealthRequest) (*xrayruntimev1.HealthResponse, error) {
	close(s.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWaitForServeStopsAfterGracefulShutdownTimeout(t *testing.T) {
	previousTimeout := gracefulStopTimeout
	gracefulStopTimeout = 10 * time.Millisecond
	defer func() { gracefulStopTimeout = previousTimeout }()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	service := blockingHealthServer{entered: make(chan struct{})}
	xrayruntimev1.RegisterRuntimeServer(server, service)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	callFinished := make(chan struct{})
	go func() {
		defer close(callFinished)
		_, _ = xrayruntimev1.NewRuntimeClient(connection).Health(context.Background(), &xrayruntimev1.HealthRequest{})
	}()
	select {
	case <-service.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocking health request did not reach server")
	}
	shutdown, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForServe(shutdown, server, serveErrors, make(chan error)); err != nil {
		t.Fatalf("wait after forced graceful shutdown: %v", err)
	}
	select {
	case <-callFinished:
	case <-time.After(2 * time.Second):
		t.Fatal("forced server stop did not cancel the active request")
	}
	_ = listener.Close()
}

type fixedHealthServer struct {
	xrayruntimev1.UnimplementedRuntimeServer
	ready bool
}

func (s fixedHealthServer) Health(context.Context, *xrayruntimev1.HealthRequest) (*xrayruntimev1.HealthResponse, error) {
	return &xrayruntimev1.HealthResponse{Ready: s.ready}, nil
}

func TestHealthcheckReportsConnectionAndReadinessFailures(t *testing.T) {
	token := strings.Repeat("t", 32)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	previousDial := newHealthConnection
	newHealthConnection = func(string) (*grpc.ClientConn, error) { return nil, errors.New("dial blocked") }
	if err := healthcheck("unavailable", tokenPath); err == nil || !strings.Contains(err.Error(), "connect to Xray runtime") {
		t.Fatalf("health connection error = %v", err)
	}

	listener := bufconn.Listen(1 << 20)
	authenticator, err := runtimeauth.NewAuthenticator([]byte(token), allowedRuntimeCall)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(authenticator.UnaryServerInterceptor()))
	xrayruntimev1.RegisterRuntimeServer(server, fixedHealthServer{ready: false})
	go func() { _ = server.Serve(listener) }()
	newHealthConnection = func(string) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		)
	}
	defer func() {
		server.Stop()
		_ = listener.Close()
		newHealthConnection = previousDial
	}()
	if err := healthcheck("bufconn", tokenPath); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("unready healthcheck error = %v", err)
	}
}
