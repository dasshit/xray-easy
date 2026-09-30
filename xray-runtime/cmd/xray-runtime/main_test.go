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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
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
}
