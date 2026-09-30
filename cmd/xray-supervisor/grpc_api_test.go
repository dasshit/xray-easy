package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"xray-easy/internal/interaction"
	supervisorapi "xray-easy/internal/supervisor"
	supervisorv1 "xray-easy/internal/supervisor/api/v1"
)

func newSupervisorTestClient(t *testing.T, instance *supervisor) *supervisorapi.Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := newSupervisorGRPCServer(instance)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///xray-supervisor-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})
	return supervisorapi.NewClientWithConn(conn, instance.cfg.tokenFile)
}

func TestSupervisorGRPCOperationsKeepExistingRuntimeBehavior(t *testing.T) {
	instance, configDir := newProcessTestSupervisor(t)
	if err := instance.startInitial(); err != nil {
		t.Fatal(err)
	}
	client := newSupervisorTestClient(t, instance)
	ctx := context.Background()
	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}
	statusValue, err := client.Status(ctx)
	if err != nil || statusValue.State != "no-config" || statusValue.Protocol != protocolVersion {
		t.Fatalf("GetStatus = %+v, %v", statusValue, err)
	}
	instance.log.add(`privateKey="grpc-secret"`)
	logs, err := client.Logs(ctx)
	if err != nil || len(logs) != 2 || strings.Contains(strings.Join(logs, "\n"), "grpc-secret") || !strings.Contains(strings.Join(logs, "\n"), "[REDACTED]") {
		t.Fatalf("GetLogs = %q, %v", logs, err)
	}
	valid := writeTestConfig(t, configDir, "candidates/grpc-valid.json", "valid")
	if err := client.Validate(ctx, valid, "validate-operation"); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if err := client.Validate(ctx, "", ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ValidateConfig missing path status = %v", err)
	}
	if err := client.Validate(ctx, valid, ""); err != nil {
		t.Fatalf("ValidateConfig with optional empty operation ID: %v", err)
	}
	if err := client.Validate(ctx, filepath.Join(configDir, "missing.json"), "bad-operation"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ValidateConfig invalid path status = %v", err)
	}
	if err := client.Apply(ctx, "", "apply-operation"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ApplyConfig missing path status = %v", err)
	}
	if err := client.Apply(interaction.WithStateRevision(ctx, 1), filepath.Join(configDir, "missing.json"), "bad-operation"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ApplyConfig invalid path status = %v", err)
	}
	if err := client.Apply(interaction.WithStateRevision(ctx, 2), valid, "apply-operation"); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	waitForSupervisorState(t, instance, "running")
	statusValue, err = client.Status(ctx)
	if err != nil || statusValue.ConfigPath != canonicalTestPath(t, valid) || statusValue.PID <= 0 {
		t.Fatalf("running status = %+v, %v", statusValue, err)
	}
	if err := client.Apply(interaction.WithStateRevision(ctx, 3), valid, ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ApplyConfig without operation id status = %v", err)
	}
	instance.mu.Lock()
	instance.state = "degraded"
	instance.lastError = `failed password="private"`
	instance.mu.Unlock()
	if err := client.Health(ctx); status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private") {
		t.Fatalf("unhealthy Health status = %v", err)
	}
	instance.mu.Lock()
	instance.state = "running"
	instance.mu.Unlock()
	instance.stopChild()
}

func TestSupervisorGRPCReplaceInboundAndProbeMethods(t *testing.T) {
	instance, candidate, previous, logPath := newReplaceTestSupervisor(t)
	client := newSupervisorTestClient(t, instance)
	if err := client.ReplaceInbound(interaction.WithStateRevision(context.Background(), 1), candidate, previous, "vless-reality", "replace-operation"); err != nil {
		t.Fatalf("ReplaceInbound: %v", err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil || string(calls) != "rmi\nadi\n" {
		t.Fatalf("inbound RPC API calls = %q, %v", calls, err)
	}
	if err := client.ReplaceInbound(interaction.WithStateRevision(context.Background(), 2), candidate, previous, "", "op"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ReplaceInbound missing tag = %v", err)
	}
	for _, fields := range [][4]string{
		{"", previous, "vless-reality", "op"},
		{candidate, "", "vless-reality", "op"},
		{candidate, previous, "vless-reality", ""},
	} {
		if err := client.ReplaceInbound(interaction.WithStateRevision(context.Background(), 3), fields[0], fields[1], fields[2], fields[3]); status.Code(err) != codes.InvalidArgument {
			t.Errorf("ReplaceInbound missing field %q/%q/%q/%q = %v", fields[0], fields[1], fields[2], fields[3], err)
		}
	}
	if err := client.ProbeTarget(context.Background(), "not-a-host-port", ""); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("ProbeTarget invalid address = %v", err)
	}
	if err := client.ProbeTarget(context.Background(), "", ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ProbeTarget missing target = %v", err)
	}
	instance.cfg.probeTargetFn = func(_ context.Context, target, sni string) error {
		if target != "example.com:443" || sni != "example.com" {
			t.Fatalf("probe target callback arguments = %q %q", target, sni)
		}
		return nil
	}
	if err := client.ProbeTarget(context.Background(), "example.com:443", "example.com"); err != nil {
		t.Fatalf("ProbeTarget success: %v", err)
	}
	instance.cfg.probeTargetFn = func(context.Context, string, string) error { return errors.New("TLS dial failed") }
	if err := client.ProbeTarget(context.Background(), "example.com:443", "example.com"); status.Code(err) != codes.Unavailable {
		t.Fatalf("ProbeTarget connection failure status = %v", err)
	}
	instance.ipv6ProbeFn = func(context.Context) error { return nil }
	if err := client.ProbeIPv6(context.Background()); err != nil {
		t.Fatalf("ProbeIPv6: %v", err)
	}
	instance.ipv6ProbeFn = func(context.Context) error { return context.DeadlineExceeded }
	if err := client.ProbeIPv6(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("failed IPv6 probe status = %v", err)
	}
}

func TestSupervisorGRPCReceiveMessageLimit(t *testing.T) {
	instance, _ := newProcessTestSupervisor(t)
	client := newSupervisorTestClient(t, instance)
	largePath := strings.Repeat("x", (24<<20)+100)
	if err := client.Validate(context.Background(), largePath, "oversized"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("oversized request status = %v", err)
	}
}

type failingSupervisorListener struct{}

func (failingSupervisorListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (failingSupervisorListener) Close() error              { return nil }
func (failingSupervisorListener) Addr() net.Addr            { return supervisorTestAddr("fake") }

type supervisorTestAddr string

func (a supervisorTestAddr) Network() string { return "test" }
func (a supervisorTestAddr) String() string  { return string(a) }

func TestRunSupervisorReportsServeFailure(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "xray")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "xray-bin")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo Xray; exit 0; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config{configDir: configDir, xrayBinary: binary, tokenFile: token, listen: "test", grace: 10 * time.Millisecond, listenFunc: func(string, string) (net.Listener, error) { return failingSupervisorListener{}, nil }}
	err := runSupervisor(cfg, make(chan os.Signal))
	if err == nil || !strings.Contains(err.Error(), "supervisor gRPC server stopped: accept failed") {
		t.Fatalf("Serve error = %v", err)
	}
}

func TestSupervisorRPCValidationHelpers(t *testing.T) {
	instance, configDir := newProcessTestSupervisor(t)
	if _, err := instance.ValidateConfig(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil ValidateConfig request status = %v", err)
	}
	if _, err := instance.ValidateConfig(context.Background(), &supervisorv1.ValidateConfigRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing ValidateConfig path status = %v", err)
	}
	if _, err := instance.ValidateConfig(context.Background(), &supervisorv1.ValidateConfigRequest{Path: filepath.Join(configDir, "missing.json")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("invalid ValidateConfig path status = %v", err)
	}
	for _, revision := range []int64{0, -1} {
		if err := rpcRevision(revision); status.Code(err) != codes.InvalidArgument {
			t.Errorf("rpcRevision(%d) = %v, want InvalidArgument", revision, err)
		}
	}
	if err := rpcRevision(17); err != nil {
		t.Fatalf("rpcRevision(valid) = %v", err)
	}
	if rpcOperationError(codes.Internal, nil) != nil {
		t.Fatal("nil operation error became non-nil")
	}
}
