package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"xray-easy/internal/interaction"
	"xray-easy/internal/runtimeauth"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

const embeddedTestToken = "0123456789abcdef0123456789abcdef"

type embeddedRuntimeStub struct {
	xrayruntimev1.UnimplementedRuntimeServer
	failMethod          string
	invalidStatus       bool
	missingVersion      bool
	invalidTimestamp    bool
	invalidTelemetry    string
	invalidLog          bool
	invalidCapabilities bool
	validResult         bool
	seenConfig          []byte
	seenReplace         *xrayruntimev1.ReplaceInboundRequest
	seenAdd             *xrayruntimev1.AddUserRequest
	seenRemove          *xrayruntimev1.RemoveUserRequest
	seenListProtocol    xrayruntimev1.Protocol
}

func (s *embeddedRuntimeStub) fail(method string) error {
	if s.failMethod == method {
		return status.Error(codes.Unavailable, "injected runtime outage")
	}
	return nil
}

func (s *embeddedRuntimeStub) Health(_ context.Context, _ *xrayruntimev1.HealthRequest) (*xrayruntimev1.HealthResponse, error) {
	if err := s.fail("Health"); err != nil {
		return nil, err
	}
	return &xrayruntimev1.HealthResponse{Ready: true, XrayCoreVersion: "26.7.28"}, nil
}

func (s *embeddedRuntimeStub) GetStatus(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.RuntimeStatus, error) {
	if err := s.fail("GetStatus"); err != nil {
		return nil, err
	}
	state := xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING
	if s.invalidStatus {
		state = xrayruntimev1.RuntimeState_RUNTIME_STATE_UNSPECIFIED
	}
	version := "Xray 26.7.28"
	if s.missingVersion {
		version = ""
	}
	started := timestamppb.New(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))
	if s.invalidTimestamp {
		started = &timestamppb.Timestamp{Seconds: 999999999999}
	}
	return &xrayruntimev1.RuntimeStatus{State: state, XrayCoreVersion: version, ActiveRevision: 8, LastError: "redacted error", StartedAt: started}, nil
}

func (s *embeddedRuntimeStub) GetCapabilities(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.CapabilitiesResponse, error) {
	if err := s.fail("GetCapabilities"); err != nil {
		return nil, err
	}
	protocols := []*xrayruntimev1.ProtocolCapability{
		{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Configured: true, TrafficCounters: true, InboundTag: "vless-reality"},
		{Protocol: xrayruntimev1.Protocol_PROTOCOL_VMESS, Configured: true, InboundTag: "vmess-tls"},
	}
	if s.invalidCapabilities {
		protocols = append(protocols, &xrayruntimev1.ProtocolCapability{Protocol: xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, Configured: true, InboundTag: "vless-reality"})
	}
	return &xrayruntimev1.CapabilitiesResponse{Protocols: protocols}, nil
}

func (s *embeddedRuntimeStub) GetRecentLogs(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.LogsResponse, error) {
	if err := s.fail("GetRecentLogs"); err != nil {
		return nil, err
	}
	entries := []*xrayruntimev1.LogEntry{{Timestamp: timestamppb.Now(), Level: "warn", Component: "runtime", Message: "safe warning"}}
	if s.invalidLog {
		entries = append(entries, nil)
	}
	return &xrayruntimev1.LogsResponse{Entries: entries}, nil
}

func (s *embeddedRuntimeStub) ValidateConfiguration(_ context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.ConfigurationResponse, error) {
	if err := s.fail("ValidateConfiguration"); err != nil {
		return nil, err
	}
	s.seenConfig = append([]byte(nil), request.GetConfigurationJson()...)
	digest := sha256.Sum256(request.GetConfigurationJson())
	response := &xrayruntimev1.ConfigurationResponse{Valid: true, OperationId: request.GetOperationId(), Revision: request.GetRevision(), ConfigurationDigest: hex.EncodeToString(digest[:])}
	if s.validResult {
		response.ConfigurationDigest = "wrong"
	}
	return response, nil
}

func (s *embeddedRuntimeStub) ApplyConfiguration(_ context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.OperationResponse, error) {
	if err := s.fail("ApplyConfiguration"); err != nil {
		return nil, err
	}
	s.seenConfig = append([]byte(nil), request.GetConfigurationJson()...)
	operationID, revision := request.GetOperationId(), request.GetRevision()
	if s.validResult {
		operationID += "-unexpected"
	}
	return &xrayruntimev1.OperationResponse{OperationId: operationID, Revision: revision}, nil
}

func (s *embeddedRuntimeStub) ReplaceInbound(_ context.Context, request *xrayruntimev1.ReplaceInboundRequest) (*xrayruntimev1.OperationResponse, error) {
	if err := s.fail("ReplaceInbound"); err != nil {
		return nil, err
	}
	s.seenReplace = request
	operationID, revision := request.GetOperationId(), request.GetRevision()
	if s.validResult {
		revision++
	}
	return &xrayruntimev1.OperationResponse{OperationId: operationID, Revision: revision}, nil
}

func (s *embeddedRuntimeStub) ProbeRealityTarget(context.Context, *xrayruntimev1.ProbeRealityTargetRequest) (*xrayruntimev1.ProbeResponse, error) {
	if err := s.fail("ProbeRealityTarget"); err != nil {
		return nil, err
	}
	return &xrayruntimev1.ProbeResponse{Ok: !s.validResult}, nil
}

func (s *embeddedRuntimeStub) ProbeIPv6Egress(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.ProbeResponse, error) {
	if err := s.fail("ProbeIPv6Egress"); err != nil {
		return nil, err
	}
	return &xrayruntimev1.ProbeResponse{Ok: !s.validResult}, nil
}

func (s *embeddedRuntimeStub) AddUser(_ context.Context, request *xrayruntimev1.AddUserRequest) (*xrayruntimev1.OperationResponse, error) {
	if err := s.fail("AddUser"); err != nil {
		return nil, err
	}
	s.seenAdd = request
	operationID := request.GetOperationId()
	if s.validResult {
		operationID += "-unexpected"
	}
	return &xrayruntimev1.OperationResponse{OperationId: operationID, Revision: request.GetRevision()}, nil
}

func (s *embeddedRuntimeStub) RemoveUser(_ context.Context, request *xrayruntimev1.RemoveUserRequest) (*xrayruntimev1.OperationResponse, error) {
	if err := s.fail("RemoveUser"); err != nil {
		return nil, err
	}
	s.seenRemove = request
	revision := request.GetRevision()
	if s.validResult {
		revision++
	}
	return &xrayruntimev1.OperationResponse{OperationId: request.GetOperationId(), Revision: revision}, nil
}

func (s *embeddedRuntimeStub) ListUsers(_ context.Context, request *xrayruntimev1.ListUsersRequest) (*xrayruntimev1.ListUsersResponse, error) {
	s.seenListProtocol = request.GetProtocol()
	return &xrayruntimev1.ListUsersResponse{Emails: []string{"device-1@xray-easy"}}, nil
}

func (s *embeddedRuntimeStub) GetTelemetry(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.TelemetryResponse, error) {
	if err := s.fail("GetTelemetry"); err != nil {
		return nil, err
	}
	user := &xrayruntimev1.UserTelemetry{Email: "device-1@xray-easy", UploadBytes: 12, DownloadBytes: 34, LastSeen: timestamppb.Now(), SourceIps: []*xrayruntimev1.IPObservation{{Address: "::ffff:192.0.2.12", LastSeen: timestamppb.Now()}}}
	switch s.invalidTelemetry {
	case "nil-user":
		return &xrayruntimev1.TelemetryResponse{Users: []*xrayruntimev1.UserTelemetry{nil}}, nil
	case "negative":
		user.UploadBytes = -1
	case "timestamp":
		user.LastSeen = &timestamppb.Timestamp{Seconds: 999999999999}
	case "nil-ip":
		user.SourceIps = []*xrayruntimev1.IPObservation{nil}
	case "bad-ip":
		user.SourceIps = []*xrayruntimev1.IPObservation{{Address: "invalid"}}
	}
	return &xrayruntimev1.TelemetryResponse{Users: []*xrayruntimev1.UserTelemetry{user}}, nil
}

func newEmbeddedClientTest(t *testing.T) (*EmbeddedXrayClient, *embeddedRuntimeStub, string) {
	t.Helper()
	root := t.TempDir()
	tokenPath := filepath.Join(root, "runtime-token")
	if err := os.WriteFile(tokenPath, []byte(embeddedTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	authenticator, err := runtimeauth.NewAuthenticator([]byte(embeddedTestToken), func(method, identity string) bool {
		if identity == embeddedHealthIdentity {
			return method == xrayruntimev1.Runtime_Health_FullMethodName
		}
		return identity == embeddedControlIdentity && strings.HasPrefix(method, "/xrayeasy.xray.v1.Runtime/")
	})
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(authenticator.UnaryServerInterceptor()))
	stub := &embeddedRuntimeStub{}
	xrayruntimev1.RegisterRuntimeServer(grpcServer, stub)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})
	connection, err := grpc.NewClient("passthrough:///embedded-runtime-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return NewEmbeddedXrayClientWithConn(connection, tokenPath, configDir), stub, configDir
}

func TestEmbeddedXrayAdapterCoversControllerRuntimeInterfaces(t *testing.T) {
	client, stub, configDir := newEmbeddedClientTest(t)
	candidate := filepath.Join(configDir, "candidates", "candidate.json")
	previous := filepath.Join(configDir, "active.json")
	snapshot := []byte(`{"inbounds":[{"tag":"vless-reality"}]}`)
	for path, data := range map[string][]byte{candidate: snapshot, previous: []byte(`{"old":true}`)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health() = %v", err)
	}
	statusValue, err := client.Status(context.Background())
	if err != nil || statusValue.State != "running" || statusValue.Protocol != "embedded-core" || statusValue.XrayVersion != "Xray 26.7.28" || statusValue.ActiveRevision != 8 || !statusValue.StatsAvailable || strings.Join(statusValue.InboundTags, ",") != "vless-reality,vmess-tls" {
		t.Fatalf("Status() = %+v, %v", statusValue, err)
	}
	logs, err := client.Logs(context.Background())
	if err != nil || len(logs) != 1 || !strings.Contains(logs[0], "[WARN] runtime: safe warning") {
		t.Fatalf("Logs() = %v, %v", logs, err)
	}
	operationID := "11111111111111111111111111111111"
	ctx := interaction.WithStateRevision(interaction.WithOperationID(context.Background(), operationID), 11)
	if err := client.Validate(ctx, candidate, operationID); err != nil || string(stub.seenConfig) != string(snapshot) {
		t.Fatalf("Validate() = %v, snapshot=%s", err, stub.seenConfig)
	}
	if err := client.Apply(ctx, candidate, operationID); err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if err := client.ReplaceInbound(ctx, candidate, previous, "vless-reality", operationID); err != nil {
		t.Fatalf("ReplaceInbound() = %v", err)
	}
	if string(stub.seenReplace.GetCandidateConfigurationJson()) != string(snapshot) || string(stub.seenReplace.GetPreviousConfigurationJson()) != `{"old":true}` || stub.seenReplace.GetInboundTag() != "vless-reality" || stub.seenReplace.GetRevision() != 11 {
		t.Fatalf("ReplaceInbound request = %+v", stub.seenReplace)
	}
	if err := client.ProbeTarget(context.Background(), "target.example:443", "front.example"); err != nil {
		t.Fatalf("ProbeTarget() = %v", err)
	}
	if err := client.ProbeIPv6(context.Background()); err != nil {
		t.Fatalf("ProbeIPv6() = %v", err)
	}
	userCtx := interaction.WithOperationID(context.Background(), "22222222222222222222222222222222")
	userCtx = interaction.WithStateRevision(userCtx, 0)
	if err := client.AddUser(userCtx, "device@xray-easy", "uuid", "xtls-rprx-vision"); err != nil {
		t.Fatalf("AddUser() = %v", err)
	}
	if stub.seenAdd.GetProtocol() != xrayruntimev1.Protocol_PROTOCOL_VLESS || stub.seenAdd.GetRevision() != 0 || stub.seenAdd.GetFlow() != "xtls-rprx-vision" {
		t.Fatalf("AddUser request = %+v", stub.seenAdd)
	}
	if err := client.AddHysteriaUser(context.Background(), "hysteria@xray-easy", "password"); err != nil {
		t.Fatalf("AddHysteriaUser() = %v", err)
	}
	if stub.seenAdd.GetProtocol() != xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2 {
		t.Fatalf("Hysteria protocol = %v", stub.seenAdd.GetProtocol())
	}
	if err := client.AddVMessUser(context.Background(), "vmess@xray-easy", "uuid"); err != nil {
		t.Fatalf("AddVMessUser() = %v", err)
	}
	if err := client.RemoveUser(context.Background(), "device@xray-easy"); err != nil {
		t.Fatalf("RemoveUser() = %v", err)
	}
	if err := client.RemoveHysteriaUser(context.Background(), "hysteria@xray-easy"); err != nil {
		t.Fatalf("RemoveHysteriaUser() = %v", err)
	}
	if err := client.RemoveVMessUser(context.Background(), "vmess@xray-easy"); err != nil {
		t.Fatalf("RemoveVMessUser() = %v", err)
	}
	if stub.seenRemove.GetProtocol() != xrayruntimev1.Protocol_PROTOCOL_VMESS {
		t.Fatalf("RemoveVMess protocol = %v", stub.seenRemove.GetProtocol())
	}
	if users, err := client.Users(context.Background()); err != nil || len(users) != 1 || users[0] != "device-1@xray-easy" {
		t.Fatalf("Users() = %v, %v", users, err)
	}
	for inbound, want := range map[string]xrayruntimev1.Protocol{"vless-reality": xrayruntimev1.Protocol_PROTOCOL_VLESS, "vmess-tls": xrayruntimev1.Protocol_PROTOCOL_VMESS, "hysteria2": xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2} {
		if users, err := client.UsersInInbound(context.Background(), inbound); err != nil || len(users) != 1 {
			t.Fatalf("UsersInInbound(%q) = %v, %v", inbound, users, err)
		}
		if stub.seenListProtocol != want {
			t.Errorf("UsersInInbound(%q) protocol = %v, want %v", inbound, stub.seenListProtocol, want)
		}
	}
	if _, err := client.UsersInInbound(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown inbound was accepted")
	}
	telemetry, err := client.Poll(context.Background())
	if err != nil || len(telemetry) != 1 || telemetry[0].UploadBytes != 12 || telemetry[0].DownloadBytes != 34 || len(telemetry[0].SourceIPs) != 1 || telemetry[0].SourceIPs[0].Address != "192.0.2.12" {
		t.Fatalf("Poll() = %+v, %v", telemetry, err)
	}
}

func TestEmbeddedXrayAdapterValidatesResponsesAndMapsFailures(t *testing.T) {
	client, stub, configDir := newEmbeddedClientTest(t)
	config := filepath.Join(configDir, "candidate.json")
	if err := os.WriteFile(config, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := interaction.WithStateRevision(interaction.WithOperationID(context.Background(), "33333333333333333333333333333333"), 3)
	for method, call := range map[string]func() error{
		"Health":                func() error { return client.Health(context.Background()) },
		"GetStatus":             func() error { _, err := client.Status(context.Background()); return err },
		"GetCapabilities":       func() error { _, err := client.Status(context.Background()); return err },
		"GetRecentLogs":         func() error { _, err := client.Logs(context.Background()); return err },
		"ValidateConfiguration": func() error { return client.Validate(ctx, config, interaction.OperationID(ctx)) },
		"ApplyConfiguration":    func() error { return client.Apply(ctx, config, interaction.OperationID(ctx)) },
		"ReplaceInbound": func() error {
			return client.ReplaceInbound(ctx, config, config, "vless-reality", interaction.OperationID(ctx))
		},
		"ProbeRealityTarget": func() error { return client.ProbeTarget(context.Background(), "target:443", "target") },
		"ProbeIPv6Egress":    func() error { return client.ProbeIPv6(context.Background()) },
		"AddUser":            func() error { return client.AddUser(context.Background(), "email", "cred", "") },
		"RemoveUser":         func() error { return client.RemoveUser(context.Background(), "email") },
		"GetTelemetry":       func() error { _, err := client.Poll(context.Background()); return err },
	} {
		t.Run(method, func(t *testing.T) {
			stub.failMethod = method
			if err := call(); status.Code(err) != codes.Unavailable {
				t.Fatalf("%s error = %v, want Unavailable", method, err)
			}
		})
	}
	stub.failMethod = ""
	if err := client.Close(); err != nil {
		t.Fatalf("Close() on caller-owned connection = %v", err)
	}
	stub.invalidStatus = true
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("unspecified runtime state was accepted")
	}
	stub.invalidStatus, stub.missingVersion = false, true
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("missing runtime version was accepted")
	}
	stub.missingVersion, stub.invalidTimestamp = false, true
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("invalid runtime timestamp was accepted")
	}
	stub.invalidTimestamp = false
	stub.invalidCapabilities = true
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("duplicate runtime inbound tags were accepted")
	}
	stub.invalidCapabilities = false
	stub.invalidLog = true
	if _, err := client.Logs(context.Background()); err == nil {
		t.Fatal("nil log entry was accepted")
	}
	stub.invalidLog = false
	for _, value := range []string{"nil-user", "negative", "timestamp", "nil-ip", "bad-ip"} {
		stub.invalidTelemetry = value
		if _, err := client.Poll(context.Background()); err == nil {
			t.Errorf("invalid telemetry %q was accepted", value)
		}
	}
	stub.invalidTelemetry = ""
	stub.validResult = true
	if err := client.AddUser(context.Background(), "email", "cred", ""); err == nil {
		t.Fatal("unexpected AddUser operation identity was accepted")
	}
	if err := client.RemoveUser(context.Background(), "email"); err == nil {
		t.Fatal("unexpected RemoveUser revision was accepted")
	}
	if err := client.Validate(ctx, config, interaction.OperationID(ctx)); err == nil {
		t.Fatal("changed config digest was accepted")
	}
	if err := client.Apply(ctx, config, interaction.OperationID(ctx)); err == nil {
		t.Fatal("changed apply operation ID was accepted")
	}
	if err := client.ReplaceInbound(ctx, config, config, "vless-reality", interaction.OperationID(ctx)); err == nil {
		t.Fatal("changed inbound revision was accepted")
	}
	if err := client.ProbeTarget(context.Background(), "target:443", "target"); err == nil {
		t.Fatal("unsuccessful target probe was accepted")
	}
	if err := client.ProbeIPv6(context.Background()); err == nil {
		t.Fatal("unsuccessful IPv6 probe was accepted")
	}
	if _, err := (*EmbeddedXrayClient)(nil).call(context.Background(), embeddedControlIdentity, "method", &xrayruntimev1.EmptyRequest{}, func(context.Context, proto.Message) (proto.Message, error) { return nil, nil }); err == nil {
		t.Fatal("nil client connection was accepted")
	}
}

func TestEmbeddedXraySnapshotReaderRestrictsMountedFiles(t *testing.T) {
	client, _, root := newEmbeddedClientTest(t)
	valid := filepath.Join(root, "candidates", "candidate.json")
	if err := os.WriteFile(valid, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := client.readSnapshot(valid); err != nil || string(snapshot) != `{"ok":true}` {
		t.Fatalf("readSnapshot() = %q, %v", snapshot, err)
	}
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"secret":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "candidates", "escape.json")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outside, filepath.Join(root, "candidates", "escape.json"), filepath.Join(root, "missing.json")} {
		if _, err := client.readSnapshot(path); err == nil {
			t.Errorf("readSnapshot(%q) unexpectedly succeeded", path)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "directory.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readSnapshot(filepath.Join(root, "directory.json")); err == nil {
		t.Fatal("directory was accepted as a snapshot")
	}
	tooLarge := filepath.Join(root, "large.json")
	if err := os.WriteFile(tooLarge, make([]byte, maxRuntimeConfigSnapshot+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.readSnapshot(tooLarge); err == nil {
		t.Fatal("oversized snapshot was accepted")
	}
	if _, err := (*EmbeddedXrayClient)(nil).readSnapshot("candidate.json"); err == nil {
		t.Fatal("nil snapshot reader was accepted")
	}
}

func TestDialEmbeddedXrayValidatesConfiguration(t *testing.T) {
	for _, address := range []string{"invalid", "localhost:0", "localhost:65536", "localhost:port"} {
		if _, err := DialEmbeddedXray(address, "token", "/etc/xray"); err == nil {
			t.Errorf("invalid gRPC address %q was accepted", address)
		}
	}
	if _, err := DialEmbeddedXray("localhost:10086", " ", "/etc/xray"); err == nil {
		t.Fatal("empty token path was accepted")
	}
	if _, err := DialEmbeddedXray("localhost:10086", "token", " "); err == nil {
		t.Fatal("empty config directory was accepted")
	}
	client, err := DialEmbeddedXray("127.0.0.1:1", filepath.Join(t.TempDir(), "token"), "/etc/xray")
	if err != nil {
		t.Fatalf("lazy gRPC dial should succeed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close gRPC client: %v", err)
	}
	client = &EmbeddedXrayClient{TokenFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := client.readToken(); err == nil {
		t.Fatal("missing runtime token was accepted")
	}
	shortToken := filepath.Join(t.TempDir(), "short-token")
	if err := os.WriteFile(shortToken, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	client.TokenFile = shortToken
	if _, err := client.readToken(); err == nil {
		t.Fatal("short runtime token was accepted")
	}
	client.TokenFile = ""
	if _, err := client.readToken(); err == nil {
		t.Fatal("empty runtime token path was accepted")
	}
}

type telemetryRuntimeServer struct {
	xrayruntimev1.UnimplementedRuntimeServer
	requests chan *xrayruntimev1.WatchTelemetryRequest
}

func (s *telemetryRuntimeServer) WatchTelemetry(request *xrayruntimev1.WatchTelemetryRequest, stream xrayruntimev1.Runtime_WatchTelemetryServer) error {
	s.requests <- request
	if runtimeauth.IdentityFromContext(stream.Context()) != embeddedControlIdentity {
		return status.Error(codes.Unauthenticated, "runtime stream identity is invalid")
	}
	return stream.Send(&xrayruntimev1.TelemetryResponse{SampledAt: timestamppb.Now(), SourceGeneration: "embedded-runtime", Sequence: 3, FullSnapshot: true, Users: []*xrayruntimev1.UserTelemetry{{Email: "ios@example.test", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, UploadBytes: 15}}})
}

func TestEmbeddedXrayClientOpensAuthenticatedTelemetryStream(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	authenticator, err := runtimeauth.NewAuthenticator([]byte(embeddedTestToken), func(method, identity string) bool {
		return method == xrayruntimev1.Runtime_WatchTelemetry_FullMethodName && identity == embeddedControlIdentity
	})
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.ChainStreamInterceptor(authenticator.StreamServerInterceptor()))
	stub := &telemetryRuntimeServer{requests: make(chan *xrayruntimev1.WatchTelemetryRequest, 2)}
	xrayruntimev1.RegisterRuntimeServer(server, stub)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///embedded-stream-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	tokenPath := filepath.Join(t.TempDir(), "runtime-token")
	if err := os.WriteFile(tokenPath, []byte(embeddedTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	client := NewEmbeddedXrayClientWithConn(connection, tokenPath, t.TempDir())

	for _, interval := range []time.Duration{100 * time.Millisecond, 10 * time.Second} {
		stream, err := client.WatchTelemetry(context.Background(), interval)
		if err != nil {
			t.Fatalf("WatchTelemetry(%s): %v", interval, err)
		}
		request := <-stub.requests
		wantInterval := uint32(interval.Milliseconds())
		if interval < 500*time.Millisecond {
			wantInterval = 1000
		} else if interval > 5*time.Second {
			wantInterval = 5000
		}
		if request.GetSampleIntervalMs() != wantInterval {
			t.Fatalf("stream interval = %dms, want %dms", request.GetSampleIntervalMs(), wantInterval)
		}
		update, err := stream.Recv()
		if err != nil || update.GetSequence() != 3 || len(update.GetUsers()) != 1 || update.GetUsers()[0].GetEmail() != "ios@example.test" {
			t.Fatalf("runtime telemetry update = %+v, %v", update, err)
		}
		if _, err := stream.Recv(); err != io.EOF {
			t.Fatalf("runtime stream completion error = %v, want EOF", err)
		}
	}
}
