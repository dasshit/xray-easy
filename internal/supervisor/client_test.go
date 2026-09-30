package supervisor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/interaction"
	supervisorv1 "xray-easy/internal/supervisor/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type testRPCServer struct {
	supervisorv1.UnimplementedSupervisorServer
	requests    map[string][]proto.Message
	errors      map[string]error
	health      *supervisorv1.HealthResponse
	probeTarget *supervisorv1.ProbeTargetResponse
	probeIPv6   *supervisorv1.ProbeIPv6Response
	status      *supervisorv1.SupervisorStatus
	logs        *supervisorv1.LogsResponse
	users       *supervisorv1.ListUsersResponse
	stats       *supervisorv1.UserStatsResponse
}

func newTestRPCServer() *testRPCServer {
	return &testRPCServer{
		requests: make(map[string][]proto.Message), errors: make(map[string]error),
		status: &supervisorv1.SupervisorStatus{Protocol: "v1", XrayVersion: "Xray test", State: "running", Pid: 123, ConfigPath: "/etc/xray/active.json", RestartCount: 4, StartedAt: timestamppb.New(time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC))},
		logs:   &supervisorv1.LogsResponse{Lines: []string{"one", "two"}},
		users:  &supervisorv1.ListUsersResponse{Users: []string{"device@example.test"}},
		stats:  &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{Email: "device@example.test", UploadBytes: 12, DownloadBytes: 34}}},
	}
}

func (s *testRPCServer) record(method string, request proto.Message) error {
	s.requests[method] = append(s.requests[method], proto.Clone(request))
	return s.errors[method]
}
func (s *testRPCServer) Health(_ context.Context, request *emptypb.Empty) (*supervisorv1.HealthResponse, error) {
	if err := s.record("Health", request); err != nil {
		return nil, err
	}
	if s.health != nil {
		return proto.Clone(s.health).(*supervisorv1.HealthResponse), nil
	}
	return &supervisorv1.HealthResponse{Ok: true, State: "running", Protocol: "v1"}, nil
}
func (s *testRPCServer) GetStatus(_ context.Context, request *emptypb.Empty) (*supervisorv1.SupervisorStatus, error) {
	if err := s.record("GetStatus", request); err != nil {
		return nil, err
	}
	return proto.Clone(s.status).(*supervisorv1.SupervisorStatus), nil
}
func (s *testRPCServer) GetLogs(_ context.Context, request *emptypb.Empty) (*supervisorv1.LogsResponse, error) {
	if err := s.record("GetLogs", request); err != nil {
		return nil, err
	}
	return proto.Clone(s.logs).(*supervisorv1.LogsResponse), nil
}
func (s *testRPCServer) ValidateConfig(_ context.Context, request *supervisorv1.ValidateConfigRequest) (*supervisorv1.OperationResponse, error) {
	if err := s.record("ValidateConfig", request); err != nil {
		return nil, err
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId}, nil
}
func (s *testRPCServer) ApplyConfig(_ context.Context, request *supervisorv1.ApplyConfigRequest) (*supervisorv1.OperationResponse, error) {
	if err := s.record("ApplyConfig", request); err != nil {
		return nil, err
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId}, nil
}
func (s *testRPCServer) ReplaceInbound(_ context.Context, request *supervisorv1.ReplaceInboundRequest) (*supervisorv1.OperationResponse, error) {
	if err := s.record("ReplaceInbound", request); err != nil {
		return nil, err
	}
	return &supervisorv1.OperationResponse{Ok: true, OperationId: request.OperationId}, nil
}
func (s *testRPCServer) ProbeTarget(_ context.Context, request *supervisorv1.ProbeTargetRequest) (*supervisorv1.ProbeTargetResponse, error) {
	if err := s.record("ProbeTarget", request); err != nil {
		return nil, err
	}
	if s.probeTarget != nil {
		return proto.Clone(s.probeTarget).(*supervisorv1.ProbeTargetResponse), nil
	}
	return &supervisorv1.ProbeTargetResponse{Ok: true, Target: request.Target}, nil
}
func (s *testRPCServer) ProbeIPv6(_ context.Context, request *emptypb.Empty) (*supervisorv1.ProbeIPv6Response, error) {
	if err := s.record("ProbeIPv6", request); err != nil {
		return nil, err
	}
	if s.probeIPv6 != nil {
		return proto.Clone(s.probeIPv6).(*supervisorv1.ProbeIPv6Response), nil
	}
	return &supervisorv1.ProbeIPv6Response{Ok: true}, nil
}
func (s *testRPCServer) AlterUser(_ context.Context, request *supervisorv1.AlterUserRequest) (*supervisorv1.OperationResponse, error) {
	if err := s.record("AlterUser", request); err != nil {
		return nil, err
	}
	return &supervisorv1.OperationResponse{Ok: true}, nil
}
func (s *testRPCServer) ListUsers(_ context.Context, request *supervisorv1.ListUsersRequest) (*supervisorv1.ListUsersResponse, error) {
	if err := s.record("ListUsers", request); err != nil {
		return nil, err
	}
	return proto.Clone(s.users).(*supervisorv1.ListUsersResponse), nil
}
func (s *testRPCServer) GetUserStats(_ context.Context, request *emptypb.Empty) (*supervisorv1.UserStatsResponse, error) {
	if err := s.record("GetUserStats", request); err != nil {
		return nil, err
	}
	return proto.Clone(s.stats).(*supervisorv1.UserStatsResponse), nil
}

func newBufconnClient(t *testing.T, api supervisorv1.SupervisorServer, tokenFile string, interceptor grpc.UnaryServerInterceptor) (*Client, *testRPCServer) {
	t.Helper()
	server, ok := api.(*testRPCServer)
	if !ok {
		t.Fatalf("test API has unexpected type %T", api)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(interceptor))
	RegisterRPC(grpcServer, api)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() { grpcServer.Stop(); _ = listener.Close() })
	connection, err := grpc.NewClient("passthrough:///supervisor-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return NewClientWithConn(connection, tokenFile), server
}

func verifyTestSignature(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		values, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		get := func(key string) string {
			entries := values.Get(key)
			if len(entries) != 1 {
				return ""
			}
			return entries[0]
		}
		operation, nonce, signature := get("x-xray-operation"), get("x-xray-nonce"), get("x-xray-signature")
		message, ok := request.(proto.Message)
		if !ok || operation == "" || nonce == "" || signature == "" {
			return nil, status.Error(codes.Unauthenticated, "bad signed request")
		}
		body, err := DeterministicBytes(message)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal request")
		}
		digest := sha256.Sum256(body)
		canonical := strings.Join([]string{info.FullMethod, operation, nonce, hex.EncodeToString(digest[:])}, "\n")
		mac := hmac.New(sha256.New, []byte(token))
		_, _ = mac.Write([]byte(canonical))
		provided, err := hex.DecodeString(signature)
		if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
			return nil, status.Error(codes.Unauthenticated, "invalid signature")
		}
		if operation == "healthcheck" && info.FullMethod != supervisorv1.Supervisor_Health_FullMethodName {
			return nil, status.Error(codes.PermissionDenied, "healthcheck scope")
		}
		return handler(ctx, request)
	}
}

func writeTestToken(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClientMethodsUseTypedSupervisorContractAndDeterministicAuth(t *testing.T) {
	server := newTestRPCServer()
	client, _ := newBufconnClient(t, server, writeTestToken(t, "test-token\n"), verifyTestSignature("test-token"))
	ctx := interaction.WithStateRevision(interaction.WithRequestID(context.Background(), "abcdef0123456789abcdef0123456789"), 23)
	if err := client.Health(ctx); err != nil {
		t.Fatal(err)
	}
	statusResult, err := client.Status(ctx)
	if err != nil || statusResult.Protocol != "v1" || statusResult.State != "running" || statusResult.PID != 123 || statusResult.RestartCount != 4 || statusResult.ConfigPath != "/etc/xray/active.json" || !statusResult.StartedAt.Equal(time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("Status() = %+v, %v", statusResult, err)
	}
	if lines, err := client.Logs(ctx); err != nil || !reflect.DeepEqual(lines, []string{"one", "two"}) {
		t.Fatalf("Logs() = %v, %v", lines, err)
	}
	if err := client.Validate(ctx, "/etc/xray/candidate.json", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "/etc/xray/candidate.json", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceInbound(ctx, "/candidate.json", "/active.json", "vless-reality", "op-3"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeTarget(ctx, "example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeIPv6(ctx); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { return client.AddUser(ctx, "v@example.test", "uuid", "vision") },
		func() error { return client.RemoveUser(ctx, "v@example.test") },
		func() error { return client.AddVMessUser(ctx, "m@example.test", "uuid") },
		func() error { return client.RemoveVMessUser(ctx, "m@example.test") },
		func() error { return client.AddHysteriaUser(ctx, "h@example.test", "password") },
		func() error { return client.RemoveHysteriaUser(ctx, "h@example.test") },
	} {
		if err := call(); err != nil {
			t.Fatal(err)
		}
	}
	if users, err := client.Users(ctx); err != nil || !reflect.DeepEqual(users, []string{"device@example.test"}) {
		t.Fatalf("Users() = %v, %v", users, err)
	}
	if users, err := client.UsersInInbound(ctx, "vmess-tls"); err != nil || len(users) != 1 {
		t.Fatalf("UsersInInbound() = %v, %v", users, err)
	}
	if users, err := client.UsersInInbound(ctx, "hysteria2"); err != nil || len(users) != 1 {
		t.Fatalf("Hysteria UsersInInbound() = %v, %v", users, err)
	}
	stats, err := client.Poll(ctx)
	if err != nil || len(stats) != 1 || stats[0].UploadBytes != 12 || stats[0].DownloadBytes != 34 {
		t.Fatalf("Poll() = %+v, %v", stats, err)
	}
	if len(server.requests) != 11 {
		t.Fatalf("RPC method count = %d, calls: %v", len(server.requests), server.requests)
	}
	apply := server.requests["ApplyConfig"][0].(*supervisorv1.ApplyConfigRequest)
	if apply.Path != "/etc/xray/candidate.json" || apply.OperationId != "op-2" || apply.StateRevision != 23 {
		t.Fatalf("typed ApplyConfig request = %+v", apply)
	}
	replace := server.requests["ReplaceInbound"][0].(*supervisorv1.ReplaceInboundRequest)
	if replace.Tag != "vless-reality" || replace.StateRevision != 23 {
		t.Fatalf("typed ReplaceInbound request = %+v", replace)
	}
	alter := server.requests["AlterUser"]
	if len(alter) != 6 || alter[0].(*supervisorv1.AlterUserRequest).Protocol != supervisorv1.XrayProtocol_XRAY_PROTOCOL_VLESS || alter[2].(*supervisorv1.AlterUserRequest).Protocol != supervisorv1.XrayProtocol_XRAY_PROTOCOL_VMESS || alter[4].(*supervisorv1.AlterUserRequest).Protocol != supervisorv1.XrayProtocol_XRAY_PROTOCOL_HYSTERIA2 {
		t.Fatalf("typed AlterUser requests = %+v", alter)
	}
}

func TestClientValidatesTypedResponses(t *testing.T) {
	badTimestamp := &supervisorv1.SupervisorStatus{Protocol: "v1", XrayVersion: "Xray", State: "running", StartedAt: &timestamppb.Timestamp{Seconds: 999999999999}}
	for _, test := range []struct {
		name  string
		setup func(*testRPCServer)
		run   func(*Client) error
	}{
		{"negative pid", func(s *testRPCServer) { s.status.Pid = -1 }, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"missing status fields", func(s *testRPCServer) { s.status.Protocol = "" }, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"invalid timestamp", func(s *testRPCServer) { s.status = badTimestamp }, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"invalid stats counter", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{Email: "phone", UploadBytes: -1}}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"missing stats email", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{UploadBytes: 1}}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"nil stats user", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{nil}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"invalid IP entry", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{Email: "phone", SourceIps: []*supervisorv1.SourceIPObservation{nil}}}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"invalid user timestamp", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{Email: "phone", LastSeen: &timestamppb.Timestamp{Seconds: 999999999999}}}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"invalid source timestamp", func(s *testRPCServer) {
			s.stats = &supervisorv1.UserStatsResponse{Users: []*supervisorv1.XrayUserStats{{Email: "phone", SourceIps: []*supervisorv1.SourceIPObservation{{Address: "203.0.113.1", LastSeen: &timestamppb.Timestamp{Seconds: 999999999999}}}}}}
		}, func(c *Client) error { _, err := c.Poll(context.Background()); return err }},
		{"unsuccessful target probe", func(s *testRPCServer) { s.probeTarget = &supervisorv1.ProbeTargetResponse{} }, func(c *Client) error { return c.ProbeTarget(context.Background(), "host:443", "host") }},
		{"unsuccessful IPv6 probe", func(s *testRPCServer) { s.probeIPv6 = &supervisorv1.ProbeIPv6Response{} }, func(c *Client) error { return c.ProbeIPv6(context.Background()) }},
		{"unhealthy response", func(s *testRPCServer) { s.health = &supervisorv1.HealthResponse{State: "starting"} }, func(c *Client) error { return c.Health(context.Background()) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestRPCServer()
			test.setup(server)
			client, _ := newBufconnClient(t, server, writeTestToken(t, "token"), verifyTestSignature("token"))
			if err := test.run(client); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
}

func TestClientRPCFailuresAndInvalidSetup(t *testing.T) {
	server := newTestRPCServer()
	server.errors["GetUserStats"] = status.Error(codes.Unavailable, "stats unavailable")
	server.errors["ProbeTarget"] = status.Error(codes.Unavailable, "probe unavailable")
	server.errors["ProbeIPv6"] = status.Error(codes.Unavailable, "IPv6 probe unavailable")
	server.errors["GetStatus"] = status.Error(codes.Unavailable, "status unavailable")
	server.errors["GetLogs"] = status.Error(codes.Unavailable, "logs unavailable")
	client, _ := newBufconnClient(t, server, writeTestToken(t, "token"), verifyTestSignature("token"))
	if _, err := client.Poll(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("Poll RPC error = %v", err)
	}
	if err := client.ProbeTarget(context.Background(), "host:443", "host"); status.Code(err) != codes.Unavailable {
		t.Fatalf("ProbeTarget RPC error = %v", err)
	}
	if err := client.ProbeIPv6(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("ProbeIPv6 RPC error = %v", err)
	}
	if _, err := client.Status(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("Status RPC error = %v", err)
	}
	if _, err := client.Logs(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("Logs RPC error = %v", err)
	}
	if _, err := client.UsersInInbound(context.Background(), "unknown"); err == nil {
		t.Fatal("unknown inbound accepted")
	}
	if err := client.AddProtocolUser(context.Background(), "unsupported", "email", "id", ""); err == nil {
		t.Fatal("unknown protocol accepted")
	}
	if err := client.RemoveProtocolUser(context.Background(), "unsupported", "email"); err == nil {
		t.Fatal("unknown protocol accepted")
	}
	if err := (&Client{}).Health(context.Background()); err == nil {
		t.Fatal("uninitialized client accepted")
	}
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := NewClientWithConn(nil, "").Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial("", ""); err == nil {
		t.Fatal("empty address accepted")
	}
	if _, err := Dial("not-host-port", ""); err == nil {
		t.Fatal("invalid address accepted")
	}
	if _, err := Dial("host:0", ""); err == nil {
		t.Fatal("invalid port accepted")
	}
	if _, err := DialWithOperation("localhost:1234", "", "other"); err == nil {
		t.Fatal("invalid operation accepted")
	}
	if _, err := DialWithOperation("localhost:1234", "", operationControlPlane); err != nil {
		t.Fatalf("Dial() = %v", err)
	}
}

func TestHealthcheckClientIsRestrictedToHealthMethod(t *testing.T) {
	server := newTestRPCServer()
	client, _ := newBufconnClient(t, server, writeTestToken(t, "token"), verifyTestSignature("token"))
	client.operation = operationHealthcheck
	if err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(context.Background(), "/candidate", "op"); err == nil {
		t.Fatal("healthcheck client invoked Apply")
	}
}

func TestSigningAndDeterministicSerializationFailures(t *testing.T) {
	ctx := context.Background()
	request := &supervisorv1.ApplyConfigRequest{Path: "/candidate", OperationId: "operation", StateRevision: 19}
	if _, err := signRequest(ctx, filepath.Join(t.TempDir(), "missing"), operationControlPlane, supervisorv1.Supervisor_ApplyConfig_FullMethodName, request); err == nil {
		t.Fatal("missing token accepted")
	}
	emptyToken := writeTestToken(t, " \n")
	if _, err := signRequest(ctx, emptyToken, operationControlPlane, supervisorv1.Supervisor_ApplyConfig_FullMethodName, request); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := signRequest(ctx, writeTestToken(t, "token"), operationControlPlane, supervisorv1.Supervisor_ApplyConfig_FullMethodName, &supervisorv1.ApplyConfigRequest{Path: string([]byte{0xff})}); err == nil {
		t.Fatal("invalid UTF-8 protobuf string accepted")
	}
	left, err := DeterministicBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	right, err := DeterministicBytes(proto.Clone(request))
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(left, right) {
		t.Fatal("deterministic protobuf bytes differ for equal messages")
	}
}

func TestProtobufTimeValidation(t *testing.T) {
	if got, err := protobufTimeToTime("time", nil); err != nil || !got.IsZero() {
		t.Fatalf("nil time = %v, %v", got, err)
	}
	want := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	if got, err := protobufTimeToTime("time", timestamppb.New(want)); err != nil || !got.Equal(want) {
		t.Fatalf("timestamp = %v, %v", got, err)
	}
	if _, err := protobufTimeToTime("time", &timestamppb.Timestamp{Seconds: 999999999999}); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
}

func TestDialWithOperationValidatesAddressButCanClose(t *testing.T) {
	path := writeTestToken(t, "token")
	client, err := DialWithOperation("127.0.0.1:10086", path, operationControlPlane)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	healthcheck, err := DialWithOperation("127.0.0.1:10086", path, operationHealthcheck)
	if err != nil {
		t.Fatal(err)
	}
	if err := healthcheck.Close(); err != nil {
		t.Fatal(err)
	}
}

var _ supervisorv1.SupervisorServer = (*testRPCServer)(nil)
