package supervisor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"xray-easy/internal/interaction"
)

const testToken = "shared-supervisor-token"

type testRPCServer struct {
	validateRequest *structpb.Struct
	applyRequest    *structpb.Struct
	replaceRequest  *structpb.Struct
	probeRequest    *structpb.Struct
	statusResponse  *structpb.Struct
	logsResponse    *structpb.Struct
	usersResponse   *structpb.Struct
	statsResponse   *structpb.Struct
	runtimeRequest  *structpb.Struct
	methodError     error
}

func (s *testRPCServer) Health(context.Context, *emptypb.Empty) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"ok": true, "state": "running", "protocol": "v1"})
}
func (s *testRPCServer) GetStatus(context.Context, *emptypb.Empty) (*structpb.Struct, error) {
	if s.methodError != nil {
		return nil, s.methodError
	}
	if s.statusResponse != nil {
		return s.statusResponse, nil
	}
	return structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray test", "state": "running", "pid": 123, "config_path": "/etc/xray/active.json", "last_error": "", "last_exit": "", "restart_count": 4, "started_at": "2026-09-30T10:00:00Z"})
}
func (s *testRPCServer) GetLogs(context.Context, *emptypb.Empty) (*structpb.Struct, error) {
	if s.methodError != nil {
		return nil, s.methodError
	}
	if s.logsResponse != nil {
		return s.logsResponse, nil
	}
	return structpb.NewStruct(map[string]any{"lines": []any{"one", "two"}})
}
func (s *testRPCServer) ValidateConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.validateRequest = request
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) ApplyConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.applyRequest = request
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) ReplaceInbound(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.replaceRequest = request
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) ProbeTarget(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.probeRequest = request
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) ProbeIPv6(context.Context, *emptypb.Empty) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) AlterUser(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.runtimeRequest = request
	if s.methodError != nil {
		return nil, s.methodError
	}
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (s *testRPCServer) ListUsers(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.runtimeRequest = request
	if s.methodError != nil {
		return nil, s.methodError
	}
	if s.usersResponse != nil {
		return s.usersResponse, nil
	}
	return structpb.NewStruct(map[string]any{"users": []any{"device@example.test"}})
}
func (s *testRPCServer) GetUserStats(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.runtimeRequest = request
	if s.methodError != nil {
		return nil, s.methodError
	}
	if s.statsResponse != nil {
		return s.statsResponse, nil
	}
	return structpb.NewStruct(map[string]any{"users": []any{
		map[string]any{"email": "device@example.test", "upload_bytes": "123", "download_bytes": "456", "last_seen": "2026-09-30T10:00:00Z", "source_ips": []any{map[string]any{"address": "203.0.113.2", "last_seen": "2026-09-30T09:59:00Z"}}},
	}})
}

func newBufconnClient(t *testing.T, api RPCServer, tokenFile string, interceptor grpc.UnaryServerInterceptor) *Client {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.UnaryInterceptor(interceptor))
	RegisterRPC(server, api)
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///supervisor-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
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
	return NewClientWithConn(conn, tokenFile)
}

func writeToken(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClientMethodsSignAndUseSupervisorGRPCContract(t *testing.T) {
	server := &testRPCServer{}
	client := newBufconnClient(t, server, writeToken(t, "  "+testToken+"\n"), verifyTestSignature(testToken))
	ctx := interaction.WithStateRevision(context.Background(), 23)
	if err := client.Validate(ctx, "/etc/xray/candidate.json", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "/etc/xray/candidate.json", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceInbound(ctx, "/etc/xray/candidate.json", "/etc/xray/active.json", "vless-reality", "op-3"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeTarget(ctx, "example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeIPv6(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.AddUser(ctx, "vless@example.test", "uuid", "xtls-rprx-vision"); err != nil {
		t.Fatal(err)
	}
	if err := client.AddHysteriaUser(ctx, "hy2@example.test", "password"); err != nil {
		t.Fatal(err)
	}
	if err := client.AddVMessUser(ctx, "vmess@example.test", "uuid"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveUser(ctx, "vless@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveHysteriaUser(ctx, "hy2@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveVMessUser(ctx, "vmess@example.test"); err != nil {
		t.Fatal(err)
	}
	if users, err := client.Users(ctx); err != nil || len(users) != 1 || users[0] != "device@example.test" {
		t.Fatalf("Users() = %v, %v", users, err)
	}
	if users, err := client.UsersInInbound(ctx, "hysteria2"); err != nil || len(users) != 1 {
		t.Fatalf("UsersInInbound() = %v, %v", users, err)
	}
	if _, err := client.UsersInInbound(ctx, "unsupported"); err == nil {
		t.Fatal("unsupported inbound was accepted")
	}
	stats, err := client.Poll(ctx)
	if err != nil || len(stats) != 1 || stats[0].UploadBytes != 123 || stats[0].DownloadBytes != 456 || len(stats[0].SourceIPs) != 1 || stats[0].SourceIPs[0].Address != "203.0.113.2" {
		t.Fatalf("Poll() = %+v, %v", stats, err)
	}
	if err := client.Health(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(ctx)
	if err != nil || status.Protocol != "v1" || status.State != "running" || status.PID != 123 || status.ConfigPath != "/etc/xray/active.json" || status.RestartCount != 4 || !status.StartedAt.Equal(time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	logs, err := client.Logs(ctx)
	if err != nil || len(logs) != 2 || logs[0] != "one" || logs[1] != "two" {
		t.Fatalf("Logs() = %v, %v", logs, err)
	}
	if server.validateRequest.GetFields()["path"].GetStringValue() != "/etc/xray/candidate.json" || server.validateRequest.GetFields()["operation_id"].GetStringValue() != "op-1" || server.validateRequest.GetFields()["state_revision"].GetStringValue() != "23" {
		t.Fatalf("ValidateConfig payload = %v", server.validateRequest)
	}
	if server.applyRequest.GetFields()["operation_id"].GetStringValue() != "op-2" || server.applyRequest.GetFields()["state_revision"].GetStringValue() != "23" || server.replaceRequest.GetFields()["tag"].GetStringValue() != "vless-reality" || server.replaceRequest.GetFields()["state_revision"].GetStringValue() != "23" || server.probeRequest.GetFields()["sni"].GetStringValue() != "example.com" {
		t.Fatalf("unexpected RPC payloads: apply=%v replace=%v probe=%v", server.applyRequest, server.replaceRequest, server.probeRequest)
	}
}

func TestRuntimeClientRejectsMalformedUserAndStatsResponses(t *testing.T) {
	server := &testRPCServer{}
	client := newBufconnClient(t, server, writeToken(t, testToken), verifyTestSignature(testToken))
	server.usersResponse, _ = structpb.NewStruct(map[string]any{"users": "not-list"})
	if _, err := client.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "users must be a list") {
		t.Fatalf("invalid users response = %v", err)
	}
	server.usersResponse, _ = structpb.NewStruct(map[string]any{"users": []any{4}})
	if _, err := client.Users(context.Background()); err == nil || !strings.Contains(err.Error(), "item 0 must be a string") {
		t.Fatalf("invalid user item response = %v", err)
	}
	for _, response := range []map[string]any{
		{"users": "not-list"},
		{"users": []any{"invalid-user"}},
		{"users": []any{map[string]any{"email": "device@example.test"}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "-1", "download_bytes": "0", "source_ips": []any{}}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "0", "download_bytes": "0", "last_seen": "invalid", "source_ips": []any{}}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "0", "download_bytes": "0", "source_ips": "not-list"}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "0", "download_bytes": "0", "source_ips": []any{4}}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "0", "download_bytes": "0", "source_ips": []any{map[string]any{}}}}},
		{"users": []any{map[string]any{"email": "device@example.test", "upload_bytes": "0", "download_bytes": "0", "source_ips": []any{map[string]any{"address": "203.0.113.2", "last_seen": "bad"}}}}},
	} {
		server.statsResponse, _ = structpb.NewStruct(response)
		if _, err := client.Poll(context.Background()); err == nil {
			t.Fatalf("malformed stats response accepted: %v", response)
		}
	}
	server.methodError = status.Error(codes.Unavailable, "runtime down")
	if err := client.AddUser(context.Background(), "email", "id", "flow"); status.Code(err) != codes.Unavailable {
		t.Fatalf("runtime RPC error = %v", err)
	}
}

func verifyTestSignature(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		values, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		operation, nonce, signature := values.Get("x-xray-operation"), values.Get("x-xray-nonce"), values.Get("x-xray-signature")
		if len(operation) != 1 || len(nonce) != 1 || len(signature) != 1 {
			return nil, status.Error(codes.Unauthenticated, "bad signed metadata")
		}
		if operation[0] != operationControlPlane && !(operation[0] == operationHealthcheck && strings.HasSuffix(info.FullMethod, "/Health")) {
			return nil, status.Error(codes.Unauthenticated, "bad signed operation")
		}
		nonceBytes, err := hex.DecodeString(nonce[0])
		if err != nil || len(nonceBytes) != 16 {
			return nil, status.Error(codes.Unauthenticated, "bad nonce")
		}
		message, ok := request.(proto.Message)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "request is not proto")
		}
		serialized, err := DeterministicBytes(message)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(serialized)
		canonical := strings.Join([]string{info.FullMethod, operation[0], nonce[0], hex.EncodeToString(hash[:])}, "\n")
		mac := hmac.New(sha256.New, []byte(token))
		_, _ = mac.Write([]byte(canonical))
		provided, err := hex.DecodeString(signature[0])
		if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
			return nil, status.Error(codes.Unauthenticated, "bad HMAC")
		}
		return handler(ctx, request)
	}
}

func TestClientReportsTokenAndConnectionErrors(t *testing.T) {
	client := NewClientWithConn(nil, filepath.Join(t.TempDir(), "missing-token"))
	if err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "connection is not initialized") {
		t.Fatalf("nil connection error = %v", err)
	}
	connClient := NewClientWithConn(noopConn{}, filepath.Join(t.TempDir(), "missing-token"))
	if err := connClient.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "read supervisor token") {
		t.Fatalf("missing token error = %v", err)
	}
	emptyToken := writeToken(t, " \n")
	connClient.TokenFile = emptyToken
	if err := connClient.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "token is empty") {
		t.Fatalf("empty token error = %v", err)
	}
	if _, err := Dial("", emptyToken); err == nil {
		t.Fatal("empty gRPC address accepted")
	}
	if _, err := DialWithOperation("127.0.0.1:1", emptyToken, "admin"); err == nil {
		t.Fatal("unknown operation identity accepted")
	}
	for _, address := range []string{" ", "localhost", ":10086", "localhost:0", "localhost:65536", "localhost:abc", "[::1]"} {
		if _, err := DialWithOperation(address, emptyToken, operationControlPlane); err == nil {
			t.Errorf("invalid supervisor address %q accepted", address)
		}
	}
}

type noopConn struct{}

func (noopConn) Invoke(context.Context, string, any, any, ...grpc.CallOption) error { return nil }
func (noopConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected stream")
}

func TestClientRestrictsHealthcheckIdentityAndMapsRPCError(t *testing.T) {
	server := &testRPCServer{methodError: status.Error(codes.Unavailable, "xray stopped")}
	client := newBufconnClient(t, server, writeToken(t, testToken), verifyTestSignature(testToken))
	client.operation = operationHealthcheck
	if err := client.Apply(context.Background(), "candidate", "op"); err == nil || !strings.Contains(err.Error(), "cannot invoke") {
		t.Fatalf("healthcheck identity apply error = %v", err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("healthcheck identity could not call health: %v", err)
	}
	client.operation = operationControlPlane
	_, err := client.Status(context.Background())
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "xray stopped") {
		t.Fatalf("RPC failure = %v", err)
	}
	if _, err := client.Logs(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("logs RPC failure = %v", err)
	}
}

func TestClientRejectsMalformedStatusAndLogsResponses(t *testing.T) {
	malformedStatus, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "state": "running"})
	server := &testRPCServer{statusResponse: malformedStatus}
	client := newBufconnClient(t, server, writeToken(t, testToken), verifyTestSignature(testToken))
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "missing xray_version") {
		t.Fatalf("missing status fields error = %v", err)
	}
	badStatus, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 1.5, "restart_count": 1})
	server.statusResponse = badStatus
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "pid must be an integer") {
		t.Fatalf("fractional pid error = %v", err)
	}
	badTime, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, "started_at": "not-a-time"})
	server.statusResponse = badTime
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "decode supervisor started_at") {
		t.Fatalf("invalid timestamp error = %v", err)
	}
	server.logsResponse, _ = structpb.NewStruct(map[string]any{"lines": "not-list"})
	if _, err := client.Logs(context.Background()); err == nil || !strings.Contains(err.Error(), "lines must be a list") {
		t.Fatalf("invalid log list error = %v", err)
	}
	server.logsResponse, _ = structpb.NewStruct(map[string]any{"lines": []any{"ok", 2}})
	if _, err := client.Logs(context.Background()); err == nil || !strings.Contains(err.Error(), "line 1 must be a string") {
		t.Fatalf("invalid log item error = %v", err)
	}
	server.logsResponse, _ = structpb.NewStruct(map[string]any{"lines": []any{nil}})
	if _, err := client.Logs(context.Background()); err == nil {
		t.Fatal("null log line accepted")
	}
	server.statusResponse, _ = structpb.NewStruct(map[string]any{
		"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 1, "restart_count": 0,
	})
	if got, err := client.Status(context.Background()); err != nil || !got.StartedAt.IsZero() || got.ConfigPath != "" {
		t.Fatalf("optional status fields = %+v, %v", got, err)
	}
	server.statusResponse, _ = structpb.NewStruct(map[string]any{
		"protocol": "v1", "xray_version": "Xray", "state": 1, "pid": 1, "restart_count": 0,
	})
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "state must be a string") {
		t.Fatalf("invalid status state = %v", err)
	}
	server.statusResponse, _ = structpb.NewStruct(map[string]any{
		"protocol": "v1", "xray_version": "Xray", "state": "running", "restart_count": 0,
	})
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "missing pid") {
		t.Fatalf("missing status pid = %v", err)
	}
	server.statusResponse, _ = structpb.NewStruct(map[string]any{
		"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": "not-number", "restart_count": 0,
	})
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "pid must be an integer") {
		t.Fatalf("invalid status pid = %v", err)
	}
	for _, fields := range []map[string]any{
		{"xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0},
		{"protocol": 1, "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, "config_path": 1},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, "last_error": 1},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, "last_exit": 1},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": "bad"},
		{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, "started_at": 1},
	} {
		server.statusResponse, _ = structpb.NewStruct(fields)
		if _, err := client.Status(context.Background()); err == nil {
			t.Errorf("malformed status accepted: %v", fields)
		}
	}
}

func TestDialAndCloseConnection(t *testing.T) {
	client, err := Dial("127.0.0.1:1", writeToken(t, testToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatalf("nil client close = %v", err)
	}
}

func TestDeterministicBytesPreservesCanonicalStructOrder(t *testing.T) {
	first, _ := structpb.NewStruct(map[string]any{"z": "last", "a": "first"})
	second, _ := structpb.NewStruct(map[string]any{"a": "first", "z": "last"})
	left, err := DeterministicBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := DeterministicBytes(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("deterministic protobuf differed: %x != %x", left, right)
	}
}

func TestRPCMethodHandlersCoverDirectAndDecodeFailurePaths(t *testing.T) {
	api := &testRPCServer{}
	for _, method := range rpcServiceDescription(api).Methods {
		_, err := method.Handler(api, context.Background(), func(any) error { return errors.New("decode failed") }, nil)
		if err == nil || err.Error() != "decode failed" {
			t.Fatalf("%s decode error = %v", method.MethodName, err)
		}
		response, err := method.Handler(api, context.Background(), func(destination any) error {
			switch value := destination.(type) {
			case *emptypb.Empty:
				*value = emptypb.Empty{}
			case *structpb.Struct:
				*value = structpb.Struct{}
			default:
				return fmt.Errorf("unexpected request type %T", destination)
			}
			return nil
		}, nil)
		if err != nil || response == nil {
			t.Fatalf("%s direct handler = %v, %v", method.MethodName, response, err)
		}
	}
}

func TestStatusOptionalFieldsAndResponseTypeFailures(t *testing.T) {
	server := &testRPCServer{}
	client := newBufconnClient(t, server, writeToken(t, testToken), verifyTestSignature(testToken))
	minimalStatus, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray", "state": "no-config", "pid": 0, "restart_count": 0})
	server.statusResponse = minimalStatus
	status, err := client.Status(context.Background())
	if err != nil || status.ConfigPath != "" || !status.StartedAt.IsZero() {
		t.Fatalf("optional status fields = %+v, %v", status, err)
	}
	for name, value := range map[string]any{
		"protocol": float64(7), "config_path": float64(7), "pid": "not-number", "restart_count": "not-number",
	} {
		badStatus, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": 0, "restart_count": 0, name: value})
		server.statusResponse = badStatus
		_, err := client.Status(context.Background())
		if err == nil {
			t.Fatalf("bad %s field accepted", name)
		}
	}
	badInt, _ := structpb.NewStruct(map[string]any{"protocol": "v1", "xray_version": "Xray", "state": "running", "pid": "not-number", "restart_count": 0})
	server.statusResponse = badInt
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "pid must be an integer") {
		t.Fatalf("string pid error = %v", err)
	}
	badLines, _ := structpb.NewStruct(map[string]any{})
	server.logsResponse = badLines
	if _, err := client.Logs(context.Background()); err == nil || !strings.Contains(err.Error(), "lines must be a list") {
		t.Fatalf("missing lines error = %v", err)
	}
}

func TestDialRejectsInvalidTarget(t *testing.T) {
	if _, err := Dial("http://[invalid", writeToken(t, testToken)); err == nil {
		t.Fatal("malformed gRPC target accepted")
	}
}
