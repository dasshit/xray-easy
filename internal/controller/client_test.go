package controller

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/interaction"
	"xray-easy/internal/supervisor"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func controllerTestClient(t *testing.T, runtime *fakeRuntime, token string) (*Client, *grpc.ClientConn) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggingInterceptor("controller-test"), AuthInterceptor(token)))
	RegisterRPC(server, NewService(runtime))
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///controller-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Stop(); _ = connection.Close(); _ = listener.Close() })
	return NewClientWithConn(connection, token), connection
}

func TestClientInvokesControllerAndForwardsRequestID(t *testing.T) {
	runtime := &fakeRuntime{status: supervisor.Status{Protocol: "v1", XrayVersion: "26.7.28", State: "running", PID: 5, RestartCount: 1, StartedAt: time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC)}, logs: []string{"line"}}
	client, _ := controllerTestClient(t, runtime, "test-token")
	wantID := "abcdef0123456789abcdef0123456789"
	wantOperationID := "0123456789abcdef0123456789abcdef"
	ctx := interaction.WithStateRevision(
		interaction.WithAttempt(
			interaction.WithOperationID(interaction.WithRequestID(context.Background(), wantID), wantOperationID), 3), 42)
	if err := client.Health(ctx); err != nil || runtime.requestID != wantID || runtime.operationID != wantOperationID || runtime.attempt != 3 || runtime.stateRevision != 42 {
		t.Fatalf("Health() trace=%q/%q/%d/%d, err=%v", runtime.requestID, runtime.operationID, runtime.attempt, runtime.stateRevision, err)
	}
	statusValue, err := client.Status(ctx)
	if err != nil || statusValue.XrayVersion != "26.7.28" || statusValue.PID != 5 {
		t.Fatalf("Status() = %+v, %v", statusValue, err)
	}
	lines, err := client.Logs(ctx)
	if err != nil || len(lines) != 1 || lines[0] != "line" {
		t.Fatalf("Logs() = %v, %v", lines, err)
	}
	if err := client.Validate(ctx, "/candidate", "validate-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "/candidate", "apply-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceInbound(ctx, "/candidate", "/active", "vless", "replace-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeTarget(ctx, "example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeIPv6(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBackendControllerAndXrayAdapterShareMutationTrace(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggingInterceptor("controller-test"), AuthInterceptor("test-token")))
	handler := &fakeXrayHandler{}
	RegisterRPC(server, NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil))
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///controller-trace-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	defer connection.Close()
	defer listener.Close()
	client := NewClientWithConn(connection, "test-token")
	requestID := "abcdef0123456789abcdef0123456789"
	operationID := "0123456789abcdef0123456789abcdef"
	ctx := interaction.WithStateRevision(interaction.WithAttempt(interaction.WithOperationID(interaction.WithRequestID(context.Background(), requestID), operationID), 2), 77)
	if err := client.AddUser(ctx, "device-1-vless@xray-easy", "stable-uuid", "vision"); err != nil {
		t.Fatal(err)
	}
	if handler.adds != 1 || len(handler.traces) != 2 || len(handler.requestIDs) != 2 {
		t.Fatalf("runtime observed calls=%d traces=%+v IDs=%v", handler.adds, handler.traces, handler.requestIDs)
	}
	for index, trace := range handler.traces {
		if trace.OperationID != operationID || trace.Attempt != 2 || trace.StateRevision != 77 || handler.requestIDs[index] != requestID {
			t.Errorf("adapter trace[%d] = %+v requestID=%q", index, trace, handler.requestIDs[index])
		}
	}
}

func TestProtocolForClientCallClassifiesWithoutLoggingRequestFields(t *testing.T) {
	for _, test := range []struct {
		method string
		fields map[string]any
		want   string
	}{
		{"Health", nil, "runtime"},
		{"GetCapabilities", nil, "runtime"},
		{"GetAmneziaWGClientConfig", map[string]any{"name": "private"}, "amneziawg"},
		{"AddDeviceUser", map[string]any{"protocol": "vless", "id": "secret"}, "vless"},
		{"AddDeviceUser", map[string]any{"protocol": "vmess"}, "vmess"},
		{"AddDeviceUser", map[string]any{"protocol": "hysteria2"}, "hysteria2"},
		{"GetStatus", nil, "xray"},
	} {
		if got := protocolForClientCall(test.method, test.fields); got != test.want {
			t.Errorf("protocolForClientCall(%q) = %q, want %q", test.method, got, test.want)
		}
	}
}

func TestClientDialAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := Dial("127.0.0.1:1", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := NewClientWithConn(nil, "token").Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial("127.0.0.1:1", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Dial with missing token succeeded")
	}
	if err := os.WriteFile(path, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial("127.0.0.1:1", path); err == nil {
		t.Fatal("Dial with empty token succeeded")
	}
}

func TestClientUnauthorizedAndMalformedResponses(t *testing.T) {
	client, connection := controllerTestClient(t, &fakeRuntime{}, "right")
	client.token = "wrong"
	if err := client.Health(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Health() err = %v", err)
	}
	response := new(structpb.Struct)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer wrong")
	if err := connection.Invoke(ctx, "/"+RPCServiceName+"/Health", &structpb.Struct{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthorized Invoke() = %v", err)
	}
	if err := connection.Invoke(context.Background(), "/"+RPCServiceName+"/Health", &structpb.Struct{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing auth Invoke() = %v", err)
	}
	repeated := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer right", "authorization", "Bearer right")
	if err := connection.Invoke(repeated, "/"+RPCServiceName+"/Health", &structpb.Struct{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("repeated auth Invoke() = %v", err)
	}
	if _, err := responseString(nil, "required", true); err == nil {
		t.Fatal("missing required string accepted")
	}
	if _, err := responseString(map[string]*structpb.Value{"key": structpb.NewNumberValue(1)}, "key", false); err == nil {
		t.Fatal("number response string accepted")
	}
	if _, err := responseInt(nil, "pid"); err == nil {
		t.Fatal("missing integer accepted")
	}
	if _, err := responseInt(map[string]*structpb.Value{"pid": structpb.NewStringValue("1")}, "pid"); err == nil {
		t.Fatal("string integer accepted")
	}
	for _, number := range []float64{-1, 1.5, float64(int(^uint(0)>>1)) + 1} {
		if _, err := responseInt(map[string]*structpb.Value{"pid": structpb.NewNumberValue(number)}, "pid"); err == nil {
			t.Fatalf("invalid integer %v accepted", number)
		}
	}
	if err := (&Client{}).Health(context.Background()); err == nil {
		t.Fatal("uninitialized client call succeeded")
	}
	if _, err := client.call(context.Background(), "bad", map[string]any{"unsupported": make(chan int)}); err == nil {
		t.Fatal("unsupported request value accepted")
	}
}

func TestClientRejectsMalformedLogs(t *testing.T) {
	api := &malformedLogsAPI{}
	client, connection := clientForAPI(t, api)
	defer connection.Close()
	if _, err := client.Logs(context.Background()); err == nil {
		t.Fatal("malformed log entry accepted")
	}
	client, connection = clientForAPI(t, &emptyLogsAPI{})
	defer connection.Close()
	if _, err := client.Logs(context.Background()); err == nil {
		t.Fatal("missing log lines accepted")
	}
}

type staticInvoker struct {
	value  *structpb.Struct
	err    error
	method string
}

func (f *staticInvoker) Invoke(_ context.Context, method string, _ any, reply any, _ ...grpc.CallOption) error {
	f.method = method
	if f.err != nil {
		return f.err
	}
	proto.Merge(reply.(proto.Message), f.value)
	return nil
}
func (*staticInvoker) Close() error { return nil }

func TestClientStatusStrictlyDecodesEveryField(t *testing.T) {
	valid := map[string]any{"protocol": "v1", "xray_version": "26.7.28", "state": "running", "pid": 3, "config_path": "/active", "last_error": "", "last_exit": "", "restart_count": 1, "started_at": "2026-09-30T12:00:00Z"}
	mutations := []struct {
		name   string
		update func(map[string]any)
	}{
		{"missing protocol", func(v map[string]any) { delete(v, "protocol") }},
		{"wrong protocol type", func(v map[string]any) { v["protocol"] = true }},
		{"missing version", func(v map[string]any) { delete(v, "xray_version") }},
		{"wrong state type", func(v map[string]any) { v["state"] = 3 }},
		{"wrong config path type", func(v map[string]any) { v["config_path"] = 3 }},
		{"wrong last error type", func(v map[string]any) { v["last_error"] = false }},
		{"wrong last exit type", func(v map[string]any) { v["last_exit"] = false }},
		{"invalid pid", func(v map[string]any) { v["pid"] = "3" }},
		{"missing restart count", func(v map[string]any) { delete(v, "restart_count") }},
		{"invalid timestamp type", func(v map[string]any) { v["started_at"] = true }},
		{"invalid timestamp", func(v map[string]any) { v["started_at"] = "tomorrow" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			fields := make(map[string]any, len(valid))
			for key, value := range valid {
				fields[key] = value
			}
			test.update(fields)
			value, err := structpb.NewStruct(fields)
			if err != nil {
				t.Fatal(err)
			}
			client := NewClientWithConn(&staticInvoker{value: value}, "token")
			if _, err := client.Status(context.Background()); err == nil {
				t.Fatal("malformed status was accepted")
			}
		})
	}
	fields := make(map[string]any, len(valid))
	for key, value := range valid {
		fields[key] = value
	}
	fields["started_at"] = ""
	value, _ := structpb.NewStruct(fields)
	if _, err := NewClientWithConn(&staticInvoker{value: value}, "token").Status(context.Background()); err != nil {
		t.Fatalf("empty optional timestamp rejected: %v", err)
	}
}

func TestClientRPCErrorIncludesMethodOnly(t *testing.T) {
	invoker := &staticInvoker{err: status.Error(codes.Unavailable, "sensitive detail")}
	client := NewClientWithConn(invoker, "token")
	if err := client.Health(context.Background()); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "Health") {
		t.Fatalf("Health() error = %v", err)
	}
	if strings.Contains(invoker.method, "sensitive") {
		t.Fatalf("method unexpectedly includes error data: %q", invoker.method)
	}
}

type malformedLogsAPI struct{ Service }

func (*malformedLogsAPI) GetLogs(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"lines": []any{42}})
}

type emptyLogsAPI struct{ Service }

func (*emptyLogsAPI) GetLogs(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return &structpb.Struct{}, nil
}

func clientForAPI(t *testing.T, api RPCServer) (*Client, *grpc.ClientConn) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(AuthInterceptor("token")))
	RegisterRPC(server, api)
	go func() { _ = server.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///malformed", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return NewClientWithConn(connection, "token"), connection
}
