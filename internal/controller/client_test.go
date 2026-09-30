package controller

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/interaction"
	"xray-easy/internal/supervisor"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	if err != nil || statusValue.XrayVersion != "26.7.28" || statusValue.PID != 5 || !statusValue.StartedAt.Equal(runtime.status.StartedAt) {
		t.Fatalf("Status() = %+v, %v", statusValue, err)
	}
	lines, err := client.Logs(ctx)
	if err != nil || len(lines) != 1 || lines[0] != "line" {
		t.Fatalf("Logs() = %v, %v", lines, err)
	}
	if err := client.Validate(ctx, "/candidate", "11111111111111111111111111111111"); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "/candidate", "22222222222222222222222222222222"); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceInbound(ctx, "/candidate", "/active", "vless", "33333333333333333333333333333333"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeTarget(ctx, "example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeIPv6(ctx); err != nil {
		t.Fatal(err)
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil || capabilities.Xray == nil || !capabilities.Xray.Configured {
		t.Fatalf("Capabilities() = %+v, %v", capabilities, err)
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

func TestProtocolForClientCallUsesTypedProtocolOnly(t *testing.T) {
	for _, test := range []struct {
		method  string
		request proto.Message
		want    string
	}{
		{"Health", &controllerv1.EmptyRequest{}, "runtime"},
		{"GetCapabilities", &controllerv1.EmptyRequest{}, "runtime"},
		{"GetAmneziaWGClientConfig", &controllerv1.GetAmneziaWGClientConfigRequest{Name: "private"}, "amneziawg"},
		{"AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "vless", Id: "secret"}, "vless"},
		{"AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "vmess"}, "vmess"},
		{"AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "hysteria2"}, "hysteria2"},
		{"GetStatus", &controllerv1.EmptyRequest{}, "xray"},
	} {
		if got := protocolForClientCall(test.method, test.request); got != test.want {
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

func TestClientUnauthorizedAndMalformedTypedResponses(t *testing.T) {
	client, connection := controllerTestClient(t, &fakeRuntime{}, "right")
	client.token = "wrong"
	if err := client.Health(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Health() err = %v", err)
	}
	response := new(controllerv1.HealthResponse)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer wrong")
	if err := connection.Invoke(ctx, controllerv1.Controller_Health_FullMethodName, &controllerv1.EmptyRequest{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthorized Invoke() = %v", err)
	}
	if err := connection.Invoke(context.Background(), controllerv1.Controller_Health_FullMethodName, &controllerv1.EmptyRequest{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing auth Invoke() = %v", err)
	}
	repeated := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer right", "authorization", "Bearer right")
	if err := connection.Invoke(repeated, controllerv1.Controller_Health_FullMethodName, &controllerv1.EmptyRequest{}, response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("repeated auth Invoke() = %v", err)
	}
	if err := (&Client{}).Health(context.Background()); err == nil {
		t.Fatal("uninitialized client call succeeded")
	}
	if _, err := (&Client{}).call(context.Background(), "bad", &controllerv1.EmptyRequest{}); err == nil {
		t.Fatal("unknown RPC method accepted")
	}
	if _, err := protobufTimeToTime("timestamp", &timestamppb.Timestamp{Seconds: 999999999999}); err == nil {
		t.Fatal("invalid protobuf timestamp accepted")
	}
}

type staticInvoker struct {
	value  proto.Message
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

func TestClientStatusValidatesRequiredCountersAndTimestamp(t *testing.T) {
	for _, response := range []*controllerv1.StatusResponse{
		{Protocol: "v1", State: "running"},
		{Protocol: "v1", XrayVersion: "x", State: "running", Pid: -1},
		{Protocol: "v1", XrayVersion: "x", State: "running", RestartCount: -1},
		{Protocol: "v1", XrayVersion: "x", State: "running", StartedAt: &timestamppb.Timestamp{Seconds: 999999999999}},
	} {
		client := NewClientWithConn(&staticInvoker{value: response}, "token")
		if _, err := client.Status(context.Background()); err == nil {
			t.Fatalf("invalid status was accepted: %+v", response)
		}
	}
	response := &controllerv1.StatusResponse{Protocol: "v1", XrayVersion: "26.7.28", State: "running"}
	if _, err := NewClientWithConn(&staticInvoker{value: response}, "token").Status(context.Background()); err != nil {
		t.Fatalf("valid status without optional timestamp rejected: %v", err)
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
