package controller

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRPCDispatchWithoutInterceptors(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterRPC(server, NewService(&fakeRuntime{}))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///controller-no-interceptor", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	response := new(structpb.Struct)
	if err := connection.Invoke(context.Background(), "/"+RPCServiceName+"/Health", &structpb.Struct{}, response); err != nil {
		t.Fatalf("Health without interceptor: %v", err)
	}
}

func TestRPCHandlerDecodeErrorAndUnknownDispatch(t *testing.T) {
	api := NewService(&fakeRuntime{})
	handler := structMethod("Health", api).Handler
	if _, err := handler(nil, context.Background(), func(any) error { return errors.New("decode failed") }, nil); err == nil || !strings.Contains(err.Error(), "decode failed") {
		t.Fatalf("decode error = %v", err)
	}
	unknown := structMethod("Unknown", api).Handler
	defer func() {
		if recover() == nil {
			t.Fatal("unknown RPC dispatch did not panic")
		}
	}()
	_, _ = unknown(nil, context.Background(), func(value any) error { value.(*structpb.Struct).Reset(); return nil }, nil)
}

func TestRPCDispatchesEveryRegisteredMethod(t *testing.T) {
	api := NewService(&fakeRuntime{})
	methods := []string{
		"Health", "GetCapabilities", "GetStatus", "GetLogs", "ValidateConfig", "ApplyConfig",
		"ReplaceInbound", "ProbeTarget", "ProbeIPv6", "AddDeviceUser", "RemoveDeviceUser",
		"ListDeviceUsers", "GetXrayTelemetry", "GetAmneziaWGStatus", "ListAmneziaWGPeers",
		"CreateAmneziaWGPeer", "RemoveAmneziaWGPeer", "GetAmneziaWGPeerStats",
		"GetAmneziaWGClientConfig", "ExportAmneziaWGBackup", "RestoreAmneziaWGBackup",
	}
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			handler := structMethod(name, api).Handler
			_, _ = handler(nil, context.Background(), func(value any) error {
				value.(*structpb.Struct).Reset()
				return nil
			}, nil)
		})
	}
}

func TestLoggingInterceptorPreservesHandlerErrors(t *testing.T) {
	want := status.Error(codes.Unavailable, "adapter offline")
	_, err := LoggingInterceptor("controller-test")(
		context.Background(), &structpb.Struct{}, &grpc.UnaryServerInfo{FullMethod: "/controller/Health"},
		func(context.Context, any) (any, error) { return nil, want },
	)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("logging interceptor error = %v, want Unavailable", err)
	}
}

func TestProtocolForRPCUsesOnlySafeProtocolMetadata(t *testing.T) {
	for _, test := range []struct {
		method  string
		request map[string]any
		want    string
	}{
		{"/controller/Health", map[string]any{"id": "uuid"}, "runtime"},
		{"/controller/GetCapabilities", nil, "runtime"},
		{"/controller/GetAmneziaWGStatus", nil, "amneziawg"},
		{"/controller/AddDeviceUser", map[string]any{"protocol": "vless", "id": "private"}, "vless"},
		{"/controller/AddDeviceUser", map[string]any{"protocol": "hysteria2"}, "hysteria2"},
		{"/controller/GetStatus", nil, "xray"},
		{"/controller/AddDeviceUser", map[string]any{"protocol": "unexpected"}, "xray"},
	} {
		var request *structpb.Struct
		if test.request != nil {
			request, _ = structpb.NewStruct(test.request)
		}
		if got := protocolForRPC(test.method, request); got != test.want {
			t.Errorf("protocolForRPC(%q) = %q, want %q", test.method, got, test.want)
		}
	}
}
