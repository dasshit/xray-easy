package controller

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	controllerv1 "xray-easy/internal/controller/api/v1"
)

func TestGeneratedRPCHealthRoundTripWithoutInterceptors(t *testing.T) {
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
	response := new(controllerv1.HealthResponse)
	if err := connection.Invoke(context.Background(), controllerv1.Controller_Health_FullMethodName, &controllerv1.EmptyRequest{}, response); err != nil || !response.Ok {
		t.Fatalf("Health without interceptor: response=%+v err=%v", response, err)
	}
}

func TestControllerTelemetryStreamRequiresBearerAndHonorsCancellation(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ChainStreamInterceptor(LoggingStreamInterceptor("controller-stream-test"), AuthStreamInterceptor("stream-test-token")))
	RegisterRPC(server, NewService(&fakeRuntime{}))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///controller-stream-auth", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	client := controllerv1.NewControllerClient(connection)
	request := &controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}
	unauthorized, err := client.WatchTelemetry(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unauthorized.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated stream error = %v", err)
	}
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer stream-test-token"))
	stream, err := client.WatchTelemetry(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil || !first.GetFullSnapshot() {
		t.Fatalf("first telemetry message = %+v, %v", first, err)
	}
	cancel()
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := stream.Recv(); status.Code(err) == codes.Canceled {
			return
		} else if err != nil {
			t.Fatalf("canceled stream error = %v", err)
		}
	}
	t.Fatal("canceled stream did not terminate")
}

func TestLeaseTokenIsRestrictedToLeaseRPCs(t *testing.T) {
	interceptor := AuthInterceptorWithLeaseToken("admin-secret", "lease-secret")
	info := &grpc.UnaryServerInfo{FullMethod: controllerv1.Controller_DisconnectLease_FullMethodName}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer lease-secret"))
	_, err := interceptor(ctx, &controllerv1.EmptyRequest{}, info, func(callContext context.Context, _ any) (any, error) {
		if got := ControllerIdentityFromContext(callContext); got != "lease-service" {
			t.Fatalf("lease identity = %q", got)
		}
		return &controllerv1.DisconnectLeaseResponse{}, nil
	})
	if err != nil {
		t.Fatalf("allowed lease RPC: %v", err)
	}
	info.FullMethod = controllerv1.Controller_GetStatus_FullMethodName
	_, err = interceptor(ctx, &controllerv1.EmptyRequest{}, info, func(context.Context, any) (any, error) {
		t.Fatal("lease token reached a forbidden admin RPC")
		return nil, nil
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forbidden lease RPC error = %v", err)
	}
	adminContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer admin-secret"))
	_, err = interceptor(adminContext, &controllerv1.EmptyRequest{}, info, func(callContext context.Context, _ any) (any, error) {
		if got := ControllerIdentityFromContext(callContext); got != "admin" {
			t.Fatalf("admin identity = %q", got)
		}
		return &controllerv1.StatusResponse{}, nil
	})
	if err != nil {
		t.Fatalf("admin RPC: %v", err)
	}
}

func TestGeneratedRPCDispatchesEveryTypedMethod(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterRPC(server, NewService(&fakeRuntime{}))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///controller-all-methods", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	cases := []struct {
		method   string
		request  proto.Message
		response proto.Message
	}{
		{"Health", &controllerv1.EmptyRequest{}, &controllerv1.HealthResponse{}},
		{"GetCapabilities", &controllerv1.EmptyRequest{}, &controllerv1.CapabilitiesResponse{}},
		{"GetStatus", &controllerv1.EmptyRequest{}, &controllerv1.StatusResponse{}},
		{"GetLogs", &controllerv1.EmptyRequest{}, &controllerv1.LogsResponse{}},
		{"ValidateConfig", &controllerv1.ValidateConfigRequest{}, &controllerv1.OperationResponse{}},
		{"ApplyConfig", &controllerv1.ApplyConfigRequest{}, &controllerv1.OperationResponse{}},
		{"ReplaceInbound", &controllerv1.ReplaceInboundRequest{}, &controllerv1.OperationResponse{}},
		{"ProbeTarget", &controllerv1.ProbeTargetRequest{}, &controllerv1.OperationResponse{}},
		{"ProbeIPv6", &controllerv1.EmptyRequest{}, &controllerv1.ProbeIPv6Response{}},
		{"SetXrayLogLevel", &controllerv1.SetXrayLogLevelRequest{Level: "debug"}, &controllerv1.OperationResponse{}},
		{"AddDeviceUser", &controllerv1.AddDeviceUserRequest{}, &controllerv1.OperationResponse{}},
		{"RemoveDeviceUser", &controllerv1.RemoveDeviceUserRequest{}, &controllerv1.OperationResponse{}},
		{"ListDeviceUsers", &controllerv1.ListDeviceUsersRequest{}, &controllerv1.ListDeviceUsersResponse{}},
		{"GetXrayTelemetry", &controllerv1.EmptyRequest{}, &controllerv1.XrayTelemetryResponse{}},
		{"DisconnectLease", &controllerv1.DisconnectLeaseRequest{Protocol: "vless", ProfileEmail: "device@xray-easy", SourceIp: "192.0.2.1", OperationId: "0123456789abcdef0123456789abcdef", SourceGeneration: "runtime-generation"}, &controllerv1.DisconnectLeaseResponse{}},
		{"GetAmneziaWGStatus", &controllerv1.EmptyRequest{}, &controllerv1.AmneziaWGStatusResponse{}},
		{"ListAmneziaWGPeers", &controllerv1.EmptyRequest{}, &controllerv1.ListAmneziaWGPeersResponse{}},
		{"CreateAmneziaWGPeer", &controllerv1.CreateAmneziaWGPeerRequest{}, &controllerv1.AmneziaWGPeer{}},
		{"RemoveAmneziaWGPeer", &controllerv1.RemoveAmneziaWGPeerRequest{}, &controllerv1.OperationResponse{}},
		{"GetAmneziaWGPeerStats", &controllerv1.EmptyRequest{}, &controllerv1.AmneziaWGPeerStatsResponse{}},
		{"GetAmneziaWGClientConfig", &controllerv1.GetAmneziaWGClientConfigRequest{}, &controllerv1.AmneziaWGClientConfigResponse{}},
		{"ExportAmneziaWGBackup", &controllerv1.EmptyRequest{}, &controllerv1.AmneziaWGBackupResponse{}},
		{"RestoreAmneziaWGBackup", &controllerv1.RestoreAmneziaWGBackupRequest{}, &controllerv1.OperationResponse{}},
	}
	if got := controllerv1.File_controller_proto.Services().Get(0).Methods().Len(); got != len(cases)+2 {
		t.Fatalf("generated RPC descriptor methods=%d, test cases=%d", got, len(cases))
	}
	watch := controllerv1.File_controller_proto.Services().Get(0).Methods().ByName("WatchTelemetry")
	if watch == nil || !watch.IsStreamingServer() {
		t.Fatalf("WatchTelemetry descriptor is missing server streaming")
	}
	leaseWatch := controllerv1.File_controller_proto.Services().Get(0).Methods().ByName("WatchLeaseSnapshots")
	if leaseWatch == nil || !leaseWatch.IsStreamingServer() {
		t.Fatalf("WatchLeaseSnapshots descriptor is missing server streaming")
	}
	for _, test := range cases {
		t.Run(test.method, func(t *testing.T) {
			err := connection.Invoke(context.Background(), "/"+RPCServiceName+"/"+test.method, test.request, test.response)
			if status.Code(err) == codes.Unimplemented {
				t.Fatalf("generated method is not registered: %v", err)
			}
		})
	}
}

func TestLoggingInterceptorPreservesHandlerErrors(t *testing.T) {
	want := status.Error(codes.Unavailable, "adapter offline")
	_, err := LoggingInterceptor("controller-test")(
		context.Background(), &controllerv1.EmptyRequest{}, &grpc.UnaryServerInfo{FullMethod: "/controller/Health"},
		func(context.Context, any) (any, error) { return nil, want },
	)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("logging interceptor error = %v, want Unavailable", err)
	}
}

func TestProtocolForRPCUsesOnlySafeTypedMetadata(t *testing.T) {
	for _, test := range []struct {
		method  string
		request proto.Message
		want    string
	}{
		{"/controller/Health", &controllerv1.EmptyRequest{}, "runtime"},
		{"/controller/GetCapabilities", &controllerv1.EmptyRequest{}, "runtime"},
		{"/controller/GetAmneziaWGStatus", &controllerv1.EmptyRequest{}, "amneziawg"},
		{"/controller/AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "vless", Id: "private"}, "vless"},
		{"/controller/AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "hysteria2"}, "hysteria2"},
		{"/controller/GetStatus", &controllerv1.EmptyRequest{}, "xray"},
		{"/controller/AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "unexpected"}, "xray"},
	} {
		if got := protocolForRPC(test.method, test.request); got != test.want {
			t.Errorf("protocolForRPC(%q) = %q, want %q", test.method, got, test.want)
		}
	}
}

func TestGeneratedRPCContractHasNoStructFields(t *testing.T) {
	service := controllerv1.File_controller_proto.Services().Get(0)
	for index := 0; index < service.Methods().Len(); index++ {
		method := service.Methods().Get(index)
		if strings.Contains(string(method.Input().FullName()), "Struct") || strings.Contains(string(method.Output().FullName()), "Struct") {
			t.Fatalf("RPC %s still uses Struct messages", method.Name())
		}
	}
}
