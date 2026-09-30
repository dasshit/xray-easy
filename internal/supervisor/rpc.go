package supervisor

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

const RPCServiceName = "xrayeasy.supervisor.v1.Supervisor"

// RPCServer is the private process-control surface implemented by xray-supervisor.
type RPCServer interface {
	Health(context.Context, *emptypb.Empty) (*structpb.Struct, error)
	GetStatus(context.Context, *emptypb.Empty) (*structpb.Struct, error)
	GetLogs(context.Context, *emptypb.Empty) (*structpb.Struct, error)
	ValidateConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ApplyConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ReplaceInbound(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ProbeTarget(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ProbeIPv6(context.Context, *emptypb.Empty) (*structpb.Struct, error)
}

// RegisterRPC registers the supervisor service without generated code, matching
// the existing internal AmneziaWG service descriptor approach.
func RegisterRPC(registrar grpc.ServiceRegistrar, api RPCServer) {
	registrar.RegisterService(rpcServiceDescription(api), api)
}

func rpcServiceDescription(api RPCServer) *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: RPCServiceName,
		HandlerType: (*RPCServer)(nil),
		Methods: []grpc.MethodDesc{
			emptyMethod("Health", api.Health),
			emptyMethod("GetStatus", api.GetStatus),
			emptyMethod("GetLogs", api.GetLogs),
			structMethod("ValidateConfig", api.ValidateConfig),
			structMethod("ApplyConfig", api.ApplyConfig),
			structMethod("ReplaceInbound", api.ReplaceInbound),
			structMethod("ProbeTarget", api.ProbeTarget),
			emptyMethod("ProbeIPv6", api.ProbeIPv6),
		},
	}
}

func emptyMethod(name string, call func(context.Context, *emptypb.Empty) (*structpb.Struct, error)) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := new(emptypb.Empty)
		if err := decode(request); err != nil {
			return nil, err
		}
		invoke := func(ctx context.Context, request any) (any, error) { return call(ctx, request.(*emptypb.Empty)) }
		if interceptor == nil {
			return invoke(ctx, request)
		}
		return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: server, FullMethod: "/" + RPCServiceName + "/" + name}, invoke)
	}}
}

func structMethod(name string, call func(context.Context, *structpb.Struct) (*structpb.Struct, error)) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := new(structpb.Struct)
		if err := decode(request); err != nil {
			return nil, err
		}
		invoke := func(ctx context.Context, request any) (any, error) { return call(ctx, request.(*structpb.Struct)) }
		if interceptor == nil {
			return invoke(ctx, request)
		}
		return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: server, FullMethod: "/" + RPCServiceName + "/" + name}, invoke)
	}}
}

// DeterministicBytes serializes a message with stable protobuf field ordering.
func DeterministicBytes(message proto.Message) ([]byte, error) {
	return (proto.MarshalOptions{Deterministic: true}).Marshal(message)
}
