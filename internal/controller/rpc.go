// Package controller contains the private gRPC Controller boundary and its
// adapters to protocol runtime services.
package controller

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const RPCServiceName = "xrayeasy.controller.v1.Controller"

// RPCServer is the transport-level Controller API.
type RPCServer interface {
	Health(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetCapabilities(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetLogs(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ValidateConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ApplyConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ReplaceInbound(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ProbeTarget(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ProbeIPv6(context.Context, *structpb.Struct) (*structpb.Struct, error)
	AddDeviceUser(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RemoveDeviceUser(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ListDeviceUsers(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetXrayTelemetry(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetAmneziaWGStatus(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ListAmneziaWGPeers(context.Context, *structpb.Struct) (*structpb.Struct, error)
	CreateAmneziaWGPeer(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RemoveAmneziaWGPeer(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetAmneziaWGPeerStats(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetAmneziaWGClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ExportAmneziaWGBackup(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RestoreAmneziaWGBackup(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

// RegisterRPC registers the handwritten gRPC service descriptor.
func RegisterRPC(registrar grpc.ServiceRegistrar, api RPCServer) {
	methods := []string{"Health", "GetCapabilities", "GetStatus", "GetLogs", "ValidateConfig", "ApplyConfig", "ReplaceInbound", "ProbeTarget", "ProbeIPv6", "AddDeviceUser", "RemoveDeviceUser", "ListDeviceUsers", "GetXrayTelemetry", "GetAmneziaWGStatus", "ListAmneziaWGPeers", "CreateAmneziaWGPeer", "RemoveAmneziaWGPeer", "GetAmneziaWGPeerStats", "GetAmneziaWGClientConfig", "ExportAmneziaWGBackup", "RestoreAmneziaWGBackup"}
	desc := &grpc.ServiceDesc{ServiceName: RPCServiceName, HandlerType: (*RPCServer)(nil)}
	for _, name := range methods {
		desc.Methods = append(desc.Methods, structMethod(name, api))
	}
	registrar.RegisterService(desc, api)
}

func structMethod(name string, api RPCServer) grpc.MethodDesc {
	fullMethod := "/" + RPCServiceName + "/" + name
	return grpc.MethodDesc{MethodName: name, Handler: func(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := new(structpb.Struct)
		if err := decode(request); err != nil {
			return nil, err
		}
		call := func(ctx context.Context, request any) (any, error) {
			switch name {
			case "Health":
				return api.Health(ctx, request.(*structpb.Struct))
			case "GetCapabilities":
				return api.GetCapabilities(ctx, request.(*structpb.Struct))
			case "GetStatus":
				return api.GetStatus(ctx, request.(*structpb.Struct))
			case "GetLogs":
				return api.GetLogs(ctx, request.(*structpb.Struct))
			case "ValidateConfig":
				return api.ValidateConfig(ctx, request.(*structpb.Struct))
			case "ApplyConfig":
				return api.ApplyConfig(ctx, request.(*structpb.Struct))
			case "ReplaceInbound":
				return api.ReplaceInbound(ctx, request.(*structpb.Struct))
			case "ProbeTarget":
				return api.ProbeTarget(ctx, request.(*structpb.Struct))
			case "ProbeIPv6":
				return api.ProbeIPv6(ctx, request.(*structpb.Struct))
			case "AddDeviceUser":
				return api.AddDeviceUser(ctx, request.(*structpb.Struct))
			case "RemoveDeviceUser":
				return api.RemoveDeviceUser(ctx, request.(*structpb.Struct))
			case "ListDeviceUsers":
				return api.ListDeviceUsers(ctx, request.(*structpb.Struct))
			case "GetXrayTelemetry":
				return api.GetXrayTelemetry(ctx, request.(*structpb.Struct))
			case "GetAmneziaWGStatus":
				return api.GetAmneziaWGStatus(ctx, request.(*structpb.Struct))
			case "ListAmneziaWGPeers":
				return api.ListAmneziaWGPeers(ctx, request.(*structpb.Struct))
			case "CreateAmneziaWGPeer":
				return api.CreateAmneziaWGPeer(ctx, request.(*structpb.Struct))
			case "RemoveAmneziaWGPeer":
				return api.RemoveAmneziaWGPeer(ctx, request.(*structpb.Struct))
			case "GetAmneziaWGPeerStats":
				return api.GetAmneziaWGPeerStats(ctx, request.(*structpb.Struct))
			case "GetAmneziaWGClientConfig":
				return api.GetAmneziaWGClientConfig(ctx, request.(*structpb.Struct))
			case "ExportAmneziaWGBackup":
				return api.ExportAmneziaWGBackup(ctx, request.(*structpb.Struct))
			case "RestoreAmneziaWGBackup":
				return api.RestoreAmneziaWGBackup(ctx, request.(*structpb.Struct))
			default:
				panic("unregistered Controller RPC method: " + name)
			}
		}
		if interceptor == nil {
			return call(ctx, request)
		}
		return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: server, FullMethod: fullMethod}, call)
	}}
}
