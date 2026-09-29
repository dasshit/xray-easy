package control

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const serviceName = "xrayeasy.awg.v1.Control"

// API is the authenticated, private gRPC surface used by the Xray-easy control plane.
type API interface {
	GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ListPeers(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetPeerStats(context.Context, *structpb.Struct) (*structpb.Struct, error)
	CreatePeer(context.Context, *structpb.Struct) (*structpb.Struct, error)
	AddPeer(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RemovePeer(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ExportBackup(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RestoreBackup(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RenderClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

// Register installs the prototype service descriptor without generated code.
func Register(server grpc.ServiceRegistrar, api API) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*API)(nil),
		Methods: []grpc.MethodDesc{
			method("GetStatus", api.GetStatus),
			method("ListPeers", api.ListPeers),
			method("GetPeerStats", api.GetPeerStats),
			method("CreatePeer", api.CreatePeer),
			method("AddPeer", api.AddPeer),
			method("RemovePeer", api.RemovePeer),
			method("GetClientConfig", api.GetClientConfig),
			method("ExportBackup", api.ExportBackup),
			method("RestoreBackup", api.RestoreBackup),
			method("RenderClientConfig", api.RenderClientConfig),
		},
	}, api)
}

func method(name string, call func(context.Context, *structpb.Struct) (*structpb.Struct, error)) grpc.MethodDesc {
	fullMethod := "/" + serviceName + "/" + name
	return grpc.MethodDesc{MethodName: name, Handler: func(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		request := new(structpb.Struct)
		if err := decode(request); err != nil {
			return nil, err
		}
		invoke := func(ctx context.Context, request any) (any, error) {
			return call(ctx, request.(*structpb.Struct))
		}
		if interceptor == nil {
			return invoke(ctx, request)
		}
		return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: server, FullMethod: fullMethod}, invoke)
	}}
}

// AuthInterceptor rejects requests unless they carry the configured bearer token.
func AuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		values, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing control token")
		}
		provided := ""
		if entries := values.Get("authorization"); len(entries) > 0 {
			if strings.HasPrefix(entries[0], "Bearer ") {
				provided = strings.TrimPrefix(entries[0], "Bearer ")
			}
		}
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid control token")
		}
		return handler(ctx, request)
	}
}

// Field helpers keep decoding strict and return safe gRPC validation errors.
func stringField(request *structpb.Struct, key string) (string, error) {
	value := request.GetFields()[key]
	if value == nil {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", key)
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", status.Errorf(codes.InvalidArgument, "%s must be a string", key)
	}
	if value.GetStringValue() == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", key)
	}
	return value.GetStringValue(), nil
}

func response(fields map[string]any) (*structpb.Struct, error) {
	result, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("encode response: %w", err)
	}
	return result, nil
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, ErrAlreadyExists) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	if errors.Is(err, ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, "AWG operation failed")
}
