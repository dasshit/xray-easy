package controller

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	controllerv1 "xray-easy/internal/controller/api/v1"
	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor requires the private Controller bearer token.
func AuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		values, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing Controller token")
		}
		entries := values.Get("authorization")
		provided := ""
		if len(entries) == 1 && strings.HasPrefix(entries[0], "Bearer ") {
			provided = strings.TrimPrefix(entries[0], "Bearer ")
		}
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid Controller token")
		}
		return handler(ctx, request)
	}
}

// LoggingInterceptor records safe RPC metadata and never serializes messages.
func LoggingInterceptor(service string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, requestID, err := interaction.EnsureIncoming(ctx)
		if err != nil {
			return nil, status.Error(codes.Internal, "could not create request identifier")
		}
		started := time.Now()
		response, callErr := handler(ctx, request)
		interaction.LogRPC(nil, service, info.FullMethod, requestID, protocolForRPC(info.FullMethod, request), started, callErr, interaction.TraceFromContext(ctx))
		return response, callErr
	}
}

func protocolForRPC(method string, request any) string {
	if strings.Contains(method, "AmneziaWG") {
		return "amneziawg"
	}
	if strings.HasSuffix(method, "/Health") || strings.HasSuffix(method, "/GetCapabilities") {
		return "runtime"
	}
	switch value := request.(type) {
	case *controllerv1.AddDeviceUserRequest:
		return safeProtocolName(value.GetProtocol())
	case *controllerv1.RemoveDeviceUserRequest:
		return safeProtocolName(value.GetProtocol())
	case *controllerv1.ListDeviceUsersRequest:
		return safeProtocolName(value.GetProtocol())
	}
	return "xray"
}

func safeProtocolName(protocol string) string {
	switch protocol {
	case "vless", "vmess", "hysteria2", "amneziawg":
		return protocol
	default:
		return "xray"
	}
}
