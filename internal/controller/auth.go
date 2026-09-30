package controller

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
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
		interaction.LogRPC(nil, service, info.FullMethod, requestID, protocolForRPC(info.FullMethod, request), started, callErr)
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
	if value, ok := request.(*structpb.Struct); ok {
		if protocol := value.GetFields()["protocol"]; protocol != nil {
			if text, ok := protocol.GetKind().(*structpb.Value_StringValue); ok {
				switch text.StringValue {
				case "vless", "vmess", "hysteria2", "amneziawg":
					return text.StringValue
				}
			}
		}
	}
	return "xray"
}
