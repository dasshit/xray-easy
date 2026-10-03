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
	return AuthInterceptorWithLeaseToken(token, "")
}

// AuthInterceptorWithLeaseToken authenticates the administrator token for all
// methods and a separate lease token for the small lease-service method set.
func AuthInterceptorWithLeaseToken(token, leaseToken string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		identity, err := controllerIdentity(ctx, info.FullMethod, token, leaseToken)
		if err != nil {
			return nil, err
		}
		return handler(context.WithValue(ctx, controllerIdentityContextKey{}, identity), request)
	}
}

// controllerIdentityContextKey stores the authenticated Controller caller.
type controllerIdentityContextKey struct{}

// ControllerIdentityFromContext returns the authenticated Controller caller.
func ControllerIdentityFromContext(ctx context.Context) string {
	identity, _ := ctx.Value(controllerIdentityContextKey{}).(string)
	return identity
}

// controllerIdentity validates the bearer token and applies the lease method ACL.
func controllerIdentity(ctx context.Context, method, adminToken, leaseToken string) (string, error) {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing Controller token")
	}
	entries := values.Get("authorization")
	provided := ""
	if len(entries) == 1 && strings.HasPrefix(entries[0], "Bearer ") {
		provided = strings.TrimPrefix(entries[0], "Bearer ")
	}
	if validControllerToken(provided, adminToken) {
		return "admin", nil
	}
	if validControllerToken(provided, leaseToken) {
		if !leaseMethodAllowed(method) {
			return "", status.Error(codes.PermissionDenied, "lease-service identity cannot call this method")
		}
		return "lease-service", nil
	}
	return "", status.Error(codes.Unauthenticated, "invalid Controller token")
}

// validControllerToken compares a supplied bearer token without timing leaks.
func validControllerToken(provided, expected string) bool {
	return expected != "" && len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// leaseMethodAllowed limits the dedicated lease identity to read/enforcement RPCs.
func leaseMethodAllowed(method string) bool {
	switch method {
	case "/xrayeasy.controller.v1.Controller/Health",
		"/xrayeasy.controller.v1.Controller/GetCapabilities",
		"/xrayeasy.controller.v1.Controller/WatchLeaseSnapshots",
		"/xrayeasy.controller.v1.Controller/DisconnectLease":
		return true
	default:
		return false
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

// protocolForRPC performs the operation represented by its name.
func protocolForRPC(method string, request any) string {
	if strings.Contains(method, "Lease") {
		return "lease"
	}
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

// safeProtocolName performs the operation represented by its name.
func safeProtocolName(protocol string) string {
	switch protocol {
	case "vless", "vmess", "hysteria2", "shadowsocks", "trojan", "amneziawg":
		return protocol
	default:
		return "xray"
	}
}
