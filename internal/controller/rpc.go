// Package controller contains the private gRPC Controller boundary and its
// adapters to protocol runtime services.
package controller

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	controllerv1 "xray-easy/internal/controller/api/v1"
	"xray-easy/internal/interaction"
)

// RPCServiceName identifies a supported package value.
const RPCServiceName = "xrayeasy.controller.v1.Controller"

// RPCServer is the generated transport-level Controller API.
type RPCServer = controllerv1.ControllerServer

// RegisterRPC registers the generated typed Controller gRPC service.
func RegisterRPC(registrar grpc.ServiceRegistrar, api RPCServer) {
	controllerv1.RegisterControllerServer(registrar, api)
}

// AuthStreamInterceptor authenticates Controller server streams with the
// same private bearer token used by its unary API.
func AuthStreamInterceptor(token string) grpc.StreamServerInterceptor {
	return AuthStreamInterceptorWithLeaseToken(token, "")
}

// AuthStreamInterceptorWithLeaseToken authenticates Controller streams with
// separate administrator and lease-service identities.
func AuthStreamInterceptorWithLeaseToken(token, leaseToken string) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		identity, err := controllerIdentity(stream.Context(), info.FullMethod, token, leaseToken)
		if err != nil {
			return err
		}
		return handler(server, &controllerIdentityServerStream{ServerStream: stream, ctx: context.WithValue(stream.Context(), controllerIdentityContextKey{}, identity)})
	}
}

// controllerIdentityServerStream exposes the authenticated identity in stream context.
type controllerIdentityServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the stream context annotated with the authenticated caller.
func (s *controllerIdentityServerStream) Context() context.Context { return s.ctx }

// LoggingStreamInterceptor logs stream completion metadata without payloads.
func LoggingStreamInterceptor(service string) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, requestID, traceErr := interaction.EnsureIncoming(stream.Context())
		if traceErr != nil {
			return status.Error(codes.Internal, "could not create stream request identifier")
		}
		started := time.Now()
		err := handler(server, &controllerContextServerStream{ServerStream: stream, ctx: ctx})
		protocol := "runtime"
		if strings.Contains(info.FullMethod, "Lease") {
			protocol = "lease"
		}
		interaction.LogRPC(slog.Default(), service, info.FullMethod, requestID, protocol, started, err, interaction.TraceFromContext(ctx))
		return err
	}
}

// controllerContextServerStream is an internal type used by the package.
type controllerContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context associated with the value.
func (s *controllerContextServerStream) Context() context.Context { return s.ctx }
