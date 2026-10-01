// Package controller contains the private gRPC Controller boundary and its
// adapters to protocol runtime services.
package controller

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	controllerv1 "xray-easy/internal/controller/api/v1"
	"xray-easy/internal/interaction"
)

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
	return func(server any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		values, ok := metadata.FromIncomingContext(stream.Context())
		provided := ""
		if ok {
			if entries := values.Get("authorization"); len(entries) == 1 && strings.HasPrefix(entries[0], "Bearer ") {
				provided = strings.TrimPrefix(entries[0], "Bearer ")
			}
		}
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			return status.Error(codes.Unauthenticated, "invalid Controller token")
		}
		return handler(server, stream)
	}
}

// LoggingStreamInterceptor logs stream completion metadata without payloads.
func LoggingStreamInterceptor(service string) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, requestID, traceErr := interaction.EnsureIncoming(stream.Context())
		if traceErr != nil {
			return status.Error(codes.Internal, "could not create stream request identifier")
		}
		started := time.Now()
		err := handler(server, &controllerContextServerStream{ServerStream: stream, ctx: ctx})
		interaction.LogRPC(slog.Default(), service, info.FullMethod, requestID, "runtime", started, err, interaction.TraceFromContext(ctx))
		return err
	}
}

type controllerContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *controllerContextServerStream) Context() context.Context { return s.ctx }
