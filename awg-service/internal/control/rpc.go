package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// traceContextKey is an internal type used by the package.
type traceContextKey string

const (
	// requestIDKey is an internal package constant.
	requestIDKey traceContextKey = "x-request-id"
	// operationIDKey is an internal package constant.
	operationIDKey traceContextKey = "x-controller-operation-id"
	// attemptKey is an internal package constant.
	attemptKey traceContextKey = "x-controller-attempt"
	// revisionKey is an internal package constant.
	revisionKey traceContextKey = "x-controller-state-revision"
)

// OperationID returns the Controller operation ID attached by the server interceptor.
func OperationID(ctx context.Context) string {
	value, _ := ctx.Value(operationIDKey).(string)
	return value
}

// StateRevision returns the desired-state revision attached by the interceptor.
func StateRevision(ctx context.Context) int64 {
	value, _ := ctx.Value(revisionKey).(int64)
	return value
}

// API is the generated, authenticated private AWG control surface.
type API = awgapi.ControlServer

// Register installs the generated AWG protobuf service.
func Register(server grpc.ServiceRegistrar, api API) {
	awgapi.RegisterControlServer(server, api)
}

// AuthInterceptor rejects requests unless they carry the configured bearer token.
func AuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		values, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing control token")
		}
		provided := ""
		if entries := values.Get("authorization"); len(entries) == 1 && strings.HasPrefix(entries[0], "Bearer ") {
			provided = strings.TrimPrefix(entries[0], "Bearer ")
		}
		if len(provided) != len(token) || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid control token")
		}
		return handler(ctx, request)
	}
}

// AuthStreamInterceptor checks the same private bearer token on server streams.
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
			return status.Error(codes.Unauthenticated, "invalid control token")
		}
		return handler(server, stream)
	}
}

// LoggingInterceptor records request correlation and outcome without logging
// protobuf payloads, peer credentials, or raw error messages.
func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, requestID, operationID, attempt, traceErr := ensureIncomingTrace(ctx)
		if traceErr != nil {
			return nil, status.Error(codes.Internal, "could not create request identifier")
		}
		started := time.Now()
		response, err := handler(ctx, request)
		code, result, level := codes.OK.String(), "success", slog.LevelInfo
		if err != nil {
			code, result, level = status.Code(err).String(), "failure", slog.LevelError
		}
		attrs := []slog.Attr{
			slog.String("service", "awg-service"), slog.String("method", info.FullMethod),
			slog.String("request_id", requestID), slog.String("controller_operation_id", operationID),
			slog.Int("retry_attempt", attempt), slog.String("protocol", "amneziawg"),
			slog.String("result", result), slog.String("grpc_code", code),
			slog.Int64("duration_ms", time.Since(started).Milliseconds()),
		}
		if revision := StateRevision(ctx); revision > 0 {
			attrs = append(attrs, slog.Int64("state_revision", revision))
		}
		slog.Default().LogAttrs(context.Background(), level, "grpc interaction", attrs...)
		return response, err
	}
}

// LoggingStreamInterceptor records stream lifecycle and result without logging
// peer telemetry or protobuf payloads.
func LoggingStreamInterceptor() grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, requestID, operationID, attempt, traceErr := ensureIncomingTrace(stream.Context())
		if traceErr != nil {
			return status.Error(codes.Internal, "could not create stream request identifier")
		}
		started := time.Now()
		err := handler(server, &controlContextServerStream{ServerStream: stream, ctx: ctx})
		code, result, level := codes.OK.String(), "success", slog.LevelInfo
		if err != nil && !errors.Is(err, context.Canceled) {
			code, result, level = status.Code(err).String(), "failure", slog.LevelError
		} else if errors.Is(err, context.Canceled) {
			code, result = codes.Canceled.String(), "canceled"
		}
		slog.Default().LogAttrs(context.Background(), level, "grpc stream", slog.String("service", "awg-service"), slog.String("method", info.FullMethod), slog.String("request_id", requestID), slog.String("controller_operation_id", operationID), slog.Int("retry_attempt", attempt), slog.String("protocol", "amneziawg"), slog.String("result", result), slog.String("grpc_code", code), slog.Int64("duration_ms", time.Since(started).Milliseconds()))
		return err
	}
}

// controlContextServerStream is an internal type used by the package.
type controlContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context associated with the value.
func (s *controlContextServerStream) Context() context.Context { return s.ctx }

// ensureIncomingTrace performs the operation represented by its name.
func ensureIncomingTrace(ctx context.Context) (context.Context, string, string, int, error) {
	values, _ := metadata.FromIncomingContext(ctx)
	readID := func(key string) string {
		items := values.Get(key)
		if len(items) != 1 || len(items[0]) != 32 {
			return ""
		}
		if _, err := hex.DecodeString(items[0]); err != nil {
			return ""
		}
		return strings.ToLower(items[0])
	}
	newID := func() (string, error) {
		value := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, value); err != nil {
			return "", err
		}
		return hex.EncodeToString(value), nil
	}
	requestID := readID("x-request-id")
	if requestID == "" {
		var err error
		requestID, err = newID()
		if err != nil {
			return nil, "", "", 0, err
		}
	}
	operationID := readID("x-controller-operation-id")
	if operationID == "" {
		var err error
		operationID, err = newID()
		if err != nil {
			return nil, "", "", 0, err
		}
	}
	attempt := 1
	if items := values.Get("x-controller-attempt"); len(items) == 1 {
		if parsed, err := strconv.Atoi(items[0]); err == nil && parsed > 0 && parsed <= 1_000_000 {
			attempt = parsed
		}
	}
	var revision int64
	if items := values.Get("x-controller-state-revision"); len(items) == 1 {
		if parsed, err := strconv.ParseInt(items[0], 10, 64); err == nil && parsed > 0 {
			revision = parsed
		}
	}
	ctx = context.WithValue(ctx, requestIDKey, requestID)
	ctx = context.WithValue(ctx, operationIDKey, operationID)
	ctx = context.WithValue(ctx, attemptKey, attempt)
	if revision > 0 {
		ctx = context.WithValue(ctx, revisionKey, revision)
	}
	return ctx, requestID, operationID, attempt, nil
}

// mapError performs the operation represented by its name.
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
	if errors.Is(err, ErrOperationConflict) {
		return status.Error(codes.Aborted, err.Error())
	}
	if errors.Is(err, ErrOperationCompleted) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, ErrPeerExpired) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, ErrPeerExpiryPending) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, "AWG operation failed")
}
