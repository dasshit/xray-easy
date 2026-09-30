package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const serviceName = "xrayeasy.awg.v1.Control"

type traceContextKey string

const (
	requestIDKey   traceContextKey = "x-request-id"
	operationIDKey traceContextKey = "x-controller-operation-id"
	attemptKey     traceContextKey = "x-controller-attempt"
	revisionKey    traceContextKey = "x-controller-state-revision"
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
		if _, err := rand.Read(value); err != nil {
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
	if errors.Is(err, ErrOperationConflict) {
		return status.Error(codes.Aborted, err.Error())
	}
	if errors.Is(err, ErrOperationCompleted) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if errors.Is(err, ErrInvalid) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, "AWG operation failed")
}
