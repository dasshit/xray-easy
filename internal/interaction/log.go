package interaction

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LogRPC writes payload-free structured metadata for one RPC boundary.
func LogRPC(logger *slog.Logger, service, method, requestID, protocol string, started time.Time, err error, trace ...Trace) {
	if logger == nil {
		logger = slog.Default()
	}
	fields := Trace{Attempt: 1}
	if len(trace) > 0 {
		fields = trace[0]
		if fields.Attempt < 1 {
			fields.Attempt = 1
		}
	}
	code, level, result := "OK", slog.LevelInfo, "success"
	if errors.Is(err, context.Canceled) {
		code, result = codes.Canceled.String(), "canceled"
	} else if err != nil {
		code, level, result = status.Code(err).String(), slog.LevelError, "failure"
	}
	attrs := []slog.Attr{
		slog.String("service", service),
		slog.String("method", method),
		slog.String("request_id", requestID),
		slog.String("controller_operation_id", fields.OperationID),
		slog.Int("retry_attempt", fields.Attempt),
		slog.String("protocol", protocol),
		slog.String("result", result),
		slog.String("grpc_code", code),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	}
	if fields.StateRevision > 0 {
		attrs = append(attrs, slog.Int64("state_revision", fields.StateRevision))
	}
	logger.LogAttrs(context.Background(), level, "grpc interaction", attrs...)
}
