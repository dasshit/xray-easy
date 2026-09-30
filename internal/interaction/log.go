package interaction

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/status"
)

// LogRPC writes payload-free structured metadata for one RPC boundary.
func LogRPC(logger *slog.Logger, service, method, requestID, protocol string, started time.Time, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	code, level, result := "OK", slog.LevelInfo, "success"
	if err != nil {
		code, level, result = status.Code(err).String(), slog.LevelError, "failure"
	}
	logger.LogAttrs(context.Background(), level, "grpc interaction",
		slog.String("service", service),
		slog.String("method", method),
		slog.String("request_id", requestID),
		slog.String("protocol", protocol),
		slog.String("result", result),
		slog.String("grpc_code", code),
		slog.Int64("duration_ms", time.Since(started).Milliseconds()),
	)
}
