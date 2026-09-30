// Package interaction carries safe correlation metadata across private service
// calls without exposing request payloads or credentials to logs.
package interaction

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

const metadataKey = "x-request-id"

var randomRead = rand.Read

type contextKey struct{}

// NewRequestID returns a random 128-bit hexadecimal correlation identifier.
func NewRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := randomRead(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

// WithRequestID stores a validated correlation identifier in ctx.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if !validRequestID(requestID) {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, strings.ToLower(requestID))
}

// RequestID returns the correlation identifier stored in ctx, if any.
func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{}).(string)
	return value
}

// IncomingRequestID reads a well-formed ID from incoming gRPC metadata.
func IncomingRequestID(ctx context.Context) string {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	items := values.Get(metadataKey)
	if len(items) != 1 || !validRequestID(items[0]) {
		return ""
	}
	return strings.ToLower(items[0])
}

// OutgoingContext forwards an existing ID or creates one for background work.
func OutgoingContext(ctx context.Context) (context.Context, string, error) {
	requestID := RequestID(ctx)
	if requestID == "" {
		requestID = IncomingRequestID(ctx)
	}
	if requestID == "" {
		var err error
		requestID, err = NewRequestID()
		if err != nil {
			return nil, "", err
		}
	}
	ctx = WithRequestID(ctx, requestID)
	if values, ok := metadata.FromOutgoingContext(ctx); ok {
		items := values.Get(metadataKey)
		if len(items) == 1 && strings.EqualFold(items[0], requestID) {
			return ctx, requestID, nil
		}
	}
	return metadata.AppendToOutgoingContext(ctx, metadataKey, requestID), requestID, nil
}

// EnsureIncoming attaches an incoming request ID to ctx, generating one when
// the caller omitted or supplied malformed metadata.
func EnsureIncoming(ctx context.Context) (context.Context, string, error) {
	requestID := IncomingRequestID(ctx)
	if requestID == "" {
		var err error
		requestID, err = NewRequestID()
		if err != nil {
			return nil, "", err
		}
	}
	return WithRequestID(ctx, requestID), requestID, nil
}

// HTTPMiddleware creates a server-owned ID, makes it available to downstream
// calls, and returns it to the caller for log correlation.
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID, err := NewRequestID()
		if err != nil {
			http.Error(writer, "could not create request identifier", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(writer, request.WithContext(WithRequestID(request.Context(), requestID)))
	})
}

func validRequestID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
