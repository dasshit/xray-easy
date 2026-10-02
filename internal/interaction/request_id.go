// Package interaction carries safe correlation metadata across private service
// calls without exposing request payloads or credentials to logs.
package interaction

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"
)

const (
	// metadataKey is an internal package constant.
	metadataKey = "x-request-id"
	// operationMetadataKey is an internal package constant.
	operationMetadataKey = "x-controller-operation-id"
	// attemptMetadataKey is an internal package constant.
	attemptMetadataKey = "x-controller-attempt"
	// revisionMetadataKey is an internal package constant.
	revisionMetadataKey = "x-controller-state-revision"
)

// randomRead is an internal package variable.
var randomRead = rand.Read

// contextKey is an internal type used by the package.
type contextKey struct{ name string }

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
	return context.WithValue(ctx, contextKey{name: metadataKey}, strings.ToLower(requestID))
}

// RequestID returns the correlation identifier stored in ctx, if any.
func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{name: metadataKey}).(string)
	return value
}

// WithOperationID stores a validated stable ID for one logical controller operation.
func WithOperationID(ctx context.Context, operationID string) context.Context {
	if !validRequestID(operationID) {
		return ctx
	}
	return context.WithValue(ctx, contextKey{name: operationMetadataKey}, strings.ToLower(operationID))
}

// OperationID returns the logical operation identifier stored in ctx.
func OperationID(ctx context.Context) string {
	value, _ := ctx.Value(contextKey{name: operationMetadataKey}).(string)
	return value
}

// WithAttempt stores a positive transport attempt number in ctx.
func WithAttempt(ctx context.Context, attempt int) context.Context {
	if attempt < 1 || attempt > 1_000_000 {
		return ctx
	}
	return context.WithValue(ctx, contextKey{name: attemptMetadataKey}, attempt)
}

// Attempt returns the current transport attempt, defaulting to one.
func Attempt(ctx context.Context) int {
	value, _ := ctx.Value(contextKey{name: attemptMetadataKey}).(int)
	if value < 1 || value > 1_000_000 {
		return 1
	}
	return value
}

// WithStateRevision stores a positive, persisted desired-state revision.
func WithStateRevision(ctx context.Context, revision int64) context.Context {
	if revision < 1 {
		return ctx
	}
	return context.WithValue(ctx, contextKey{name: revisionMetadataKey}, revision)
}

// StateRevision returns the desired-state revision attached to ctx, if any.
func StateRevision(ctx context.Context) int64 {
	value, _ := ctx.Value(contextKey{name: revisionMetadataKey}).(int64)
	if value < 1 {
		return 0
	}
	return value
}

// Trace contains safe correlation fields shared by gRPC layers.
type Trace struct {
	// OperationID is the idempotency key for the operation.
	OperationID string
	// Attempt contains the Attempt value for this object.
	Attempt int
	// StateRevision contains the StateRevision value for this object.
	StateRevision int64
}

// TraceFromContext returns trace fields suitable for structured logging.
func TraceFromContext(ctx context.Context) Trace {
	return Trace{OperationID: OperationID(ctx), Attempt: Attempt(ctx), StateRevision: StateRevision(ctx)}
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
	operationID := OperationID(ctx)
	if operationID == "" {
		operationID = IncomingOperationID(ctx)
	}
	if operationID == "" {
		var err error
		operationID, err = NewRequestID()
		if err != nil {
			return nil, "", err
		}
	}
	ctx = WithOperationID(ctx, operationID)
	attempt := Attempt(ctx)
	if incoming := IncomingAttempt(ctx); incoming > 0 && Attempt(ctx) == 1 {
		attempt = incoming
	}
	ctx = WithAttempt(ctx, attempt)
	revision := StateRevision(ctx)
	if revision == 0 {
		revision = IncomingStateRevision(ctx)
	}
	if revision > 0 {
		ctx = WithStateRevision(ctx, revision)
	}
	values, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		values = metadata.MD{}
	}
	values = values.Copy()
	values.Set(metadataKey, requestID)
	values.Set(operationMetadataKey, operationID)
	values.Set(attemptMetadataKey, strconv.Itoa(attempt))
	if revision := StateRevision(ctx); revision > 0 {
		values.Set(revisionMetadataKey, strconv.FormatInt(revision, 10))
	} else {
		values.Delete(revisionMetadataKey)
	}
	return metadata.NewOutgoingContext(ctx, values), requestID, nil
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
	ctx = WithRequestID(ctx, requestID)
	operationID := IncomingOperationID(ctx)
	if operationID == "" {
		var err error
		operationID, err = NewRequestID()
		if err != nil {
			return nil, "", err
		}
	}
	ctx = WithOperationID(ctx, operationID)
	attempt := IncomingAttempt(ctx)
	if attempt == 0 {
		attempt = 1
	}
	ctx = WithAttempt(ctx, attempt)
	if revision := IncomingStateRevision(ctx); revision > 0 {
		ctx = WithStateRevision(ctx, revision)
	}
	return ctx, requestID, nil
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
		operationID, err := NewRequestID()
		if err != nil {
			http.Error(writer, "could not create operation identifier", http.StatusInternalServerError)
			return
		}
		ctx := WithAttempt(WithOperationID(WithRequestID(request.Context(), requestID), operationID), 1)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// IncomingOperationID reads a valid operation identifier from incoming gRPC metadata.
func IncomingOperationID(ctx context.Context) string {
	return incomingID(ctx, operationMetadataKey)
}

// IncomingAttempt reads a valid positive attempt number from incoming metadata.
func IncomingAttempt(ctx context.Context) int {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0
	}
	items := values.Get(attemptMetadataKey)
	if len(items) != 1 {
		return 0
	}
	value, err := strconv.Atoi(items[0])
	if err != nil || value < 1 || value > 1_000_000 {
		return 0
	}
	return value
}

// IncomingStateRevision reads a valid positive revision from incoming metadata.
func IncomingStateRevision(ctx context.Context) int64 {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return 0
	}
	items := values.Get(revisionMetadataKey)
	if len(items) != 1 {
		return 0
	}
	value, err := strconv.ParseInt(items[0], 10, 64)
	if err != nil || value < 1 {
		return 0
	}
	return value
}

// incomingID performs the operation represented by its name.
func incomingID(ctx context.Context, key string) string {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	items := values.Get(key)
	if len(items) != 1 || !validRequestID(items[0]) {
		return ""
	}
	return strings.ToLower(items[0])
}

// validRequestID performs the operation represented by its name.
func validRequestID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
