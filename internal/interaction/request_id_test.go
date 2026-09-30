package interaction

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestNewRequestID(t *testing.T) {
	first, err := NewRequestID()
	if err != nil || len(first) != 32 {
		t.Fatalf("NewRequestID() = %q, %v", first, err)
	}
	second, err := NewRequestID()
	if err != nil || first == second {
		t.Fatalf("second NewRequestID() = %q, %v", second, err)
	}
}

func TestWithRequestIDValidatesAndNormalizes(t *testing.T) {
	ctx := WithRequestID(context.Background(), "ABCDEF0123456789ABCDEF0123456789")
	if got := RequestID(ctx); got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("RequestID() = %q", got)
	}
	if got := RequestID(WithRequestID(ctx, "invalid")); got != RequestID(ctx) {
		t.Fatalf("invalid ID replaced existing value: %q", got)
	}
}

func TestIncomingRequestID(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(metadataKey, "ABCDEF0123456789ABCDEF0123456789"))
	if got := IncomingRequestID(ctx); got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("IncomingRequestID() = %q", got)
	}
	for _, values := range [][]string{{"bad"}, {"abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789"}} {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{metadataKey: values})
		if got := IncomingRequestID(ctx); got != "" {
			t.Fatalf("IncomingRequestID(%v) = %q", values, got)
		}
	}
}

func TestOutgoingContextForwardsIncomingAndCreatesMissingID(t *testing.T) {
	want := "abcdef0123456789abcdef0123456789"
	wantOperation := "0123456789abcdef0123456789abcdef"
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(metadataKey, want, operationMetadataKey, wantOperation, attemptMetadataKey, "3", revisionMetadataKey, "42"))
	ctx, got, err := OutgoingContext(incoming)
	if err != nil || got != want || RequestID(ctx) != want || OperationID(ctx) != wantOperation || Attempt(ctx) != 3 || StateRevision(ctx) != 42 {
		t.Fatalf("OutgoingContext(incoming) = %q, %v", got, err)
	}
	values, _ := metadata.FromOutgoingContext(ctx)
	if values.Get(metadataKey)[0] != want || values.Get(operationMetadataKey)[0] != wantOperation || values.Get(attemptMetadataKey)[0] != "3" || values.Get(revisionMetadataKey)[0] != "42" {
		t.Fatalf("outgoing metadata = %v", values)
	}
	ctx, got, err = OutgoingContext(ctx)
	if err != nil || got != want {
		t.Fatalf("OutgoingContext(repeated) = %q, %v", got, err)
	}
	values, _ = metadata.FromOutgoingContext(ctx)
	if len(values.Get(metadataKey)) != 1 || len(values.Get(operationMetadataKey)) != 1 {
		t.Fatalf("trace metadata duplicated: %v", values)
	}
	ctx, got, err = OutgoingContext(context.Background())
	if err != nil || len(got) != 32 || RequestID(ctx) != got || len(OperationID(ctx)) != 32 || Attempt(ctx) != 1 {
		t.Fatalf("OutgoingContext(background) = %q, %v", got, err)
	}
	ctx, _, err = OutgoingContext(WithAttempt(WithOperationID(WithRequestID(context.Background(), want), wantOperation), 4))
	if err != nil || Attempt(ctx) != 4 {
		t.Fatalf("OutgoingContext(custom attempt) = %d, %v", Attempt(ctx), err)
	}
	if strings.TrimSpace(got) != got {
		t.Fatalf("request ID contains whitespace: %q", got)
	}
}

func TestEnsureIncomingUsesOrCreatesRequestID(t *testing.T) {
	want := "abcdef0123456789abcdef0123456789"
	wantOperation := "0123456789abcdef0123456789abcdef"
	ctx, got, err := EnsureIncoming(metadata.NewIncomingContext(context.Background(), metadata.Pairs(metadataKey, want, operationMetadataKey, wantOperation, attemptMetadataKey, "2", revisionMetadataKey, "314")))
	if err != nil || got != want || RequestID(ctx) != want || OperationID(ctx) != wantOperation || Attempt(ctx) != 2 || StateRevision(ctx) != 314 {
		t.Fatalf("EnsureIncoming(valid) = %q, %v", got, err)
	}
	ctx, got, err = EnsureIncoming(context.Background())
	if err != nil || len(got) != 32 || RequestID(ctx) != got || len(OperationID(ctx)) != 32 || Attempt(ctx) != 1 {
		t.Fatalf("EnsureIncoming(empty) = %q, %v", got, err)
	}
	for _, value := range []string{"0", "-1", "1000001", "invalid"} {
		ctx, _, err = EnsureIncoming(metadata.NewIncomingContext(context.Background(), metadata.Pairs(attemptMetadataKey, value, revisionMetadataKey, "bad")))
		if err != nil || Attempt(ctx) != 1 || StateRevision(ctx) != 0 {
			t.Fatalf("EnsureIncoming(invalid trace %q) = %d/%d, %v", value, Attempt(ctx), StateRevision(ctx), err)
		}
	}
}

func TestNewRequestIDError(t *testing.T) {
	original := randomRead
	defer func() { randomRead = original }()
	randomRead = func([]byte) (int, error) { return 0, context.Canceled }
	if _, err := NewRequestID(); err == nil {
		t.Fatal("NewRequestID() error = nil")
	}
}

func TestHTTPMiddlewareAddsIDToContextAndResponse(t *testing.T) {
	called := false
	handler := HTTPMiddleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called = true
		if got := RequestID(request.Context()); len(got) != 32 {
			t.Errorf("RequestID(context) = %q", got)
		}
		if len(OperationID(request.Context())) != 32 || Attempt(request.Context()) != 1 {
			t.Errorf("trace fields = operation %q attempt %d", OperationID(request.Context()), Attempt(request.Context()))
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || response.Code != http.StatusNoContent || len(response.Header().Get("X-Request-ID")) != 32 {
		t.Fatalf("middleware result: called=%v status=%d headers=%v", called, response.Code, response.Header())
	}
	original := randomRead
	defer func() { randomRead = original }()
	randomRead = func([]byte) (int, error) { return 0, context.Canceled }
	response = httptest.NewRecorder()
	HTTPMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler called without a request ID") })).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("random failure status = %d", response.Code)
	}
}
