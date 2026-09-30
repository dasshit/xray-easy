package runtimeauth

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestSignContextAndInterceptorAuthenticateRequest(t *testing.T) {
	token := []byte(strings.Repeat("t", 32))
	authenticator, err := NewAuthenticator(token, func(method, identity string) bool {
		return method == "/runtime/Health" && identity == "healthcheck"
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &emptypb.Empty{}
	ctx, err := SignContext(context.Background(), token, "healthcheck", "/runtime/Health", request)
	if err != nil {
		t.Fatal(err)
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("SignContext did not add outgoing metadata")
	}
	ctx = metadata.NewIncomingContext(context.Background(), md)
	interceptor := authenticator.UnaryServerInterceptor()
	response, err := interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: "/runtime/Health"}, func(ctx context.Context, request any) (any, error) {
		if got := IdentityFromContext(ctx); got != "healthcheck" {
			t.Fatalf("authenticated identity = %q", got)
		}
		return request, nil
	})
	if err != nil || response != request {
		t.Fatalf("interceptor response = %v, %v", response, err)
	}
}

func TestInterceptorRejectsReplayAndUnauthorizedMethod(t *testing.T) {
	token := []byte(strings.Repeat("s", 32))
	authenticator, err := NewAuthenticator(token, func(method, identity string) bool {
		return method == "/runtime/Health" && identity == "healthcheck"
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &emptypb.Empty{}
	ctx, err := SignContext(context.Background(), token, "healthcheck", "/runtime/Health", request)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, _ := metadata.FromOutgoingContext(ctx)
	incoming := metadata.NewIncomingContext(context.Background(), outgoing)
	interceptor := authenticator.UnaryServerInterceptor()
	handler := func(context.Context, any) (any, error) { return new(emptypb.Empty), nil }
	if _, err := interceptor(incoming, request, &grpc.UnaryServerInfo{FullMethod: "/runtime/Health"}, handler); err != nil {
		t.Fatalf("first authenticated call: %v", err)
	}
	if _, err := interceptor(incoming, request, &grpc.UnaryServerInfo{FullMethod: "/runtime/Health"}, handler); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replayed call error = %v, want unauthenticated", err)
	}

	ctx, err = SignContext(context.Background(), token, "healthcheck", "/runtime/Status", request)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, _ = metadata.FromOutgoingContext(ctx)
	incoming = metadata.NewIncomingContext(context.Background(), outgoing)
	if _, err := interceptor(incoming, request, &grpc.UnaryServerInfo{FullMethod: "/runtime/Status"}, handler); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthorized method error = %v, want unauthenticated", err)
	}
}

func TestAuthenticatorRequiresLongTokenAndAuthorizer(t *testing.T) {
	if _, err := NewAuthenticator([]byte("short"), func(string, string) bool { return true }); err == nil {
		t.Fatal("short token was accepted")
	}
	if _, err := NewAuthenticator([]byte(strings.Repeat("t", 32)), nil); err == nil {
		t.Fatal("missing authorizer was accepted")
	}
}
