package runtimeauth

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type authTestServerStream struct {
	ctx     context.Context
	request proto.Message
}

func (s *authTestServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *authTestServerStream) SendHeader(metadata.MD) error { return nil }
func (s *authTestServerStream) SetTrailer(metadata.MD)       {}
func (s *authTestServerStream) Context() context.Context     { return s.ctx }
func (s *authTestServerStream) SendMsg(any) error            { return nil }
func (s *authTestServerStream) RecvMsg(message any) error {
	target, ok := message.(proto.Message)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	proto.Merge(target, s.request)
	return nil
}

func TestStreamInterceptorAuthenticatesInitialProtobufRequest(t *testing.T) {
	token := []byte(strings.Repeat("stream-token", 4))
	method := "/runtime/WatchTelemetry"
	authenticator, err := NewAuthenticator(token, func(gotMethod, identity string) bool {
		return gotMethod == method && identity == "control-plane"
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &emptypb.Empty{}
	ctx, err := SignContext(context.Background(), token, "control-plane", method, request)
	if err != nil {
		t.Fatal(err)
	}
	outgoing, _ := metadata.FromOutgoingContext(ctx)
	incoming := metadata.NewIncomingContext(context.Background(), outgoing)
	stream := &authTestServerStream{ctx: incoming, request: request}
	called := false
	err = authenticator.StreamServerInterceptor()(nil, stream, &grpc.StreamServerInfo{FullMethod: method, IsServerStream: true}, func(_ any, wrapped grpc.ServerStream) error {
		called = true
		var received emptypb.Empty
		if err := wrapped.RecvMsg(&received); err != nil {
			return err
		}
		if got := IdentityFromContext(wrapped.Context()); got != "control-plane" {
			t.Fatalf("stream identity = %q", got)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("authenticated stream handler called=%t error=%v", called, err)
	}

	unauthorizedCtx, err := SignContext(context.Background(), token, "healthcheck", method, request)
	if err != nil {
		t.Fatal(err)
	}
	unauthorizedMetadata, _ := metadata.FromOutgoingContext(unauthorizedCtx)
	stream = &authTestServerStream{ctx: metadata.NewIncomingContext(context.Background(), unauthorizedMetadata), request: request}
	called = false
	err = authenticator.StreamServerInterceptor()(nil, stream, &grpc.StreamServerInfo{FullMethod: method, IsServerStream: true}, func(_ any, wrapped grpc.ServerStream) error {
		if err := wrapped.RecvMsg(new(emptypb.Empty)); err != nil {
			return err
		}
		called = true
		return nil
	})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("unauthorized stream called=%t error=%v", called, err)
	}
}

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
