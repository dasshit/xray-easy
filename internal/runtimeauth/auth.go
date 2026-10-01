// Package runtimeauth provides replay-resistant HMAC authentication for
// private gRPC calls between Xray-easy services.
package runtimeauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const nonceTTL = 2 * time.Minute

// Authorizer decides whether an authenticated service identity may call a method.
type Authorizer func(method, identity string) bool

// Authenticator verifies signed requests and prevents nonce replay.
type Authenticator struct {
	token  []byte
	allow  Authorizer
	now    func() time.Time
	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewAuthenticator creates a gRPC server authenticator using a service token.
func NewAuthenticator(token []byte, allow Authorizer) (*Authenticator, error) {
	if len(token) < 32 {
		return nil, errors.New("runtime authentication token must contain at least 32 bytes")
	}
	if allow == nil {
		return nil, errors.New("runtime authentication authorizer is required")
	}
	return &Authenticator{token: append([]byte(nil), token...), allow: allow, now: time.Now, nonces: make(map[string]time.Time)}, nil
}

// UnaryServerInterceptor authenticates each incoming protobuf request.
func (a *Authenticator) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		identity, err := a.authenticate(ctx, request, info.FullMethod)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "service authentication failed")
		}
		ctx = context.WithValue(ctx, identityContextKey{}, identity)
		return handler(ctx, request)
	}
}

// StreamServerInterceptor authenticates the protobuf request received by a
// server-streaming RPC before the generated handler reaches the service method.
func (a *Authenticator) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		wrapped := &authenticatedServerStream{ServerStream: stream, auth: a, method: info.FullMethod}
		return handler(server, wrapped)
	}
}

type authenticatedServerStream struct {
	grpc.ServerStream
	auth       *Authenticator
	method     string
	ctx        context.Context
	authorized bool
}

func (s *authenticatedServerStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return s.ServerStream.Context()
}

func (s *authenticatedServerStream) RecvMsg(message any) error {
	if err := s.ServerStream.RecvMsg(message); err != nil {
		return err
	}
	if s.authorized {
		return nil
	}
	identity, err := s.auth.authenticate(s.ServerStream.Context(), message, s.method)
	if err != nil {
		return status.Error(codes.Unauthenticated, "service authentication failed")
	}
	s.ctx = context.WithValue(s.ServerStream.Context(), identityContextKey{}, identity)
	s.authorized = true
	return nil
}

// SignContext attaches an HMAC signature for a deterministic protobuf request.
func SignContext(ctx context.Context, token []byte, identity, method string, request proto.Message) (context.Context, error) {
	if len(token) < 32 {
		return nil, errors.New("runtime authentication token must contain at least 32 bytes")
	}
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(method) == "" || request == nil {
		return nil, errors.New("runtime request identity, method and protobuf request are required")
	}
	requestBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return nil, errors.New("marshal runtime authentication request")
	}
	var nonceBytes [16]byte
	if _, err := io.ReadFull(rand.Reader, nonceBytes[:]); err != nil {
		return nil, errors.New("generate runtime authentication nonce")
	}
	nonce := hex.EncodeToString(nonceBytes[:])
	mac := requestMAC(token, method, identity, nonce, requestBytes)
	return metadata.AppendToOutgoingContext(ctx,
		"x-xray-operation", identity,
		"x-xray-nonce", nonce,
		"x-xray-signature", hex.EncodeToString(mac)), nil
}

func (a *Authenticator) authenticate(ctx context.Context, request any, method string) (string, error) {
	message, ok := request.(proto.Message)
	if !ok || message == nil {
		return "", errors.New("request is not a protobuf message")
	}
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("authentication metadata is missing")
	}
	readOne := func(key string) (string, error) {
		items := values.Get(key)
		if len(items) != 1 || strings.TrimSpace(items[0]) == "" {
			return "", errors.New("authentication metadata is missing or repeated")
		}
		return items[0], nil
	}
	identity, err := readOne("x-xray-operation")
	if err != nil {
		return "", err
	}
	nonce, err := readOne("x-xray-nonce")
	if err != nil {
		return "", err
	}
	signature, err := readOne("x-xray-signature")
	if err != nil {
		return "", err
	}
	if !a.allow(method, identity) {
		return "", errors.New("operation identity cannot call this method")
	}
	decodedNonce, err := hex.DecodeString(nonce)
	if err != nil || len(decodedNonce) != 16 {
		return "", errors.New("invalid request nonce")
	}
	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha256.Size {
		return "", errors.New("invalid request signature")
	}
	requestBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return "", errors.New("marshal authenticated request")
	}
	want := requestMAC(a.token, method, identity, nonce, requestBytes)
	if !hmac.Equal(provided, want) {
		return "", errors.New("request signature is invalid")
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for seenNonce, seenAt := range a.nonces {
		if now.Sub(seenAt) > nonceTTL {
			delete(a.nonces, seenNonce)
		}
	}
	if _, exists := a.nonces[nonce]; exists {
		return "", errors.New("request nonce was already used")
	}
	a.nonces[nonce] = now
	return identity, nil
}

// IdentityFromContext returns the authenticated service identity, if present.
func IdentityFromContext(ctx context.Context) string {
	identity, _ := ctx.Value(identityContextKey{}).(string)
	return identity
}

type identityContextKey struct{}

func requestMAC(token []byte, method, identity, nonce string, request []byte) []byte {
	bodyHash := sha256.Sum256(request)
	canonical := strings.Join([]string{method, identity, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, token)
	_, _ = mac.Write([]byte(canonical))
	return mac.Sum(nil)
}
