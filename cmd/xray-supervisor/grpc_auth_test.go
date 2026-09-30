package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	supervisorapi "xray-easy/internal/supervisor"
)

func signedSupervisorRequest(t *testing.T, request proto.Message, method, operation, nonce, token string) string {
	t.Helper()
	body, err := supervisorapi.DeterministicBytes(request)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{method, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestSupervisorRPCAuthenticationVerifiesSignatureReplayAndExpiry(t *testing.T) {
	instance, _ := newProcessTestSupervisor(t)
	request, _ := structpb.NewStruct(map[string]any{"path": "/etc/xray/candidate.json"})
	method := "/" + supervisorapi.RPCServiceName + "/ValidateConfig"
	nonce := "0123456789abcdef0123456789abcdef"
	signature := signedSupervisorRequest(t, request, method, "control-plane", nonce, "test-token")
	if err := instance.authenticateRPC(request, method, "control-plane", nonce, signature); err != nil {
		t.Fatalf("valid authentication rejected: %v", err)
	}
	if err := instance.authenticateRPC(request, method, "control-plane", nonce, signature); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replayed nonce error = %v", err)
	}
	oldNonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	instance.usedNonces[oldNonce] = time.Now().Add(-3 * supervisorNonceTTL)
	nextNonce := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	nextSignature := signedSupervisorRequest(t, request, method, "control-plane", nextNonce, "test-token")
	if err := instance.authenticateRPC(request, method, "control-plane", nextNonce, nextSignature); err != nil {
		t.Fatalf("valid request after expiry rejected: %v", err)
	}
	if _, exists := instance.usedNonces[oldNonce]; exists {
		t.Fatal("expired nonce was retained")
	}
}

func TestSupervisorRPCAuthenticationRejectsInvalidMetadataAndCredentials(t *testing.T) {
	instance, _ := newProcessTestSupervisor(t)
	request, _ := structpb.NewStruct(map[string]any{"path": "candidate"})
	method := "/" + supervisorapi.RPCServiceName + "/ValidateConfig"
	validNonce := "0123456789abcdef0123456789abcdef"
	validSignature := signedSupervisorRequest(t, request, method, "control-plane", validNonce, "test-token")
	for _, input := range []struct {
		name      string
		request   any
		method    string
		operation string
		nonce     string
		signature string
	}{
		{name: "not proto", request: struct{}{}, method: method, operation: "control-plane", nonce: validNonce, signature: validSignature},
		{name: "unknown operation", request: request, method: method, operation: "other", nonce: validNonce, signature: validSignature},
		{name: "healthcheck apply", request: request, method: "/" + supervisorapi.RPCServiceName + "/ApplyConfig", operation: "healthcheck", nonce: validNonce, signature: validSignature},
		{name: "unknown RPC", request: request, method: "/" + supervisorapi.RPCServiceName + "/Shutdown", operation: "control-plane", nonce: validNonce, signature: validSignature},
		{name: "short nonce", request: request, method: method, operation: "control-plane", nonce: "short", signature: validSignature},
		{name: "non hex nonce", request: request, method: method, operation: "control-plane", nonce: strings.Repeat("z", 32), signature: validSignature},
		{name: "malformed signature", request: request, method: method, operation: "control-plane", nonce: validNonce, signature: "not-hex"},
		{name: "wrong signature", request: request, method: method, operation: "control-plane", nonce: validNonce, signature: strings.Repeat("00", sha256.Size)},
	} {
		t.Run(input.name, func(t *testing.T) {
			if err := instance.authenticateRPC(input.request, input.method, input.operation, input.nonce, input.signature); err == nil {
				t.Fatal("invalid request authenticated")
			}
		})
	}
	if err := os.WriteFile(instance.cfg.tokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := instance.authenticateRPC(request, method, "control-plane", validNonce, validSignature); err == nil || !strings.Contains(err.Error(), "token is unavailable") {
		t.Fatalf("empty token error = %v", err)
	}
	if err := os.Remove(instance.cfg.tokenFile); err != nil {
		t.Fatal(err)
	}
	if err := instance.authenticateRPC(request, method, "control-plane", validNonce, validSignature); err == nil || !strings.Contains(err.Error(), "token is unavailable") {
		t.Fatalf("missing token error = %v", err)
	}
}

func TestSupervisorRPCMetadataAndUnaryInterceptor(t *testing.T) {
	for name, pairs := range map[string][]string{
		"missing":   {},
		"duplicate": {"x-xray-operation", "control-plane", "x-xray-operation", "control-plane"},
		"empty":     {"x-xray-operation", "", "x-xray-nonce", "nonce", "x-xray-signature", "sig"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if len(pairs) > 0 {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(pairs...))
			}
			if _, _, _, err := rpcAuthMetadata(ctx); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	valid := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-xray-operation", "control-plane", "x-xray-nonce", "nonce", "x-xray-signature", "sig"))
	operation, nonce, signature, err := rpcAuthMetadata(valid)
	if err != nil || operation != "control-plane" || nonce != "nonce" || signature != "sig" {
		t.Fatalf("valid metadata = %q %q %q, %v", operation, nonce, signature, err)
	}

	instance, _ := newProcessTestSupervisor(t)
	request, _ := structpb.NewStruct(map[string]any{"path": "candidate"})
	method := "/" + supervisorapi.RPCServiceName + "/ValidateConfig"
	nonce = "cccccccccccccccccccccccccccccccc"
	signature = signedSupervisorRequest(t, request, method, "control-plane", nonce, "test-token")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-xray-operation", "control-plane", "x-xray-nonce", nonce, "x-xray-signature", signature))
	called := false
	result, err := instance.unaryAuthInterceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
		called = true
		return "ok", nil
	})
	if err != nil || result != "ok" || !called {
		t.Fatalf("valid interceptor result = %v, %v, called=%v", result, err, called)
	}
	called = false
	_, err = instance.unaryAuthInterceptor(context.Background(), request, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("unauthenticated interceptor result = %v, called=%v", err, called)
	}
	if err := rpcOperationError(codes.Internal, context.Canceled); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled operation status = %v", err)
	}
	if err := rpcOperationError(codes.Internal, context.DeadlineExceeded); status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("deadline operation status = %v", err)
	}
	if err := rpcOperationError(codes.FailedPrecondition, errors.New(`failed password="secret"`)); strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("operation error was not redacted: %v", err)
	}
}

func TestAllowedSupervisorMethods(t *testing.T) {
	for _, method := range []string{"Health", "GetStatus", "GetLogs", "ValidateConfig", "ApplyConfig", "ReplaceInbound", "ProbeTarget", "ProbeIPv6"} {
		full := "/" + supervisorapi.RPCServiceName + "/" + method
		if !allowedSupervisorMethod(full, "control-plane") {
			t.Errorf("control-plane not allowed for %s", method)
		}
		if allowedSupervisorMethod(full, "healthcheck") != (method == "Health") {
			t.Errorf("healthcheck allowlist mismatch for %s", method)
		}
	}
	if allowedSupervisorMethod("/another.Service/Health", "control-plane") || allowedSupervisorMethod("/health", "healthcheck") {
		t.Fatal("unknown service method was allowed")
	}
}
