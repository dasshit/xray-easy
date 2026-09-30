package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	supervisorapi "xray-easy/internal/supervisor"
)

const supervisorNonceTTL = 2 * time.Minute

func (s *supervisor) unaryAuthInterceptor(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	operation, nonce, signature, err := rpcAuthMetadata(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.authenticateRPC(request, info.FullMethod, operation, nonce, signature); err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return handler(ctx, request)
}

func rpcAuthMetadata(ctx context.Context) (operation, nonce, signature string, err error) {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", "", errors.New("missing supervisor authentication metadata")
	}
	one := func(key string) (string, error) {
		items := values.Get(key)
		if len(items) != 1 || items[0] == "" {
			return "", errors.New("missing or repeated supervisor authentication metadata")
		}
		return items[0], nil
	}
	if operation, err = one("x-xray-operation"); err != nil {
		return "", "", "", err
	}
	if nonce, err = one("x-xray-nonce"); err != nil {
		return "", "", "", err
	}
	if signature, err = one("x-xray-signature"); err != nil {
		return "", "", "", err
	}
	return operation, nonce, signature, nil
}

func (s *supervisor) authenticateRPC(request any, method, operation, nonce, signature string) error {
	if !allowedSupervisorMethod(method, operation) {
		return errors.New("supervisor operation is not allowed")
	}
	if len(nonce) != 32 {
		return errors.New("invalid supervisor request nonce")
	}
	if decoded, err := hex.DecodeString(nonce); err != nil || len(decoded) != 16 {
		return errors.New("invalid supervisor request nonce")
	}
	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("invalid supervisor request signature")
	}
	message, ok := request.(proto.Message)
	if !ok {
		return errors.New("unsupported supervisor request message")
	}
	requestBytes, err := supervisorapi.DeterministicBytes(message)
	if err != nil {
		return errors.New("invalid supervisor request message")
	}
	secret, err := os.ReadFile(s.cfg.tokenFile)
	if err != nil {
		return errors.New("supervisor token is unavailable")
	}
	secret = []byte(strings.TrimSpace(string(secret)))
	if len(secret) == 0 {
		return errors.New("supervisor token is unavailable")
	}
	bodyHash := sha256.Sum256(requestBytes)
	canonical := strings.Join([]string{method, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return errors.New("invalid supervisor request signature")
	}
	now := time.Now()
	s.usedNoncesMu.Lock()
	defer s.usedNoncesMu.Unlock()
	for value, seen := range s.usedNonces {
		if now.Sub(seen) > supervisorNonceTTL {
			delete(s.usedNonces, value)
		}
	}
	if _, exists := s.usedNonces[nonce]; exists {
		return errors.New("supervisor request nonce was already used")
	}
	s.usedNonces[nonce] = now
	return nil
}

func allowedSupervisorMethod(method, operation string) bool {
	servicePrefix := "/" + supervisorapi.RPCServiceName + "/"
	switch operation {
	case "control-plane":
		switch method {
		case servicePrefix + "Health", servicePrefix + "GetStatus", servicePrefix + "GetLogs", servicePrefix + "ValidateConfig", servicePrefix + "ApplyConfig", servicePrefix + "ReplaceInbound", servicePrefix + "ProbeTarget", servicePrefix + "ProbeIPv6":
			return true
		}
	case "healthcheck":
		return method == servicePrefix+"Health"
	}
	return false
}
