package control

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

type unavailableRandomSource struct{}

func (unavailableRandomSource) Read([]byte) (int, error) {
	return 0, errors.New("random source unavailable")
}

func TestLoadOrCreateTokenReturnsRandomSourceFailure(t *testing.T) {
	original := rand.Reader
	rand.Reader = unavailableRandomSource{}
	t.Cleanup(func() { rand.Reader = original })
	if token, err := LoadOrCreateToken(t.TempDir() + "/control.token"); err == nil || token != "" || !strings.Contains(err.Error(), "generate AWG control token") || !strings.Contains(err.Error(), "random source unavailable") {
		t.Fatalf("LoadOrCreateToken() = %q, %v; want random-source error", token, err)
	}
}

func TestKeyGenerationAndSealingReturnRandomSourceFailures(t *testing.T) {
	original := rand.Reader
	rand.Reader = unavailableRandomSource{}
	t.Cleanup(func() { rand.Reader = original })
	if privateKey, publicKey, err := GenerateKeypair(); err == nil || privateKey != "" || publicKey != "" || !strings.Contains(err.Error(), "random source unavailable") {
		t.Fatalf("GenerateKeypair() = %q, %q, %v; want random-source error", privateKey, publicKey, err)
	}
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if envelope, err := sealPrivateKey(privateKey, bytes.Repeat([]byte{7}, 32)); err == nil || envelope != "" || !strings.Contains(err.Error(), "generate AWG key nonce") || !strings.Contains(err.Error(), "random source unavailable") {
		t.Fatalf("sealPrivateKey() = %q, %v; want random-source error", envelope, err)
	}
}
