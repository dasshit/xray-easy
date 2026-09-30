package control

import (
	"crypto/rand"
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
