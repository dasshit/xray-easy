package main

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

type failingRandomSource struct{}

func (failingRandomSource) Read([]byte) (int, error) {
	return 0, errors.New("random source unavailable")
}

func TestSecretGeneratorsReturnRandomSourceErrors(t *testing.T) {
	original := rand.Reader
	rand.Reader = failingRandomSource{}
	t.Cleanup(func() { rand.Reader = original })
	if value, err := newHysteriaAuth(); err == nil || value != "" || !strings.Contains(err.Error(), "random source unavailable") {
		t.Fatalf("newHysteriaAuth() = %q, %v; want random source error", value, err)
	}
	if value, err := randomID(); err == nil || value != "" || !strings.Contains(err.Error(), "random source unavailable") {
		t.Fatalf("randomID() = %q, %v; want random source error", value, err)
	}
}
