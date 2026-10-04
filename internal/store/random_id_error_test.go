package store

import (
	cryptorand "crypto/rand"
	"errors"
	"strings"
	"testing"
)

type storeFailedRandomReader struct{ err error }

func (r storeFailedRandomReader) Read([]byte) (int, error) { return 0, r.err }

func TestRandomIDReturnsEntropyFailures(t *testing.T) {
	previous := cryptorand.Reader
	wantErr := errors.New("entropy unavailable")
	cryptorand.Reader = storeFailedRandomReader{err: wantErr}
	t.Cleanup(func() { cryptorand.Reader = previous })

	if _, err := randomID(); !errors.Is(err, wantErr) && (err == nil || !strings.Contains(err.Error(), wantErr.Error())) {
		t.Fatalf("randomID() error = %v, want entropy failure", err)
	}
}
