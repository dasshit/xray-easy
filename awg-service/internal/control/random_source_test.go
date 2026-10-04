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

type prefixThenErrorRandomSource struct {
	first bool
}

func (source *prefixThenErrorRandomSource) Read(buffer []byte) (int, error) {
	if source.first {
		source.first = false
		for index := range buffer {
			buffer[index] = byte(index + 1)
		}
		return len(buffer), nil
	}
	return 0, errors.New("random source unavailable after key generation")
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

func TestOpenReturnsRandomSourceFailuresWhileCreatingInitialState(t *testing.T) {
	for _, test := range []struct {
		name   string
		source interface{ Read([]byte) (int, error) }
		want   string
	}{
		{name: "server key generation", source: unavailableRandomSource{}, want: "generate server key"},
		{name: "server key sealing", source: &prefixThenErrorRandomSource{first: true}, want: "generate AWG key nonce"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := rand.Reader
			rand.Reader = test.source
			t.Cleanup(func() { rand.Reader = original })
			opts := testOptions(t)
			if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Open() error = %v, want %q", err, test.want)
			}
		})
	}
}
