package xray

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestValidatePublicHost(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "198.51.100.10", "node-1.example"} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("expected %q to be accepted: %v", host, err)
		}
	}
	for _, host := range []string{"", "https://vpn.example.com", "2001:db8::1", "bad host", "-invalid.example"} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("expected %q to be rejected", host)
		}
	}
}

func TestGeneratedCredentialsHaveExpectedFormatAndKeyRelationship(t *testing.T) {
	uuid, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(uuid) {
		t.Fatalf("NewUUID returned invalid RFC 4122 v4 UUID: %q", uuid)
	}
	privateKey, publicKey, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil || len(privateBytes) != 32 {
		t.Fatalf("private key encoding/size invalid: %d bytes, %v", len(privateBytes), err)
	}
	publicBytes, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(publicBytes) != 32 {
		t.Fatalf("public key encoding/size invalid: %d bytes, %v", len(publicBytes), err)
	}
	derived, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil || string(derived.PublicKey().Bytes()) != string(publicBytes) {
		t.Fatalf("public key does not match private key: %v", err)
	}
	shortID, err := NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	shortBytes, err := hex.DecodeString(shortID)
	if err != nil || len(shortBytes) != 8 || shortID == "0000000000000000" {
		t.Fatalf("NewShortID returned invalid value %q: %v", shortID, err)
	}
}

func TestBase64RawURLMatchesStandardEncodingWithoutPadding(t *testing.T) {
	for _, input := range [][]byte{nil, {0}, {0, 1}, {0, 1, 2}, []byte("xray-easy"), make([]byte, 32)} {
		got := base64RawURL(input)
		want := base64.RawURLEncoding.EncodeToString(input)
		if got != want {
			t.Errorf("base64RawURL(%x) = %q, want %q", input, got, want)
		}
	}
}

func TestValidateTargetDelegatesRealityConstraints(t *testing.T) {
	if err := ValidateTarget("example.com:443", "example.com"); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	if err := ValidateTarget("127.0.0.1:443", "example.com"); err == nil {
		t.Fatal("loopback REALITY target accepted")
	}
}
