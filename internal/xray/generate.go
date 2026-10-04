package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"xray-easy/internal/domain"
)

// NewUUID constructs and returns the requested value.
func NewUUID() (string, error) {
	return newUUID(rand.Reader)
}

func newUUID(source io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(source, b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16])), nil
}

// NewRealityKeyPair constructs and returns the requested value.
func NewRealityKeyPair() (privateKey, publicKey string, err error) {
	return newRealityKeyPair(ecdh.X25519().GenerateKey)
}

func newRealityKeyPair(generate func(io.Reader) (*ecdh.PrivateKey, error)) (privateKey, publicKey string, err error) {
	key, err := generate(rand.Reader)
	if err != nil {
		return "", "", err
	}
	encode := func(value []byte) string {
		return strings.TrimRight(base64RawURL(value), "=")
	}
	return encode(key.Bytes()), encode(key.PublicKey().Bytes()), nil
}

// NewShortID constructs and returns the requested value.
func NewShortID() (string, error) {
	return newShortID(rand.Reader)
}

func newShortID(source io.Reader) (string, error) {
	for {
		b := make([]byte, 8)
		if _, err := io.ReadFull(source, b); err != nil {
			return "", err
		}
		value := hex.EncodeToString(b)
		if value != "0000000000000000" {
			return value, nil
		}
	}
}

// ValidateTarget validates the supplied value.
func ValidateTarget(target, sni string) error {
	return domain.ValidateRealityTarget(target, sni)
}

// ValidatePublicHost accepts a DNS hostname, IPv4 address, or global IPv6
// literal as a public profile endpoint.
func ValidatePublicHost(host string) error {
	return domain.ValidatePublicHost(host)
}

// base64RawURL performs the operation represented by its name.
func base64RawURL(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	for i := 0; i < len(value); i += 3 {
		remaining := len(value) - i
		block := uint(value[i]) << 16
		if remaining > 1 {
			block |= uint(value[i+1]) << 8
		}
		if remaining > 2 {
			block |= uint(value[i+2])
		}
		out.WriteByte(alphabet[(block>>18)&63])
		out.WriteByte(alphabet[(block>>12)&63])
		if remaining > 1 {
			out.WriteByte(alphabet[(block>>6)&63])
		}
		if remaining > 2 {
			out.WriteByte(alphabet[block&63])
		}
	}
	return out.String()
}
