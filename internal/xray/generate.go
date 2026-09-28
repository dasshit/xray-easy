package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"xray-easy/internal/domain"
)

func NewUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16])), nil
}

func NewRealityKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	encode := func(value []byte) string {
		return strings.TrimRight(base64RawURL(value), "=")
	}
	return encode(key.Bytes()), encode(key.PublicKey().Bytes()), nil
}

func NewShortID() (string, error) {
	for {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		value := hex.EncodeToString(b)
		if value != "0000000000000000" {
			return value, nil
		}
	}
}

func ValidateTarget(target, sni string) error {
	return domain.ValidateRealityTarget(target, sni)
}

// ValidatePublicHost accepts a DNS hostname, IPv4 address, or global IPv6
// literal as a public profile endpoint.
func ValidatePublicHost(host string) error {
	return domain.ValidatePublicHost(host)
}

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
