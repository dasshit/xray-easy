// Package totp generates and verifies administrator TOTP codes and recovery material.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // SHA-1 is required by RFC 6238's default TOTP profile.
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

const (
	// secretBytes is an internal package constant.
	secretBytes = 20
	// period is an internal package constant.
	period = 30
	// digits is an internal package constant.
	digits = 6
)

// NewSecret constructs and returns the requested value.
func NewSecret() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// Code returns a code for the supplied value.
func Code(secret string, at time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 16 {
		return "", errors.New("invalid TOTP secret")
	}
	counter := uint64(at.Unix() / period)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	h := hmac.New(sha1.New, key)
	_, _ = h.Write(message[:])
	digest := h.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

// Validate validates the supplied value.
func Validate(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	for delta := -1; delta <= 1; delta++ {
		want, err := Code(secret, at.Add(time.Duration(delta)*period*time.Second))
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// OTPAuthURI performs the operation represented by its name.
func OTPAuthURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", "6")
	values.Set("period", "30")
	return "otpauth://totp/" + label + "?" + values.Encode()
}

// NewRecoveryCode constructs and returns the requested value.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate recovery code: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return encoded[:5] + "-" + encoded[5:10] + "-" + encoded[10:15] + "-" + encoded[15:20] + "-" + encoded[20:], nil
}
