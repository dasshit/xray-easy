// Package secret encrypts sensitive values with the configured Xray-easy master key.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// envelopeVersion is an internal package constant.
const envelopeVersion = "enc-v1"

// Seal encrypts a value with a key-encryption key. The output contains no
// plaintext and is safe to store in SQLite. Each value gets an independent
// salt and nonce.
func Seal(masterKey []byte, value string, purpose string) (string, error) {
	if len(masterKey) < 32 {
		return "", errors.New("master key must contain at least 32 bytes")
	}
	if purpose == "" {
		return "", errors.New("envelope purpose is required")
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate envelope salt: %w", err)
	}
	key, err := derive(masterKey, salt, purpose)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate envelope nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), []byte(purpose))
	encode := base64.RawStdEncoding.EncodeToString
	return strings.Join([]string{envelopeVersion, encode(salt), encode(nonce), encode(ciphertext)}, ":"), nil
}

// Open opens the requested resource.
func Open(masterKey []byte, encoded, purpose string) (string, error) {
	if len(masterKey) < 32 {
		return "", errors.New("master key must contain at least 32 bytes")
	}
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != envelopeVersion || purpose == "" {
		return "", errors.New("invalid encrypted value")
	}
	decode := base64.RawStdEncoding.DecodeString
	salt, err := decode(parts[1])
	if err != nil || len(salt) != 32 {
		return "", errors.New("invalid encrypted value salt")
	}
	nonce, err := decode(parts[2])
	if err != nil {
		return "", errors.New("invalid encrypted value nonce")
	}
	ciphertext, err := decode(parts[3])
	if err != nil {
		return "", errors.New("invalid encrypted value payload")
	}
	key, err := derive(masterKey, salt, purpose)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return "", errors.New("invalid encrypted value nonce")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return "", errors.New("encrypted value authentication failed")
	}
	return string(plaintext), nil
}

// derive performs the operation represented by its name.
func derive(masterKey, salt []byte, purpose string) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, salt, []byte("xray-easy/"+purpose))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}
	return key, nil
}
