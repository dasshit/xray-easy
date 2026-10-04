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
	return sealWith(masterKey, value, purpose, defaultEnvelopeCrypto())
}

type envelopeCrypto struct {
	random    io.Reader
	readFull  func(io.Reader, []byte) (int, error)
	derive    func([]byte, []byte, string) ([]byte, error)
	newCipher func([]byte) (cipher.Block, error)
	newGCM    func(cipher.Block) (cipher.AEAD, error)
}

func defaultEnvelopeCrypto() envelopeCrypto {
	return envelopeCrypto{
		random: rand.Reader, readFull: io.ReadFull,
		derive: func(masterKey, salt []byte, purpose string) ([]byte, error) {
			return deriveWith(masterKey, salt, purpose, io.ReadFull)
		},
		newCipher: aes.NewCipher, newGCM: cipher.NewGCM,
	}
}

func sealWith(masterKey []byte, value string, purpose string, crypto envelopeCrypto) (string, error) {
	if len(masterKey) < 32 {
		return "", errors.New("master key must contain at least 32 bytes")
	}
	if purpose == "" {
		return "", errors.New("envelope purpose is required")
	}
	salt := make([]byte, 32)
	if _, err := crypto.readFull(crypto.random, salt); err != nil {
		return "", fmt.Errorf("generate envelope salt: %w", err)
	}
	key, err := crypto.derive(masterKey, salt, purpose)
	if err != nil {
		return "", err
	}
	block, err := crypto.newCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := crypto.newGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := crypto.readFull(crypto.random, nonce); err != nil {
		return "", fmt.Errorf("generate envelope nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), []byte(purpose))
	encode := base64.RawStdEncoding.EncodeToString
	return strings.Join([]string{envelopeVersion, encode(salt), encode(nonce), encode(ciphertext)}, ":"), nil
}

// Open opens the requested resource.
func Open(masterKey []byte, encoded, purpose string) (string, error) {
	return openWith(masterKey, encoded, purpose, defaultEnvelopeCrypto())
}

func openWith(masterKey []byte, encoded, purpose string, crypto envelopeCrypto) (string, error) {
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
	key, err := crypto.derive(masterKey, salt, purpose)
	if err != nil {
		return "", err
	}
	block, err := crypto.newCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := crypto.newGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return "", errors.New("invalid encrypted value nonce")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(purpose))
	if err != nil {
		return "", errors.New("encrypted value authentication failed")
	}
	return string(plaintext), nil
}

// Derive deterministically derives a purpose-specific 32-byte key from the
// installation master key. The result is stable across restarts and is never
// stored in the database.
func Derive(masterKey []byte, purpose string) ([]byte, error) {
	return deriveKeyWith(masterKey, purpose, io.ReadFull)
}

func deriveKeyWith(masterKey []byte, purpose string, readFull func(io.Reader, []byte) (int, error)) ([]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must contain at least 32 bytes")
	}
	if purpose == "" {
		return nil, errors.New("key derivation purpose is required")
	}
	reader := hkdf.New(sha256.New, masterKey, nil, []byte("xray-easy/derived/"+purpose))
	key := make([]byte, 32)
	if _, err := readFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// derive performs the operation represented by its name.
func deriveWith(masterKey, salt []byte, purpose string, readFull func(io.Reader, []byte) (int, error)) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, salt, []byte("xray-easy/"+purpose))
	key := make([]byte, 32)
	if _, err := readFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive envelope key: %w", err)
	}
	return key, nil
}
