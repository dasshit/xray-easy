// Package auth implements administrator password and recovery-code verification.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// argonMemory is an internal package constant.
	argonMemory = 64 * 1024
	// argonTime is an internal package constant.
	argonTime = 3
	// argonThreads is an internal package constant.
	argonThreads = 1
	// saltBytes is an internal package constant.
	saltBytes = 16
	// keyBytes is an internal package constant.
	keyBytes = 32
)

// HashPassword reports whether the value contains the requested capability.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}
	salt := make([]byte, saltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyBytes)
	encode := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, encode(salt), encode(key)), nil
}

// VerifyPassword verifies the supplied value.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := map[string]uint32{}
	for _, item := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(item, "=", 2)
		if len(pair) != 2 {
			return false
		}
		value, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return false
		}
		params[pair[0]] = uint32(value)
	}
	memory, okMemory := params["m"]
	timeCost, okTime := params["t"]
	threads, okThreads := params["p"]
	if !okMemory || !okTime || !okThreads || memory == 0 || timeCost == 0 || threads == 0 || memory > 1024*1024 || timeCost > 20 || threads > 32 {
		return false
	}
	salt, errSalt := base64.RawStdEncoding.DecodeString(parts[4])
	want, errWant := base64.RawStdEncoding.DecodeString(parts[5])
	if errSalt != nil || errWant != nil || len(salt) < 8 || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
