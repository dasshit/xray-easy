package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

// HashRecoveryCode hashes a high-entropy recovery code for storage. Recovery
// codes are generated randomly and are never persisted in plaintext.
func HashRecoveryCode(code string) string {
	hash := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(hash[:])
}

// VerifyRecoveryCode verifies the supplied value.
func VerifyRecoveryCode(code, encoded string) bool {
	got := HashRecoveryCode(code)
	return subtle.ConstantTimeCompare([]byte(got), []byte(encoded)) == 1
}

// normalizeRecoveryCode performs the operation represented by its name.
func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// ValidateRecoveryCode validates the supplied value.
func ValidateRecoveryCode(code string) error {
	if len(normalizeRecoveryCode(code)) < 20 {
		return errors.New("recovery code is invalid")
	}
	return nil
}
