package control

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"
)

func TestOpenPrivateKeyRejectsAuthenticatedWrongLengthPayload(t *testing.T) {
	masterKey := []byte("coverage-master-key")
	block, err := aes.NewCipher(deriveEncryptionKey(masterKey))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nonce, nonce, []byte("not a 32-byte private key"), []byte("xray-easy/awg/private-key/v1"))
	envelope := base64.StdEncoding.EncodeToString(sealed)
	if _, err := openPrivateKey(envelope, masterKey); err == nil || !strings.Contains(err.Error(), "invalid length") {
		t.Fatalf("openPrivateKey() error = %v, want invalid plaintext length", err)
	}
}
