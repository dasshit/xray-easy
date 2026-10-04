package main

import (
	"strings"
	"testing"
	"time"

	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/totp"
)

func TestVerifyTOTPRejectsDisabledAndUndecryptableSecrets(t *testing.T) {
	app := newTestApp(t, true)
	admin := app.admin
	if err := app.server.verifyTOTP(admin, "123456"); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("verifyTOTP with TOTP disabled = %v", err)
	}

	admin.TOTPEnabled = true
	admin.TOTPSecretEnc = ""
	if err := app.server.verifyTOTP(admin, "123456"); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("verifyTOTP with an empty encrypted secret = %v", err)
	}
	admin.TOTPSecretEnc = "malformed-envelope"
	if err := app.server.verifyTOTP(admin, "123456"); err == nil || !strings.Contains(err.Error(), "invalid TOTP") {
		t.Fatalf("verifyTOTP with an undecryptable secret = %v", err)
	}

	secretValue, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	admin.TOTPSecretEnc, err = secret.Seal(app.server.masterKey, secretValue, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.verifyTOTP(admin, "bad-code"); err == nil {
		t.Fatal("verifyTOTP accepted an invalid code")
	}
	code, err := totp.Code(secretValue, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.verifyTOTP(admin, code); err != nil {
		t.Fatalf("verifyTOTP rejected a valid code: %v", err)
	}
}

func TestVerifyTOTPRejectsSecretsEncryptedByAnotherMasterKey(t *testing.T) {
	app := newTestApp(t, true)
	secretValue, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	admin := store.Admin{TOTPEnabled: true}
	admin.TOTPSecretEnc, err = secret.Seal([]byte("fedcba9876543210fedcba9876543210"), secretValue, "totp_secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.verifyTOTP(admin, "123456"); err == nil || !strings.Contains(err.Error(), "invalid TOTP") {
		t.Fatalf("verifyTOTP with a different master key = %v", err)
	}
}
