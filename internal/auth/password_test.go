package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordAndVerifyPassword(t *testing.T) {
	password := "correct horse battery staple"
	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("unexpected password hash format: %q", encoded)
	}
	if !VerifyPassword(password, encoded) {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(password+"!", encoded) {
		t.Fatal("incorrect password verified")
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == second {
		t.Fatal("independent password hashes should use distinct salts")
	}
}

func TestHashPasswordRejectsShortPassword(t *testing.T) {
	for _, password := range []string{"", "short", "12345678901"} {
		if encoded, err := HashPassword(password); err == nil || encoded != "" {
			t.Errorf("HashPassword(%q) = %q, %v; want error and empty hash", password, encoded, err)
		}
	}
}

func TestVerifyPasswordRejectsMalformedOrUnsafeHashes(t *testing.T) {
	for _, encoded := range []string{
		"", "plain-text", "$argon2i$v=19$m=1,t=1,p=1$YWJj$YWJj",
		"$argon2id$v=16$m=1,t=1,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=1,p=1$YWJj",
		"$argon2id$v=19$m=0,t=1,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1048577,t=1,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=0,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=21,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=1,p=0$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=1,p=33$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=1$YWJj$YWJj",
		"$argon2id$v=19$m=x,t=1,p=1$YWJj$YWJj",
		"$argon2id$v=19$m=1,t=1,p=1$%%%$YWJj",
		"$argon2id$v=19$m=1,t=1,p=1$YWJj$%%%",
		"$argon2id$v=19$m=1,t=1,p=1$YWJj$",
	} {
		if VerifyPassword("password", encoded) {
			t.Errorf("VerifyPassword accepted malformed hash %q", encoded)
		}
	}
}
