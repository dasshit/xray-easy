package auth

import "testing"

func TestRecoveryCodeNormalizationAndValidation(t *testing.T) {
	code := "abcde-fghij-klmno-pqrst-uvwxy"
	hash := HashRecoveryCode(code)
	if hash != HashRecoveryCode(" ABCDEFGHIJKLMNOPQRSTUVWXY ") {
		t.Fatal("hash should ignore case, separators and surrounding spaces")
	}
	if !VerifyRecoveryCode(" ABCDE-FGHIJ-KLMNO-PQRST-UVWXY ", hash) {
		t.Fatal("normalized recovery code did not verify")
	}
	if VerifyRecoveryCode("abcde-fghij-klmno-pqrst-uvwxy!", hash) {
		t.Fatal("different recovery code verified")
	}
	if err := ValidateRecoveryCode(code); err != nil {
		t.Fatalf("valid recovery code rejected: %v", err)
	}
}

func TestValidateRecoveryCodeRequiresTwentyNormalizedCharacters(t *testing.T) {
	for _, test := range []struct {
		code  string
		valid bool
	}{
		{"", false},
		{"----", false},
		{"1234567890123456789", false},
		{"12345-67890-12345-67890", true},
		{"12345678901234567890", true},
	} {
		err := ValidateRecoveryCode(test.code)
		if (err == nil) != test.valid {
			t.Errorf("ValidateRecoveryCode(%q) error = %v, want valid=%v", test.code, err, test.valid)
		}
	}
}
