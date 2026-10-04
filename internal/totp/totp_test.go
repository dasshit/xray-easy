package totp

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/auth"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random source failed") }

func TestCodeMatchesRFC6238SHA1Vector(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, test := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		got, err := Code(secret, time.Unix(test.unix, 0).UTC())
		if err != nil {
			t.Fatalf("Code at %d: %v", test.unix, err)
		}
		if got != test.want {
			t.Errorf("Code at %d = %s, want %s", test.unix, got, test.want)
		}
	}
}

func TestValidateAcceptsAdjacentTimeStepsAndRejectsOtherCodes(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_010, 0).UTC()
	for _, delta := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := Code(secret, now.Add(delta))
		if err != nil || !Validate(secret, code, now) {
			t.Errorf("adjacent timestep %s was not accepted: code=%q err=%v", delta, code, err)
		}
	}
	if Validate(secret, " 12345 ", now) || Validate(secret, "abcdef", now) || Validate("bad", "123456", now) {
		t.Fatal("invalid code or secret was accepted")
	}
	code, err := Code(secret, now.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if Validate(secret, code, now) {
		t.Fatal("code outside the accepted time window was accepted")
	}
}

func TestCodeRejectsInvalidOrShortSecrets(t *testing.T) {
	for _, secret := range []string{"", "not-base32", "MY======", "JBSWY3DPEHPK3PXP"} {
		if _, err := Code(secret, time.Unix(0, 0)); err == nil {
			t.Errorf("Code accepted invalid or short secret %q", secret)
		}
	}
}

func TestOTPAuthURIEncodesLabelAndParameters(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	uri := OTPAuthURI(secret, "Xray Easy", "admin@example.com")
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Path != "/Xray Easy:admin@example.com" {
		t.Fatalf("unexpected OTPAuth URI label: %s", uri)
	}
	query := parsed.Query()
	for key, want := range map[string]string{"secret": secret, "issuer": "Xray Easy", "algorithm": "SHA1", "digits": "6", "period": "30"} {
		if got := query.Get(key); got != want {
			t.Errorf("parameter %s = %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(uri, "Xray%20Easy") {
		t.Fatalf("label should be URL escaped: %s", uri)
	}
}

func TestGeneratedCodesHaveExpectedFormatAndPassRecoveryValidation(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(decoded) != secretBytes {
		t.Fatalf("NewSecret returned invalid secret length: decoded=%d err=%v", len(decoded), err)
	}
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(code, "-")) != 5 {
		t.Fatalf("unexpected recovery-code grouping: %q", code)
	}
	if err := auth.ValidateRecoveryCode(code); err != nil {
		t.Fatalf("generated recovery code rejected: %v", err)
	}
}

func TestSecretAndRecoveryCodeReportRandomSourceFailure(t *testing.T) {
	previous := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = previous })
	if value, err := NewSecret(); err == nil || value != "" || !strings.Contains(err.Error(), "generate TOTP secret") {
		t.Fatalf("NewSecret() = %q, %v; want random-source error", value, err)
	}
	if value, err := NewRecoveryCode(); err == nil || value != "" || !strings.Contains(err.Error(), "generate recovery code") {
		t.Fatalf("NewRecoveryCode() = %q, %v; want random-source error", value, err)
	}
}
