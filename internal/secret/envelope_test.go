package secret

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSealAndOpenRoundTripWithPurposeSeparation(t *testing.T) {
	masterKey := []byte(strings.Repeat("k", 32))
	sealed, err := Seal(masterKey, "secret value", "totp")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "secret value") {
		t.Fatal("sealed value contains plaintext")
	}
	opened, err := Open(masterKey, sealed, "totp")
	if err != nil || opened != "secret value" {
		t.Fatalf("Open() = %q, %v", opened, err)
	}
	if _, err := Open(masterKey, sealed, "other-purpose"); err == nil {
		t.Fatal("envelope opened with a different purpose")
	}
	if _, err := Open([]byte(strings.Repeat("x", 32)), sealed, "totp"); err == nil {
		t.Fatal("envelope opened with a different master key")
	}
	second, err := Seal(masterKey, "secret value", "totp")
	if err != nil {
		t.Fatal(err)
	}
	if second == sealed {
		t.Fatal("separate envelopes should use independent salt and nonce")
	}
}

func TestSealRejectsShortKeyAndEmptyPurpose(t *testing.T) {
	for _, test := range []struct {
		key     []byte
		purpose string
	}{
		{[]byte(strings.Repeat("k", 31)), "totp"},
		{[]byte(strings.Repeat("k", 32)), ""},
	} {
		if value, err := Seal(test.key, "value", test.purpose); err == nil || value != "" {
			t.Errorf("Seal(%d-byte key, %q) = %q, %v", len(test.key), test.purpose, value, err)
		}
	}
}

func TestOpenRejectsMalformedAndTamperedEnvelopes(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	sealed, err := Seal(key, "value", "totp")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sealed, ":")
	mutations := map[string]string{
		"wrong version":        strings.Replace(sealed, "enc-v1", "enc-v2", 1),
		"missing component":    strings.Join(parts[:3], ":"),
		"bad salt encoding":    strings.Join([]string{parts[0], "%%%", parts[2], parts[3]}, ":"),
		"short salt":           strings.Join([]string{parts[0], base64.RawStdEncoding.EncodeToString([]byte("short")), parts[2], parts[3]}, ":"),
		"bad nonce encoding":   strings.Join([]string{parts[0], parts[1], "%%%", parts[3]}, ":"),
		"wrong nonce length":   strings.Join([]string{parts[0], parts[1], base64.RawStdEncoding.EncodeToString([]byte("short")), parts[3]}, ":"),
		"bad payload encoding": strings.Join([]string{parts[0], parts[1], parts[2], "%%%"}, ":"),
		"tampered payload":     strings.Join([]string{parts[0], parts[1], parts[2], base64.RawStdEncoding.EncodeToString([]byte("tampered"))}, ":"),
		"empty purpose":        sealed,
	}
	for name, envelope := range mutations {
		purpose := "totp"
		if name == "empty purpose" {
			purpose = ""
		}
		if _, err := Open(key, envelope, purpose); err == nil {
			t.Errorf("Open accepted %s", name)
		}
	}
	if _, err := Open([]byte("short"), sealed, "totp"); err == nil {
		t.Fatal("Open accepted a short master key")
	}
}
