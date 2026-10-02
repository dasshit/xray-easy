package secret

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

type limitedReader struct{ remaining int }

func (r *limitedReader) Read(value []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("injected random source failure")
	}
	count := len(value)
	if count > r.remaining {
		count = r.remaining
	}
	for index := 0; index < count; index++ {
		value[index] = 1
	}
	r.remaining -= count
	return count, nil
}

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

func TestDeriveIsStableAndPurposeSeparated(t *testing.T) {
	masterKey := []byte(strings.Repeat("k", 32))
	first, err := Derive(masterKey, "ss2022-server-key")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Derive(masterKey, "ss2022-server-key")
	if err != nil {
		t.Fatal(err)
	}
	otherPurpose, err := Derive(masterKey, "another-purpose")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || string(first) != string(second) || string(first) == string(otherPurpose) {
		t.Fatalf("derived keys are not stable and purpose-separated: first=%x second=%x other=%x", first, second, otherPurpose)
	}
}

func TestDeriveRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		masterKey []byte
		purpose   string
	}{
		{masterKey: []byte(strings.Repeat("k", 31)), purpose: "ss2022-server-key"},
		{masterKey: []byte(strings.Repeat("k", 32)), purpose: ""},
	} {
		if key, err := Derive(test.masterKey, test.purpose); err == nil || key != nil {
			t.Errorf("Derive(%d-byte key, %q) = %x, %v; want error", len(test.masterKey), test.purpose, key, err)
		}
	}
}

func TestSealReportsRandomSourceFailuresForSaltAndNonce(t *testing.T) {
	original := rand.Reader
	t.Cleanup(func() { rand.Reader = original })
	for _, test := range []struct {
		name      string
		available int
		want      string
	}{
		{name: "salt", available: 0, want: "generate envelope salt"},
		{name: "nonce", available: 32, want: "generate envelope nonce"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rand.Reader = io.Reader(&limitedReader{remaining: test.available})
			if value, err := Seal([]byte(strings.Repeat("k", 32)), "secret", "totp"); err == nil || value != "" || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Seal() = %q, %v; want %q failure", value, err, test.want)
			}
		})
	}
}
