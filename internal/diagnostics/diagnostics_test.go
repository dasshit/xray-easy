package diagnostics

import (
	"strings"
	"testing"
)

func TestRedactMasksSecretsAndBearerValues(t *testing.T) {
	value := `level=error password="secret" private_key=abc token: bearer123 Authorization: Bearer api-token shortId=deadbeef uuid=123e4567-e89b-12d3-a456-426614174000 vless://uuid@example.com:443?pbk=public#phone json={"privateKey":"json-secret","password":"json-password","token":"json-token"}`
	redacted := Redact(value)
	for _, secret := range []string{"secret", "abc", "bearer123", "api-token", "deadbeef", "123e4567-e89b-12d3-a456-426614174000", "vless://uuid@example.com", "json-secret", "json-password", "json-token"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("secret %q leaked in %q", secret, redacted)
		}
	}
	if !strings.Contains(redacted, "[REDACTED]") || !strings.Contains(redacted, "[REDACTED-UUID]") {
		t.Fatalf("redaction markers missing: %q", redacted)
	}
}

func TestBufferKeepsBoundedTail(t *testing.T) {
	buffer := NewBuffer(2)
	buffer.Add("app", "error", "one")
	buffer.Add("app", "warn", "two")
	buffer.Add("app", "error", "three")
	entries := buffer.Snapshot(0)
	if len(entries) != 2 || entries[0].Message != "two" || entries[1].Message != "three" {
		t.Fatalf("unexpected tail: %+v", entries)
	}
}
