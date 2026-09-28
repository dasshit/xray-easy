package diagnostics

import (
	"strings"
	"testing"
	"time"
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

func TestBufferAppliesDefaultLimitAndSnapshotBounds(t *testing.T) {
	buffer := NewBuffer(0)
	buffer.Add("api", "info", "first")
	buffer.Add("api", "warn", "second")
	if got := len(buffer.Snapshot(-1)); got != 2 {
		t.Fatalf("non-positive snapshot limit returned %d entries", got)
	}
	if got := buffer.Snapshot(1); len(got) != 1 || got[0].Message != "second" {
		t.Fatalf("limited snapshot = %+v", got)
	}
	entry := buffer.Snapshot(99)[0]
	if entry.Component != "api" || entry.Level != "info" || entry.At.IsZero() || entry.At.Location() != time.UTC {
		t.Fatalf("entry metadata is incomplete: %+v", entry)
	}
}

func TestBufferNilReceiverIsSafe(t *testing.T) {
	var buffer *Buffer
	buffer.Add("api", "error", "ignored")
	if got := buffer.Snapshot(0); len(got) != 0 {
		t.Fatalf("nil buffer snapshot = %+v", got)
	}
}

func TestRedactMasksUnquotedFieldsAndTrimsWhitespace(t *testing.T) {
	got := Redact("  privateKey: key-value master_key=master-value short_id:abc123  ")
	for _, secret := range []string{"key-value", "master-value", "abc123"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q leaked in %q", secret, got)
		}
	}
	if got != "privateKey: [REDACTED] master_key=[REDACTED] short_id:[REDACTED]" {
		t.Fatalf("unexpected redaction output: %q", got)
	}
}
