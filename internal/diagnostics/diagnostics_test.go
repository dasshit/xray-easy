package diagnostics

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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

func TestRedactJSONMasksCredentialsAndDeviceIdentifiers(t *testing.T) {
	input := []byte(`{"inbounds":[{"settings":{"clients":[{"id":"123e4567-e89b-12d3-a456-426614174000","email":"phone","flow":"xtls-rprx-vision"}]},"realitySettings":{"privateKey":"private","shortIds":["secret-id"]}}]}`)
	got, err := RedactJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"123e4567-e89b-12d3-a456-426614174000", "phone", `"private"`, "secret-id"} {
		if strings.Contains(string(got), secret) {
			t.Errorf("redacted JSON leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(string(got), "xtls-rprx-vision") || !strings.Contains(string(got), "[REDACTED]") {
		t.Fatalf("config details or redaction markers are missing: %s", got)
	}
}

func TestCreateBundleWritesPrivateTarGzipAndRejectsUnsafePaths(t *testing.T) {
	dataDir := t.TempDir()
	now := time.Date(2026, 9, 28, 10, 11, 12, 123, time.UTC)
	path, err := CreateBundle(dataDir, map[string][]byte{"report.txt": []byte("safe report")}, now)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode = %o, want 600", info.Mode().Perm())
	}
	directoryInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("bundle directory mode = %o, want 700", directoryInfo.Mode().Perm())
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	header, err := archive.Next()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(archive)
	if err != nil || header.Name != "report.txt" || string(contents) != "safe report" {
		t.Fatalf("unexpected bundle entry %q (%q), err=%v", header.Name, contents, err)
	}
	if _, err := CreateBundle(dataDir, map[string][]byte{"../outside": []byte("no")}, now.Add(time.Second)); err == nil {
		t.Fatal("bundle accepted path traversal")
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
