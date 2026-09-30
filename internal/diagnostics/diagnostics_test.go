package diagnostics

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingBundleFile struct {
	*os.File
	chmodErr       error
	writeErr       error
	failWriteAfter int
	writes         int
	syncErr        error
	closeErr       error
}

func (f *failingBundleFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *failingBundleFile) Write(data []byte) (int, error) {
	f.writes++
	if f.writeErr != nil && (f.failWriteAfter == 0 || f.writes >= f.failWriteAfter) {
		return 0, f.writeErr
	}
	return f.File.Write(data)
}

func (f *failingBundleFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *failingBundleFile) Close() error {
	actualErr := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return actualErr
}

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

func TestCreateBundleRejectsEmptyOrUnwritableDestination(t *testing.T) {
	if _, err := CreateBundle(t.TempDir(), nil, time.Time{}); err == nil {
		t.Fatal("empty support bundle was accepted")
	}
	root := t.TempDir()
	blockingFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBundle(blockingFile, map[string][]byte{"report.txt": []byte("safe")}, time.Time{}); err == nil {
		t.Fatal("bundle was created below a regular file")
	}
	if path, err := CreateBundle(root, map[string][]byte{"report.txt": []byte("safe")}, time.Time{}); err != nil {
		t.Fatalf("bundle with current UTC timestamp: %v", err)
	} else if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	occupiedPath := filepath.Join(root, "diagnostics", "doctor-20260929T100000.000000000Z.tar.gz")
	if err := os.Mkdir(occupiedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBundle(root, map[string][]byte{"report.txt": []byte("safe")}, now); err == nil {
		t.Fatal("bundle replaced an occupied directory")
	}
}

func TestCreateBundleReportsAtomicFileFailuresAndRemovesTemporaryFiles(t *testing.T) {
	for _, test := range []struct {
		failure string
		want    string
	}{
		{failure: "chmod", want: "secure doctor bundle"},
		{failure: "write", want: "write doctor bundle header"},
		{failure: "sync", want: "sync doctor bundle"},
		{failure: "close", want: "close doctor bundle"},
		{failure: "rename", want: "publish doctor bundle"},
	} {
		t.Run(test.failure, func(t *testing.T) {
			root := t.TempDir()
			injected := errors.New("injected " + test.failure + " failure")
			file := &failingBundleFile{}
			_, err := createBundleWith(root, map[string][]byte{"report.txt": []byte("report")}, time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
				func(dir, pattern string) (bundleFile, error) {
					created, err := os.CreateTemp(dir, pattern)
					if err != nil {
						return nil, err
					}
					file.File = created
					switch test.failure {
					case "chmod":
						file.chmodErr = injected
					case "write":
						file.writeErr = injected
					case "sync":
						file.syncErr = injected
					case "close":
						file.closeErr = injected
					}
					return file, nil
				}, os.Remove,
				func(source, destination string) error {
					if test.failure == "rename" {
						return injected
					}
					return os.Rename(source, destination)
				})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("createBundleWith() error = %v, want message containing %q", err, test.want)
			}
			entries, err := os.ReadDir(filepath.Join(root, "diagnostics"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed bundle left files behind: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestCreateBundleReportsTemporaryFileCreationFailure(t *testing.T) {
	wantErr := errors.New("temporary storage unavailable")
	_, err := createBundleWith(t.TempDir(), map[string][]byte{"report.txt": []byte("report")}, time.Now(),
		func(string, string) (bundleFile, error) { return nil, wantErr },
		os.Remove, os.Rename)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("temporary bundle creation error = %v", err)
	}
}

func TestCreateBundleReportsArchivePayloadWriteFailure(t *testing.T) {
	root := t.TempDir()
	wantErr := errors.New("payload write failed")
	file := &failingBundleFile{writeErr: wantErr, failWriteAfter: 2}
	payload := make([]byte, 1<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	_, err := createBundleWith(root, map[string][]byte{"report.txt": payload}, time.Now(),
		func(dir, pattern string) (bundleFile, error) {
			created, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			file.File = created
			return file, nil
		}, os.Remove, os.Rename)
	if err == nil || !strings.Contains(err.Error(), "write doctor bundle file") || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("archive payload write error = %v", err)
	}
}

func TestRedactJSONPreservesSafeScalarValues(t *testing.T) {
	got, err := RedactJSON([]byte(`{"enabled":true,"count":42,"optional":null}`))
	if err != nil || string(got) == "" || !strings.Contains(string(got), `"enabled": true`) || !strings.Contains(string(got), `"count": 42`) || !strings.Contains(string(got), `"optional": null`) {
		t.Fatalf("safe JSON scalar values = %s, %v", got, err)
	}
}

func TestArchiveNamesAndJSONRedactionRejectUnsafeInput(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../escape", "/absolute", "nested/../escape", `nested\escape`} {
		if safeArchiveName(name) {
			t.Errorf("unsafe archive name %q was accepted", name)
		}
	}
	if !safeArchiveName("nested/report.txt") {
		t.Fatal("safe nested report name was rejected")
	}
	for _, document := range []string{"{", `{"ok":true} {"extra":true}`, `{"ok":true} garbage`} {
		if _, err := RedactJSON([]byte(document)); err == nil {
			t.Errorf("invalid JSON %q was accepted", document)
		}
	}
	redacted, err := RedactJSON([]byte(`[{"name":"phone","nested":[{"short_id":"1234","note":"Bearer credential"}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), "phone") || strings.Contains(string(redacted), "1234") || strings.Contains(string(redacted), "credential") {
		t.Fatalf("nested secret leaked: %s", redacted)
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
