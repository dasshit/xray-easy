package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/store"
)

func newTestManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	root := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Initialize(context.Background(), "admin", "password-hash", "vpn.example.com", 443); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return NewManager(db, dataDir, configDir, []byte(strings.Repeat("m", 32))), db
}

func TestCreateListVerifyAndRestoreBackup(t *testing.T) {
	manager, db := newTestManager(t)
	activeConfig := `{"inbounds":[{"streamSettings":{"realitySettings":{"privateKey":"private-value","password":"password-value","token":"token-value","serverNames":["example.com"]}}}]}`
	if err := os.WriteFile(filepath.Join(manager.ConfigDir, "active.json"), []byte(activeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "before.example.com"
	if err := db.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}

	info, err := manager.Create("../release v1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(info.Name, "/") || strings.Contains(info.Name, " ") {
		t.Fatalf("backup label was not sanitized: %q", info.Name)
	}
	if info.CreatedAt.IsZero() || filepath.Dir(info.StatePath) != info.Path {
		t.Fatalf("backup metadata paths are incomplete: %+v", info)
	}
	for _, name := range []string{"state.db", "config.redacted.json", "metadata.json", "manifest.json"} {
		file, err := os.Stat(filepath.Join(info.Path, name))
		if err != nil {
			t.Fatalf("missing backup file %s: %v", name, err)
		}
		if file.Mode().Perm() != 0o600 {
			t.Errorf("backup file %s mode = %o, want 600", name, file.Mode().Perm())
		}
	}
	backupDirInfo, err := os.Stat(info.Path)
	if err != nil || backupDirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory mode = %v, %v", backupDirInfo, err)
	}
	redacted, err := os.ReadFile(filepath.Join(info.Path, "config.redacted.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"private-value", "password-value", "token-value"} {
		if strings.Contains(string(redacted), value) {
			t.Errorf("plaintext secret %q leaked into redacted config: %s", value, redacted)
		}
	}
	if !strings.Contains(string(redacted), "example.com") {
		t.Errorf("redacted config omitted non-secret server name: %s", redacted)
	}
	var decoded struct {
		Inbounds []struct {
			StreamSettings struct {
				RealitySettings map[string]any `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(redacted, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"privateKey", "password", "token"} {
		if got := decoded.Inbounds[0].StreamSettings.RealitySettings[field]; got != "<redacted>" {
			t.Errorf("field %s = %v, want redacted", field, got)
		}
	}

	verified, err := manager.Verify(info.Name)
	if err != nil || verified.Name != info.Name {
		t.Fatalf("verify created backup = %+v, %v", verified, err)
	}
	listed, err := manager.List()
	if err != nil || len(listed) != 1 || listed[0].Name != info.Name {
		t.Fatalf("backup list = %+v, %v", listed, err)
	}
	if _, err := manager.Verify("../" + info.Name); err == nil {
		t.Fatal("verify accepted a path traversal backup name")
	}
	if _, err := manager.Verify("backup-missing"); err == nil {
		t.Fatal("verify accepted nonexistent backup")
	}

	settings.PublicHost = "after.example.com"
	if err := db.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreState(verified); err != nil {
		t.Fatal(err)
	}
	restored, err := db.GetSettings(context.Background())
	if err != nil || restored.PublicHost != "before.example.com" {
		t.Fatalf("restored public host = %q, %v", restored.PublicHost, err)
	}
}

func TestBackupListHandlesMissingDirectoryAndIgnoresUnrelatedEntries(t *testing.T) {
	manager, _ := newTestManager(t)
	listed, err := manager.List()
	if err != nil || len(listed) != 0 {
		t.Fatalf("list without backup dir = %+v, %v", listed, err)
	}
	if err := os.MkdirAll(manager.BackupDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(manager.BackupDir(), "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.BackupDir(), "backup-list.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	listed, err = manager.List()
	if err != nil || len(listed) != 0 {
		t.Fatalf("list with unrelated entries = %+v, %v", listed, err)
	}
}

func TestCreateRejectsUninitializedManager(t *testing.T) {
	for _, manager := range []*Manager{
		{},
		{Store: nil, DataDir: t.TempDir(), MasterKey: []byte(strings.Repeat("m", 32))},
	} {
		if _, err := manager.Create("manual"); err == nil {
			t.Fatal("uninitialized manager created backup")
		}
	}
	manager, _ := newTestManager(t)
	manager.MasterKey = []byte("short")
	if _, err := manager.Create("manual"); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestVerifyRejectsWrongKeyTamperingAndInvalidMetadata(t *testing.T) {
	manager, _ := newTestManager(t)
	info, err := manager.Create("verify")
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := *manager
	wrongKey.MasterKey = []byte(strings.Repeat("x", 32))
	if _, err := wrongKey.Verify(info.Name); err == nil || !strings.Contains(err.Error(), "HMAC") {
		t.Fatalf("wrong master key verification error = %v", err)
	}
	configPath := filepath.Join(info.Path, "config.redacted.json")
	if err := os.WriteFile(configPath, []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(info.Name); err == nil || !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("tampered size verification error = %v", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(info.Path, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var signed manifest
	if err := json.Unmarshal(manifestBytes, &signed); err != nil {
		t.Fatal(err)
	}
	var expectedSize int64
	for _, file := range signed.Files {
		if file.Path == "config.redacted.json" {
			expectedSize = file.Size
		}
	}
	if expectedSize == 0 {
		t.Fatal("manifest omitted config size")
	}
	sameSize := make([]byte, expectedSize)
	for i := range sameSize {
		sameSize[i] = 'x'
	}
	if err := os.WriteFile(configPath, sameSize, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(info.Name); err == nil || !strings.Contains(err.Error(), "hash verification failed") {
		t.Fatalf("same-size tampering verification error = %v", err)
	}
	if _, err := manager.Verify(""); err == nil {
		t.Fatal("empty backup name accepted")
	}

	malformed := filepath.Join(manager.BackupDir(), "backup-malformed")
	if err := os.Mkdir(malformed, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(filepath.Base(malformed)); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("missing metadata error = %v", err)
	}
	metadataPath := filepath.Join(malformed, "metadata.json")
	if err := os.WriteFile(metadataPath, []byte(`{"format_version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(filepath.Base(malformed)); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported metadata error = %v", err)
	}
	if err := os.WriteFile(metadataPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(filepath.Base(malformed)); err == nil {
		t.Fatal("malformed metadata accepted")
	}
}

func TestBackupRetentionAndPreservingOlderBackup(t *testing.T) {
	manager, _ := newTestManager(t)
	first, err := manager.Create("oldest")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < retention; i++ {
		if _, err := manager.Create("regular"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.CreatePreserving("rotation", first.Name); err != nil {
		t.Fatal(err)
	}
	listed, err := manager.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != retention {
		t.Fatalf("retention kept %d backups, want %d", len(listed), retention)
	}
	foundPreserved := false
	for _, item := range listed {
		if item.Name == first.Name {
			foundPreserved = true
		}
	}
	if !foundPreserved {
		t.Fatal("CreatePreserving deleted the selected older backup")
	}

	// A new manager in an isolated directory checks ordinary pruning after
	// successful backup creation has already filled the retention window.
	other, _ := newTestManager(t)
	for i := 0; i < retention+1; i++ {
		if _, err := other.Create("prune"); err != nil {
			t.Fatal(err)
		}
	}
	pruned, err := other.List()
	if err != nil || len(pruned) != retention {
		t.Fatalf("ordinary retention result has %d backups, %v", len(pruned), err)
	}
}

func TestWriteRedactedConfigHandlesMissingAndMalformedFiles(t *testing.T) {
	manager, _ := newTestManager(t)
	path := filepath.Join(t.TempDir(), "config.json")
	present, err := manager.writeRedactedConfig(path)
	if err != nil || present {
		t.Fatalf("missing active config result = %v, %v", present, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "{}\n" {
		t.Fatalf("missing config backup content = %q, %v", data, err)
	}
	badConfig := filepath.Join(manager.ConfigDir, "active.json")
	if err := os.WriteFile(badConfig, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.writeRedactedConfig(path); err == nil {
		t.Fatal("malformed active config accepted")
	}
	if err := os.WriteFile(badConfig, []byte(`{"log":{"loglevel":"warning"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.writeRedactedConfig(filepath.Join(t.TempDir(), "missing-dir", "config.json")); err == nil {
		t.Fatal("write into missing directory unexpectedly succeeded")
	}
	if err := os.WriteFile(badConfig, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create("invalid-config"); err == nil {
		t.Fatal("backup created from malformed active config")
	}
	entries, err := os.ReadDir(manager.BackupDir())
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary backup files leaked after failure: %v, %v", entries, err)
	}
}

func TestRestoreStateRejectsUninitializedManager(t *testing.T) {
	if err := (&Manager{}).RestoreState(Info{}); err == nil {
		t.Fatal("restore succeeded without a Store")
	}
}

func TestManifestRejectsInvalidSignatureFormatAndTraversal(t *testing.T) {
	root := t.TempDir()
	key := []byte(strings.Repeat("m", 32))
	writeManifest := func(value manifest) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"{", `{"format_version":99,"hmac_sha256":"x"}`, `{"format_version":1}`} {
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyManifest(root, key); err == nil {
			t.Errorf("verifyManifest accepted malformed manifest %s", raw)
		}
	}
	value := manifest{FormatVersion: formatVersion, Files: []manifestFile{{Path: "../outside", Size: 0, SHA256: ""}}}
	unsigned, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	value.HMACSHA256 = hmacSHA256(key, unsigned)
	writeManifest(value)
	if err := verifyManifest(root, key); err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("manifest traversal error = %v", err)
	}
}

func TestSanitizeLabel(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"release-1", "release-1"},
		{"../release v1", "releasev1"},
		{"---___", "manual"},
		{"☃", "manual"},
	} {
		if got := sanitizeLabel(test.input); got != test.want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestHMACAndHashFiles(t *testing.T) {
	if hmacSHA256([]byte("key"), []byte("data")) == hmacSHA256([]byte("other"), []byte("data")) {
		t.Fatal("HMAC does not depend on key")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := hashFiles(root, []string{"one"})
	if err != nil || len(files) != 1 || files[0].Size != int64(len("contents")) || files[0].SHA256 == "" {
		t.Fatalf("hashFiles = %+v, %v", files, err)
	}
	if _, err := hashFiles(root, []string{"missing"}); err == nil {
		t.Fatal("hashFiles accepted a missing file")
	}
}
