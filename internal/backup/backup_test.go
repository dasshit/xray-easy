package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/store"
)

type awgBackupStub struct {
	current       []byte
	exported      int
	restored      [][]byte
	exportErr     error
	restoreErr    error
	restoreErrors []error
}

func (s *awgBackupStub) ExportBackup(context.Context) ([]byte, error) {
	s.exported++
	return append([]byte(nil), s.current...), s.exportErr
}

func (s *awgBackupStub) RestoreBackup(_ context.Context, data []byte) error {
	s.restored = append(s.restored, append([]byte(nil), data...))
	if index := len(s.restored) - 1; index < len(s.restoreErrors) {
		return s.restoreErrors[index]
	}
	return s.restoreErr
}

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

func TestBackupIncludesAndRestoresHysteriaTLSVersions(t *testing.T) {
	manager, db := newTestManager(t)
	root := filepath.Join(manager.DataDir, "hysteria-tls")
	id := "0123456789abcdef0123456789abcdef"
	certificateDir := filepath.Join(root, id)
	if err := os.MkdirAll(certificateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"fullchain.pem": "certificate-before", "privkey.pem": "private-key-before"} {
		if err := os.WriteFile(filepath.Join(certificateDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	settings := domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSCustom, CertificateID: id, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.InitializeHysteriaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create("hysteria")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(info.Name); err != nil {
		t.Fatalf("verify backup with nested TLS files: %v", err)
	}
	for name, content := range map[string]string{"fullchain.pem": "certificate-after", "privkey.pem": "private-key-after"} {
		if err := os.WriteFile(filepath.Join(certificateDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.RestoreState(info); err != nil {
		t.Fatalf("restore backup with TLS versions: %v", err)
	}
	for name, expected := range map[string]string{"fullchain.pem": "certificate-before", "privkey.pem": "private-key-before"} {
		got, err := os.ReadFile(filepath.Join(certificateDir, name))
		if err != nil || string(got) != expected {
			t.Fatalf("restored %s = %q, %v; want %q", name, got, err, expected)
		}
	}
	got, err := db.GetHysteriaSettings(context.Background())
	if err != nil || !got.Enabled || got.CertificateID != id {
		t.Fatalf("restored Hysteria settings = %+v, %v", got, err)
	}
}

func TestRestoreWithoutTLSFilesDisablesHysteriaAndClearsCertificateReference(t *testing.T) {
	manager, db := newTestManager(t)
	settings := domain.HysteriaSettings{
		Enabled: true, TLSMode: domain.HysteriaTLSCustom, CertificateID: "0123456789abcdef0123456789abcdef",
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	if err := db.InitializeHysteriaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create("without-tls")
	if err != nil {
		t.Fatal(err)
	}

	// The current host may have a certificate that was added after the backup.
	// Restore must not keep the restored inbound enabled while its certificate
	// files are absent from the snapshot.
	currentTLS := filepath.Join(manager.DataDir, "hysteria-tls", settings.CertificateID)
	if err := os.MkdirAll(currentTLS, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(currentTLS, "fullchain.pem"), []byte("new certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreState(info); err != nil {
		t.Fatalf("restore backup without TLS files: %v", err)
	}
	got, err := db.GetHysteriaSettings(context.Background())
	if err != nil || got.Enabled || got.CertificateID != "" {
		t.Fatalf("restored Hysteria settings = %+v, %v; want disabled and no certificate reference", got, err)
	}
	if _, err := os.Stat(filepath.Join(currentTLS, "fullchain.pem")); err != nil {
		t.Fatalf("backup without TLS files unexpectedly removed current files: %v", err)
	}
}

func TestRestoreRollsBackSQLiteWhenHysteriaDisableFails(t *testing.T) {
	manager, db := newTestManager(t)
	settings := domain.HysteriaSettings{
		Enabled: true, TLSMode: domain.HysteriaTLSCustom,
		CertificateID:  "0123456789abcdef0123456789abcdef",
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	if err := db.InitializeHysteriaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	mutationDB, err := sql.Open("sqlite", "file:"+filepath.Join(filepath.Dir(manager.DataDir), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mutationDB.Exec(`CREATE TRIGGER reject_hysteria_disable BEFORE UPDATE ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'disable blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := mutationDB.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := manager.Create("disable-failure")
	if err != nil {
		t.Fatal(err)
	}
	err = manager.RestoreState(info)
	if err == nil || !strings.Contains(err.Error(), "disable Hysteria 2 after restore") || !strings.Contains(err.Error(), "disable blocked") {
		t.Fatalf("restore error = %v, want Hysteria disable failure", err)
	}
	current, getErr := db.GetHysteriaSettings(context.Background())
	if getErr != nil || !current.Enabled || current.CertificateID != settings.CertificateID {
		t.Fatalf("failed restore did not roll Hysteria settings back: %+v, %v", current, getErr)
	}
}

func TestBackupIncludesAWGSnapshotAndRestoresThroughService(t *testing.T) {
	manager, _ := newTestManager(t)
	awg := &awgBackupStub{current: []byte("snapshot-before")}
	manager.AWG = awg
	info, err := manager.CreateContext(context.Background(), "awg")
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(info.Path, "amneziawg.tar.gz"))
	if err != nil || !bytes.Equal(archive, awg.current) {
		t.Fatalf("AWG snapshot in backup = %q, %v", archive, err)
	}
	if _, err := manager.Verify(info.Name); err != nil {
		t.Fatalf("verify AWG backup: %v", err)
	}
	awg.current = []byte("snapshot-after")
	if err := manager.RestoreStateContext(context.Background(), info); err != nil {
		t.Fatalf("restore AWG snapshot: %v", err)
	}
	if len(awg.restored) != 1 || !bytes.Equal(awg.restored[0], []byte("snapshot-before")) {
		t.Fatalf("AWG restore calls = %q", awg.restored)
	}
	if awg.exported != 2 {
		t.Fatalf("current AWG snapshots = %d, want backup and pre-restore snapshot", awg.exported)
	}
}

func TestRestoreRejectsAWGBackupWhenServiceUnavailableBeforeChangingState(t *testing.T) {
	manager, db := newTestManager(t)
	awg := &awgBackupStub{current: []byte("snapshot")}
	manager.AWG = awg
	info, err := manager.Create("awg")
	if err != nil {
		t.Fatal(err)
	}
	manager.AWG = nil
	if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "enable the AmneziaWG Compose profile") {
		t.Fatalf("restore without AWG service error = %v", err)
	}
	settings, err := db.GetSettings(context.Background())
	if err != nil || settings.PublicHost != "vpn.example.com" {
		t.Fatalf("failed restore changed SQLite state: settings=%+v error=%v", settings, err)
	}
}

func TestCreateRejectsUnavailableOrInvalidAWGBackup(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		err  error
	}{
		{name: "service error", data: []byte("snapshot"), err: errors.New("service unavailable")},
		{name: "empty snapshot"},
		{name: "snapshot too large", data: make([]byte, maxAWGSnapshot+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, _ := newTestManager(t)
			manager.AWG = &awgBackupStub{current: test.data, exportErr: test.err}
			if _, err := manager.Create("awg"); err == nil {
				t.Fatal("created a backup from unavailable or invalid AWG data")
			}
			entries, err := os.ReadDir(manager.BackupDir())
			if err == nil && len(entries) != 0 {
				t.Fatalf("failed backup left files behind: %v", entries)
			}
		})
	}
}

func TestRestoreRequiresAWGStateAndRejectsMalformedBackupFile(t *testing.T) {
	manager, _ := newTestManager(t)
	withoutAWG, err := manager.Create("without-awg")
	if err != nil {
		t.Fatal(err)
	}
	manager.AWG = &awgBackupStub{current: []byte("current")}
	if err := manager.RestoreState(withoutAWG); err == nil || !strings.Contains(err.Error(), "does not contain AmneziaWG state") {
		t.Fatalf("restore without AWG snapshot error = %v", err)
	}

	withAWGManager, _ := newTestManager(t)
	withAWGManager.AWG = &awgBackupStub{current: []byte("snapshot")}
	withAWG, err := withAWGManager.Create("with-awg")
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(withAWG.Path, "amneziawg.tar.gz")
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(snapshotPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := withAWGManager.RestoreState(withAWG); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("restore with directory as AWG snapshot error = %v", err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	oversized, err := os.Create(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(maxAWGSnapshot + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	if err := withAWGManager.RestoreState(withAWG); err == nil || !strings.Contains(err.Error(), "exceeds the size limit") {
		t.Fatalf("restore with oversized AWG snapshot error = %v", err)
	}
}

func TestRestoreRollsBackSQLiteAndAWGWhenApplyingAWGSnapshotFails(t *testing.T) {
	manager, db := newTestManager(t)
	awg := &awgBackupStub{
		current:       []byte("snapshot-before"),
		restoreErrors: []error{errors.New("apply failed"), nil},
	}
	manager.AWG = awg
	info, err := manager.Create("rollback")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "live.example.test"
	if err := db.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("restore with injected AWG failure error = %v", err)
	}
	current, err := db.GetSettings(context.Background())
	if err != nil || current.PublicHost != "live.example.test" {
		t.Fatalf("SQLite state after rollback = %+v, %v", current, err)
	}
	if len(awg.restored) != 2 || !bytes.Equal(awg.restored[1], []byte("snapshot-before")) {
		t.Fatalf("AWG rollback calls = %q", awg.restored)
	}
}

func TestRestoreReportsIncompleteRollbackWhenAWGRollbackAlsoFails(t *testing.T) {
	manager, _ := newTestManager(t)
	awg := &awgBackupStub{
		current:       []byte("snapshot-before"),
		restoreErrors: []error{errors.New("apply failed"), errors.New("rollback failed")},
	}
	manager.AWG = awg
	info, err := manager.Create("rollback-failure")
	if err != nil {
		t.Fatal(err)
	}
	err = manager.RestoreState(info)
	if err == nil || !strings.Contains(err.Error(), "rollback was incomplete") || !strings.Contains(err.Error(), "AmneziaWG: rollback failed") {
		t.Fatalf("restore error did not report incomplete AWG rollback: %v", err)
	}
	if len(awg.restored) != 2 {
		t.Fatalf("expected failed restore and rollback attempts, got %d calls", len(awg.restored))
	}
}

func TestRestoreStopsBeforeStateChangesWhenCurrentAWGSnapshotFails(t *testing.T) {
	manager, db := newTestManager(t)
	awg := &awgBackupStub{current: []byte("before")}
	manager.AWG = awg
	info, err := manager.Create("snapshot-failure")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := db.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "live.example.test"
	if err := db.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	awg.exportErr = errors.New("cannot snapshot live state")
	if err := manager.RestoreState(info); err == nil || !strings.Contains(err.Error(), "snapshot current AmneziaWG") {
		t.Fatalf("restore with current snapshot failure = %v", err)
	}
	current, err := db.GetSettings(context.Background())
	if err != nil || current.PublicHost != "live.example.test" {
		t.Fatalf("failed preflight changed SQLite state = %+v, %v", current, err)
	}
}

func TestRestoreRejectsUninitializedManager(t *testing.T) {
	if err := (&Manager{}).RestoreStateContext(context.Background(), Info{}); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("restore with uninitialized manager error = %v", err)
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
	if err := verifyManifest(root, key); err == nil || !strings.Contains(err.Error(), "read backup manifest") {
		t.Fatalf("verifyManifest() without a manifest = %v", err)
	}
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

func TestCreateReportsBackupDirectoryFilesystemFailure(t *testing.T) {
	manager, _ := newTestManager(t)
	// A regular file at the backup root makes MkdirAll fail before any backup
	// artifact is created; this keeps the failure deterministic and verifies the
	// installer-visible error path.
	root := filepath.Join(manager.DataDir, "blocked-backups")
	if err := os.MkdirAll(manager.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager.DataDir = root
	if _, err := manager.Create("filesystem-failure"); err == nil {
		t.Fatal("backup creation succeeded below a regular file")
	}
}
