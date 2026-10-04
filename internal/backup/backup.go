// Package backup creates, lists, verifies, and restores plaintext data-directory backups.
package backup

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xray-easy/internal/store"
)

const (
	// formatVersion is an internal package constant.
	formatVersion = 1
	// retention is an internal package constant.
	retention = 10
	// maxAWGSnapshot is an internal package constant.
	maxAWGSnapshot = 16 << 20
)

// Manager coordinates backup retention and database snapshot operations.
type Manager struct {
	// Store contains the Store value for this object.
	Store *store.Store
	// DataDir is the persistent data directory.
	DataDir string
	// ConfigDir contains the ConfigDir value for this object.
	ConfigDir string
	// MasterKey is the master key used to encrypt persisted secrets.
	MasterKey []byte
	// AWG contains the AWG value for this object.
	AWG AWGBackup
}

// AWGBackup exports and restores the optional AmneziaWG service state,
// including client private-key profiles.
type AWGBackup interface {
	// ExportBackup defines part of the interface contract.
	ExportBackup(context.Context) ([]byte, error)
	// RestoreBackup defines part of the interface contract.
	RestoreBackup(context.Context, []byte) error
}

// Info describes one backup archive and its verification metadata.
type Info struct {
	// Name is the human-readable name of the object.
	Name string
	// Path contains the Path value for this object.
	Path string
	// StatePath contains the StatePath value for this object.
	StatePath string
	// CreatedAt is the time the object was created.
	CreatedAt time.Time
}

// metadata is an internal type used by the package.
type metadata struct {
	// FormatVersion stores the value associated with the enclosing object.
	FormatVersion int `json:"format_version"`
	// CreatedAt stores the value associated with the enclosing object.
	CreatedAt time.Time `json:"created_at"`
	// ConfigPresent stores the value associated with the enclosing object.
	ConfigPresent bool `json:"config_present"`
	// TLSCertificatesPresent stores the value associated with the enclosing object.
	TLSCertificatesPresent bool `json:"tls_certificates_present,omitempty"`
	// AWGStatePresent stores the value associated with the enclosing object.
	AWGStatePresent bool `json:"awg_state_present,omitempty"`
}

// manifest is an internal type used by the package.
type manifest struct {
	// FormatVersion stores the value associated with the enclosing object.
	FormatVersion int `json:"format_version"`
	// Files stores the value associated with the enclosing object.
	Files []manifestFile `json:"files"`
	// HMACSHA256 stores the value associated with the enclosing object.
	HMACSHA256 string `json:"hmac_sha256"`
}

// manifestFile is an internal type used by the package.
type manifestFile struct {
	// Path stores the value associated with the enclosing object.
	Path string `json:"path"`
	// Size stores the value associated with the enclosing object.
	Size int64 `json:"size"`
	// SHA256 stores the value associated with the enclosing object.
	SHA256 string `json:"sha256"`
}

// NewManager constructs and returns the requested value.
func NewManager(db *store.Store, dataDir, configDir string, masterKey []byte) *Manager {
	return &Manager{Store: db, DataDir: dataDir, ConfigDir: configDir, MasterKey: masterKey}
}

// BackupDir performs the operation represented by its name.
func (m *Manager) BackupDir() string { return filepath.Join(m.DataDir, "backups") }

// Create creates the requested value.
func (m *Manager) Create(label string) (Info, error) {
	return m.CreateContext(context.Background(), label)
}

// CreateContext creates a consistent control-plane backup and includes an
// AmneziaWG snapshot whenever the optional service is configured.
func (m *Manager) CreateContext(ctx context.Context, label string) (Info, error) {
	return m.create(ctx, label, nil)
}

// CreatePreserving creates the requested value.
func (m *Manager) CreatePreserving(label, preserveName string) (Info, error) {
	return m.CreatePreservingContext(context.Background(), label, preserveName)
}

// CreatePreservingContext creates a backup while retaining the named older
// snapshot during retention pruning.
func (m *Manager) CreatePreservingContext(ctx context.Context, label, preserveName string) (Info, error) {
	return m.create(ctx, label, map[string]struct{}{preserveName: {}})
}

// create creates the requested value.
func (m *Manager) create(ctx context.Context, label string, preserve map[string]struct{}) (Info, error) {
	if m.Store == nil || len(m.MasterKey) < 32 {
		return Info{}, errors.New("backup manager is not initialized")
	}
	if err := os.MkdirAll(m.BackupDir(), 0o700); err != nil {
		return Info{}, err
	}
	suffix, err := randomSuffix()
	if err != nil {
		return Info{}, err
	}
	label = sanitizeLabel(label)
	name := fmt.Sprintf("backup-%s-%s-%s", time.Now().UTC().Format("20060102T150405Z"), label, suffix)
	tmp, err := os.MkdirTemp(m.BackupDir(), ".tmp-")
	if err != nil {
		return Info{}, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return Info{}, err
	}
	statePath := filepath.Join(tmp, "state.db")
	if err := m.Store.BackupTo(statePath); err != nil {
		return Info{}, fmt.Errorf("backup SQLite: %w", err)
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		return Info{}, err
	}
	configPresent, err := m.writeRedactedConfig(filepath.Join(tmp, "config.redacted.json"))
	if err != nil {
		return Info{}, err
	}
	tlsPresent, err := copyTLSDirectory(filepath.Join(m.DataDir, "hysteria-tls"), filepath.Join(tmp, "hysteria-tls"))
	if err != nil {
		return Info{}, fmt.Errorf("backup Hysteria 2 TLS certificates: %w", err)
	}
	if !tlsPresent {
		_ = os.RemoveAll(filepath.Join(tmp, "hysteria-tls"))
	}
	awgPresent := false
	if m.AWG != nil {
		awgCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		awgSnapshot, backupErr := m.AWG.ExportBackup(awgCtx)
		cancel()
		if backupErr != nil {
			return Info{}, fmt.Errorf("backup AmneziaWG state: %w", backupErr)
		}
		if len(awgSnapshot) == 0 {
			return Info{}, errors.New("backup AmneziaWG state: service returned an empty snapshot")
		}
		if len(awgSnapshot) > maxAWGSnapshot {
			return Info{}, errors.New("backup AmneziaWG state: snapshot exceeds the size limit")
		}
		if err := writeFile(filepath.Join(tmp, "amneziawg.tar.gz"), awgSnapshot, 0o600); err != nil {
			return Info{}, fmt.Errorf("save AmneziaWG snapshot: %w", err)
		}
		awgPresent = true
	}
	createdAt := time.Now().UTC()
	metaBytes, err := json.Marshal(metadata{FormatVersion: formatVersion, CreatedAt: createdAt, ConfigPresent: configPresent, TLSCertificatesPresent: tlsPresent, AWGStatePresent: awgPresent})
	if err != nil {
		return Info{}, err
	}
	if err := writeFile(filepath.Join(tmp, "metadata.json"), metaBytes, 0o600); err != nil {
		return Info{}, err
	}
	fileNames := []string{"state.db", "config.redacted.json", "metadata.json"}
	if awgPresent {
		fileNames = append(fileNames, "amneziawg.tar.gz")
	}
	if tlsPresent {
		tlsFiles, listErr := listRelativeFiles(tmp, "hysteria-tls")
		if listErr != nil {
			return Info{}, listErr
		}
		fileNames = append(fileNames, tlsFiles...)
	}
	files, err := hashFiles(tmp, fileNames)
	if err != nil {
		return Info{}, err
	}
	unsigned := manifest{FormatVersion: formatVersion, Files: files}
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil {
		return Info{}, err
	}
	signature := hmacSHA256(m.MasterKey, unsignedBytes)
	full := unsigned
	full.HMACSHA256 = signature
	manifestBytes, err := json.Marshal(full)
	if err != nil {
		return Info{}, err
	}
	if err := writeFile(filepath.Join(tmp, "manifest.json"), manifestBytes, 0o600); err != nil {
		return Info{}, err
	}
	finalPath := filepath.Join(m.BackupDir(), name)
	if err := os.Rename(tmp, finalPath); err != nil {
		return Info{}, err
	}
	if err := syncDir(m.BackupDir()); err != nil {
		return Info{}, err
	}
	_ = m.prune(preserve)
	return Info{Name: name, Path: finalPath, StatePath: filepath.Join(finalPath, "state.db"), CreatedAt: createdAt}, nil
}

// List returns the requested collection.
func (m *Manager) List() ([]Info, error) {
	entries, err := os.ReadDir(m.BackupDir())
	if os.IsNotExist(err) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]Info, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "backup-") {
			continue
		}
		info, err := m.inspect(entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name > result[j].Name })
	return result, nil
}

// Verify verifies the supplied value.
func (m *Manager) Verify(name string) (Info, error) {
	info, err := m.inspect(name)
	if err != nil {
		return Info{}, err
	}
	if err := verifyManifest(info.Path, m.MasterKey); err != nil {
		return Info{}, err
	}
	if err := store.ValidateDatabase(info.StatePath); err != nil {
		return Info{}, fmt.Errorf("backup database validation: %w", err)
	}
	return info, nil
}

// RestoreState restores the requested state.
func (m *Manager) RestoreState(info Info) error {
	return m.RestoreStateContext(context.Background(), info)
}

// RestoreStateContext restores SQLite, Xray-related files and optional
// AmneziaWG state. It rolls the live components back if one restore step fails.
func (m *Manager) RestoreStateContext(ctx context.Context, info Info) error {
	if m.Store == nil {
		return errors.New("backup manager is not initialized")
	}
	backupAWGPath := filepath.Join(info.Path, "amneziawg.tar.gz")
	var backupAWG []byte
	awgPresent := false
	if info, statErr := os.Lstat(backupAWGPath); statErr == nil {
		if !info.Mode().IsRegular() {
			return errors.New("AmneziaWG backup is not a regular file")
		}
		awgPresent = true
		if info.Size() > maxAWGSnapshot {
			return errors.New("AmneziaWG backup exceeds the size limit")
		}
		backupAWG, statErr = os.ReadFile(backupAWGPath)
		if statErr != nil {
			return fmt.Errorf("read AmneziaWG backup: %w", statErr)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect AmneziaWG backup: %w", statErr)
	}
	if m.AWG != nil && !awgPresent {
		return errors.New("backup does not contain AmneziaWG state; restore it with a backup created while AmneziaWG was enabled")
	}
	if m.AWG == nil && awgPresent {
		return errors.New("backup contains AmneziaWG state; enable the AmneziaWG Compose profile before restoring it")
	}
	var previousAWG []byte
	if m.AWG != nil {
		awgCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		snapshot, err := m.AWG.ExportBackup(awgCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("snapshot current AmneziaWG state before restore: %w", err)
		}
		previousAWG = snapshot
	}
	stageRoot, err := os.MkdirTemp(m.DataDir, ".state-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)
	previousStatePath := filepath.Join(stageRoot, "previous-state.db")
	if err := m.Store.BackupTo(previousStatePath); err != nil {
		return fmt.Errorf("snapshot current SQLite state before restore: %w", err)
	}
	stageTLS := filepath.Join(stageRoot, "hysteria-tls")
	backupTLS := filepath.Join(info.Path, "hysteria-tls")
	tlsPresent := false
	if _, err := os.Stat(backupTLS); err == nil {
		var copyErr error
		tlsPresent, copyErr = copyTLSDirectory(backupTLS, stageTLS)
		if copyErr != nil {
			return fmt.Errorf("prepare Hysteria 2 TLS restore: %w", copyErr)
		}
		if !tlsPresent {
			_ = os.RemoveAll(stageTLS)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	targetTLS := filepath.Join(m.DataDir, "hysteria-tls")
	oldTLS := filepath.Join(stageRoot, "previous-hysteria-tls")
	hadOldTLS := false
	tlsChanged := false
	if tlsPresent {
		if _, err := os.Stat(targetTLS); err == nil {
			if err := os.Rename(targetTLS, oldTLS); err != nil {
				return fmt.Errorf("stage current Hysteria 2 TLS files: %w", err)
			}
			hadOldTLS = true
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(stageTLS, targetTLS); err != nil {
			if hadOldTLS {
				_ = os.Rename(oldTLS, targetTLS)
			}
			return fmt.Errorf("install restored Hysteria 2 TLS files: %w", err)
		}
		tlsChanged = true
	}
	rollback := func(restoreAWG bool) []string {
		var failures []string
		if err := m.Store.RestoreFrom(previousStatePath); err != nil {
			failures = append(failures, "SQLite: "+err.Error())
		}
		if tlsChanged {
			if err := os.RemoveAll(targetTLS); err != nil {
				failures = append(failures, "Hysteria TLS cleanup: "+err.Error())
			}
			if hadOldTLS {
				if err := os.Rename(oldTLS, targetTLS); err != nil {
					failures = append(failures, "Hysteria TLS restore: "+err.Error())
				}
			}
		}
		if restoreAWG && m.AWG != nil {
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := m.AWG.RestoreBackup(rollbackCtx, previousAWG); err != nil {
				failures = append(failures, "AmneziaWG: "+err.Error())
			}
			rollbackCancel()
		}
		return failures
	}
	if err := m.Store.RestoreFrom(info.StatePath); err != nil {
		rollbackErrors := rollback(false)
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("restore SQLite state: %w; rollback was incomplete (%s)", err, strings.Join(rollbackErrors, "; "))
		}
		return err
	}
	if m.AWG != nil {
		awgCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		restoreErr := m.AWG.RestoreBackup(awgCtx, backupAWG)
		cancel()
		if restoreErr != nil {
			rollbackErrors := rollback(true)
			if len(rollbackErrors) > 0 {
				return fmt.Errorf("restore AmneziaWG backup: %w; rollback was incomplete (%s)", restoreErr, strings.Join(rollbackErrors, "; "))
			}
			return fmt.Errorf("restore AmneziaWG backup: %w", restoreErr)
		}
	}
	if !tlsPresent {
		settings, getErr := m.Store.GetHysteriaSettings(ctx)
		if errors.Is(getErr, sql.ErrNoRows) {
			return nil
		}
		if getErr != nil {
			rollbackErrors := rollback(m.AWG != nil)
			if len(rollbackErrors) > 0 {
				return fmt.Errorf("read restored Hysteria 2 settings: %w; rollback was incomplete (%s)", getErr, strings.Join(rollbackErrors, "; "))
			}
			return fmt.Errorf("read restored Hysteria 2 settings: %w", getErr)
		}
		settings.Enabled = false
		settings.CertificateID = ""
		if err := m.Store.UpdateHysteriaSettings(ctx, settings); err != nil {
			rollbackErrors := rollback(m.AWG != nil)
			if len(rollbackErrors) > 0 {
				return fmt.Errorf("disable Hysteria 2 after restore: %w; rollback was incomplete (%s)", err, strings.Join(rollbackErrors, "; "))
			}
			return fmt.Errorf("disable Hysteria 2 after restore: %w", err)
		}
	}
	return nil
}

// inspect performs the operation represented by its name.
func (m *Manager) inspect(name string) (Info, error) {
	if name == "" || filepath.Base(name) != name || !strings.HasPrefix(name, "backup-") {
		return Info{}, errors.New("invalid backup name")
	}
	path := filepath.Join(m.BackupDir(), name)
	stat, err := os.Stat(path)
	if err != nil || !stat.IsDir() {
		return Info{}, errors.New("backup not found")
	}
	metaBytes, err := os.ReadFile(filepath.Join(path, "metadata.json"))
	if err != nil {
		return Info{}, fmt.Errorf("read backup metadata: %w", err)
	}
	var meta metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil || meta.FormatVersion != formatVersion {
		return Info{}, errors.New("unsupported backup metadata")
	}
	awgInfo, awgErr := os.Lstat(filepath.Join(path, "amneziawg.tar.gz"))
	awgPresent := awgErr == nil && awgInfo.Mode().IsRegular()
	if awgErr != nil && !os.IsNotExist(awgErr) || meta.AWGStatePresent != awgPresent {
		return Info{}, errors.New("backup AmneziaWG metadata does not match its files")
	}
	return Info{Name: name, Path: path, StatePath: filepath.Join(path, "state.db"), CreatedAt: meta.CreatedAt}, nil
}

// writeRedactedConfig writes the supplied value.
func (m *Manager) writeRedactedConfig(path string) (bool, error) {
	source := filepath.Join(m.ConfigDir, "active.json")
	data, err := os.ReadFile(source)
	if os.IsNotExist(err) {
		return false, writeFile(path, []byte("{}\n"), 0o600)
	}
	if err != nil {
		return false, fmt.Errorf("read active config: %w", err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return false, fmt.Errorf("parse active config: %w", err)
	}
	redact(value)
	redacted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return false, err
	}
	redacted = append(redacted, '\n')
	return true, writeFile(path, redacted, 0o600)
}

// redact performs the operation represented by its name.
func redact(value any) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "privatekey") || strings.Contains(lower, "private_key") || lower == "password" || lower == "token" || lower == "secret" || lower == "master_key" {
				item[key] = "<redacted>"
				continue
			}
			redact(child)
		}
	case []any:
		for _, child := range item {
			redact(child)
		}
	}
}

// hashFiles performs the operation represented by its name.
func hashFiles(root string, names []string) ([]manifestFile, error) {
	result := make([]manifestFile, 0, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		result = append(result, manifestFile{Path: name, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	return result, nil
}

// verifyManifest performs the operation represented by its name.
func verifyManifest(root string, key []byte) error {
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read backup manifest: %w", err)
	}
	var full manifest
	if err := json.Unmarshal(data, &full); err != nil || full.FormatVersion != formatVersion || full.HMACSHA256 == "" {
		return errors.New("invalid backup manifest")
	}
	signature := full.HMACSHA256
	full.HMACSHA256 = ""
	unsigned, err := json.Marshal(full)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(signature), []byte(hmacSHA256(key, unsigned))) {
		return errors.New("backup manifest HMAC verification failed")
	}
	for _, file := range full.Files {
		if !validManifestPath(file.Path) {
			return errors.New("invalid backup manifest path")
		}
		path := filepath.Join(root, file.Path)
		stat, err := os.Lstat(path)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() != file.Size {
			return fmt.Errorf("backup file %s is missing or has wrong size", file.Path)
		}
		actual, err := hashFiles(root, []string{file.Path})
		if err != nil || len(actual) != 1 || actual[0].SHA256 != file.SHA256 {
			return fmt.Errorf("backup file %s hash verification failed", file.Path)
		}
	}
	return nil
}

// validManifestPath performs the operation represented by its name.
func validManifestPath(path string) bool {
	clean := filepath.Clean(path)
	return path != "" && clean == path && clean != "." && !filepath.IsAbs(clean) && clean != ".." && !strings.HasPrefix(clean, ".."+string(os.PathSeparator))
}

// copyTLSDirectory copies the requested value.
func copyTLSDirectory(source, destination string) (bool, error) {
	stat, err := os.Lstat(source)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("Hysteria 2 TLS path must be a directory")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return false, err
	}
	fileCount := 0
	err = filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink in Hysteria TLS directory: %s", entry.Name())
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unsupported file in Hysteria TLS directory: %s", entry.Name())
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if strings.Contains(strings.ToLower(entry.Name()), "privkey") {
			mode = 0o400
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			_ = input.Close()
			return err
		}
		if err := copyAndCloseTLSFile(input, output); err != nil {
			return err
		}
		fileCount++
		return nil
	})
	if err != nil {
		return false, err
	}
	return fileCount > 0, nil
}

// copyAndCloseTLSFile copies certificate bytes and reports copy or close failures in order.
func copyAndCloseTLSFile(input io.ReadCloser, output io.WriteCloser) error {
	_, copyErr := io.Copy(output, input)
	inputErr := input.Close()
	outputErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if inputErr != nil {
		return inputErr
	}
	return outputErr
}

// listRelativeFiles performs the operation represented by its name.
func listRelativeFiles(root, directory string) ([]string, error) {
	result := []string{}
	err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("backup contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("backup contains a non-regular file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result = append(result, filepath.ToSlash(relative))
		return nil
	})
	return result, err
}

// prune performs the operation represented by its name.
func (m *Manager) prune(preserve map[string]struct{}) error {
	items, err := m.List()
	if err != nil {
		return err
	}
	keep := make(map[string]struct{}, retention)
	for _, item := range items {
		if _, wanted := preserve[item.Name]; wanted {
			keep[item.Name] = struct{}{}
		}
	}
	for _, item := range items {
		if len(keep) >= retention {
			break
		}
		keep[item.Name] = struct{}{}
	}
	for _, item := range items {
		if _, wanted := keep[item.Name]; wanted {
			continue
		}
		if err := os.RemoveAll(item.Path); err != nil {
			return err
		}
	}
	return nil
}

// randomSuffix performs the operation represented by its name.
func randomSuffix() (string, error) {
	raw := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// sanitizeLabel performs the operation represented by its name.
func sanitizeLabel(value string) string {
	value = strings.Trim(value, "-_")
	if value == "" {
		return "manual"
	}
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			builder.WriteRune(char)
		}
	}
	if builder.Len() == 0 {
		return "manual"
	}
	return builder.String()
}

// hmacSHA256 performs the operation represented by its name.
func hmacSHA256(key, data []byte) string {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// writeFile writes the supplied value.
func writeFile(path string, data []byte, mode os.FileMode) error {
	return writeFileWith(path, data, mode, func(dir, pattern string) (backupTempFile, error) {
		return os.CreateTemp(dir, pattern)
	}, os.Remove, os.Rename)
}

// backupTempFile is an internal type used by the package.
type backupTempFile interface {
	// Name defines part of the interface contract.
	Name() string
	// Chmod defines part of the interface contract.
	Chmod(os.FileMode) error
	// Write defines part of the interface contract.
	Write([]byte) (int, error)
	// Sync defines part of the interface contract.
	Sync() error
	// Close defines part of the interface contract.
	Close() error
}

// writeFileWith writes the supplied value.
func writeFileWith(path string, data []byte, mode os.FileMode, createTemp func(string, string) (backupTempFile, error), remove func(string) error, rename func(string, string) error) error {
	tmp, err := createTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return rename(tmpName, path)
}

// syncDir performs the operation represented by its name.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
