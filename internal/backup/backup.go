package backup

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	formatVersion = 1
	retention     = 10
)

type Manager struct {
	Store     *store.Store
	DataDir   string
	ConfigDir string
	MasterKey []byte
}

type Info struct {
	Name      string
	Path      string
	StatePath string
	CreatedAt time.Time
}

type metadata struct {
	FormatVersion int       `json:"format_version"`
	CreatedAt     time.Time `json:"created_at"`
	ConfigPresent bool      `json:"config_present"`
}

type manifest struct {
	FormatVersion int            `json:"format_version"`
	Files         []manifestFile `json:"files"`
	HMACSHA256    string         `json:"hmac_sha256"`
}

type manifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func NewManager(db *store.Store, dataDir, configDir string, masterKey []byte) *Manager {
	return &Manager{Store: db, DataDir: dataDir, ConfigDir: configDir, MasterKey: masterKey}
}

func (m *Manager) BackupDir() string { return filepath.Join(m.DataDir, "backups") }

func (m *Manager) Create(label string) (Info, error) {
	return m.create(label, nil)
}

func (m *Manager) CreatePreserving(label, preserveName string) (Info, error) {
	return m.create(label, map[string]struct{}{preserveName: {}})
}

func (m *Manager) create(label string, preserve map[string]struct{}) (Info, error) {
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
	createdAt := time.Now().UTC()
	metaBytes, err := json.Marshal(metadata{FormatVersion: formatVersion, CreatedAt: createdAt, ConfigPresent: configPresent})
	if err != nil {
		return Info{}, err
	}
	if err := writeFile(filepath.Join(tmp, "metadata.json"), metaBytes, 0o600); err != nil {
		return Info{}, err
	}
	files, err := hashFiles(tmp, []string{"state.db", "config.redacted.json", "metadata.json"})
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

func (m *Manager) RestoreState(info Info) error {
	if m.Store == nil {
		return errors.New("backup manager is not initialized")
	}
	return m.Store.RestoreFrom(info.StatePath)
}

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
	return Info{Name: name, Path: path, StatePath: filepath.Join(path, "state.db"), CreatedAt: meta.CreatedAt}, nil
}

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
		if filepath.Base(file.Path) != file.Path || file.Path == "" {
			return errors.New("invalid backup manifest path")
		}
		path := filepath.Join(root, file.Path)
		stat, err := os.Stat(path)
		if err != nil || stat.Size() != file.Size {
			return fmt.Errorf("backup file %s is missing or has wrong size", file.Path)
		}
		actual, err := hashFiles(root, []string{file.Path})
		if err != nil || len(actual) != 1 || actual[0].SHA256 != file.SHA256 {
			return fmt.Errorf("backup file %s hash verification failed", file.Path)
		}
	}
	return nil
}

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

func randomSuffix() (string, error) {
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

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

func hmacSHA256(key, data []byte) string {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
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
	return os.Rename(tmpName, path)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
