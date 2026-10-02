package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// revisionStateVersion is an internal package constant.
	revisionStateVersion = 1
	// maxRevisionMutations is an internal package constant.
	maxRevisionMutations = 64
)

var (
	// ErrStaleRevision indicates that a request targets an older configuration revision.
	ErrStaleRevision = errors.New("stale Xray configuration revision")
	// ErrRevisionConflict indicates that an operation key was reused with different data.
	ErrRevisionConflict = errors.New("Xray revision operation conflict")
	// ErrRevisionIO indicates an error while reading or persisting revision state.
	ErrRevisionIO = errors.New("Xray revision journal I/O failure")
)

// revisionRecord is an internal type used by the package.
type revisionRecord struct {
	// Version stores the value associated with the enclosing object.
	Version int `json:"version"`
	// Revision stores the value associated with the enclosing object.
	Revision int64 `json:"revision"`
	// OperationID stores the value associated with the enclosing object.
	OperationID string `json:"operation_id"`
	// Mutations stores the value associated with the enclosing object.
	Mutations map[string]revisionMutation `json:"mutations"`
}

// revisionMutation is an internal type used by the package.
type revisionMutation struct {
	// Fingerprint stores the value associated with the enclosing object.
	Fingerprint string `json:"fingerprint"`
	// State stores the value associated with the enclosing object.
	State string `json:"state"`
}

// revisionTempFile is an internal type used by the package.
type revisionTempFile interface {
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

// revisionDirectoryHandle is an internal type used by the package.
type revisionDirectoryHandle interface {
	// Sync defines part of the interface contract.
	Sync() error
	// Close defines part of the interface contract.
	Close() error
}

// revisionFileSystem is an internal type used by the package.
type revisionFileSystem interface {
	// ReadFile defines part of the interface contract.
	ReadFile(string) ([]byte, error)
	// MkdirAll defines part of the interface contract.
	MkdirAll(string, os.FileMode) error
	// CreateTemp defines part of the interface contract.
	CreateTemp(string, string) (revisionTempFile, error)
	// Remove defines part of the interface contract.
	Remove(string) error
	// Rename defines part of the interface contract.
	Rename(string, string) error
	// OpenDirectory defines part of the interface contract.
	OpenDirectory(string) (revisionDirectoryHandle, error)
}

// osRevisionFileSystem is an internal type used by the package.
type osRevisionFileSystem struct{}

// ReadFile reads and returns the requested value.
func (osRevisionFileSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// MkdirAll performs the operation represented by its name.
func (osRevisionFileSystem) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

// CreateTemp creates the requested value.
func (osRevisionFileSystem) CreateTemp(directory, pattern string) (revisionTempFile, error) {
	return os.CreateTemp(directory, pattern)
}

// Remove removes the requested value.
func (osRevisionFileSystem) Remove(path string) error { return os.Remove(path) }

// Rename performs the operation represented by its name.
func (osRevisionFileSystem) Rename(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

// OpenDirectory opens the requested resource.
func (osRevisionFileSystem) OpenDirectory(path string) (revisionDirectoryHandle, error) {
	return os.Open(path)
}

// RevisionFence persists operation identity and hashes only. It never stores
// configuration snapshots, credentials, or user emails.
type RevisionFence struct {
	path       string
	latest     revisionRecord
	fileSystem revisionFileSystem
}

// NewRevisionFence loads the persisted fence and makes prior operations
// replayable after restart because Xray has been reconstructed from active.json.
func NewRevisionFence(path string) (*RevisionFence, error) {
	fence := &RevisionFence{path: strings.TrimSpace(path), latest: revisionRecord{Version: revisionStateVersion}, fileSystem: osRevisionFileSystem{}}
	if fence.path == "" {
		return fence, nil
	}
	data, err := fence.fileSystem.ReadFile(fence.path)
	if errors.Is(err, os.ErrNotExist) {
		return fence, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Xray runtime revision state: %w", err)
	}
	if err := json.Unmarshal(data, &fence.latest); err != nil {
		return nil, fmt.Errorf("decode Xray runtime revision state: %w", err)
	}
	if fence.latest.Version != revisionStateVersion || fence.latest.Revision < 0 || (fence.latest.Revision == 0 && (fence.latest.OperationID != "" || len(fence.latest.Mutations) != 0)) || (fence.latest.Revision > 0 && (fence.latest.OperationID == "" || len(fence.latest.Mutations) == 0)) || len(fence.latest.Mutations) > maxRevisionMutations {
		return nil, errors.New("Xray runtime revision state has invalid fields")
	}
	for key, mutation := range fence.latest.Mutations {
		if key == "" || mutation.Fingerprint == "" || (mutation.State != "pending" && mutation.State != "committed") {
			return nil, errors.New("Xray runtime revision state contains an invalid mutation")
		}
		mutation.State = "pending"
		fence.latest.Mutations[key] = mutation
	}
	if fence.latest.Revision > 0 {
		if err := fence.persist(fence.latest); err != nil {
			return nil, fmt.Errorf("prepare Xray runtime revision replay: %w", err)
		}
	}
	return fence, nil
}

// Latest returns the last durable revision.
func (f *RevisionFence) Latest() int64 {
	if f == nil {
		return 0
	}
	return f.latest.Revision
}

// Begin reserves a mutation before touching Xray. The bool is true when the
// same mutation was already committed during this process lifetime.
func (f *RevisionFence) Begin(revision int64, operationID, key, fingerprint string) (bool, error) {
	if f == nil || revision < 1 || strings.TrimSpace(operationID) == "" || strings.TrimSpace(key) == "" || fingerprint == "" {
		return false, errors.New("positive revision, operation ID, mutation key, and fingerprint are required")
	}
	if revision < f.latest.Revision {
		return false, fmt.Errorf("%w: received %d, latest is %d", ErrStaleRevision, revision, f.latest.Revision)
	}
	if revision == f.latest.Revision {
		compensation := operationID == f.latest.OperationID+"-rollback"
		if operationID != f.latest.OperationID && !compensation {
			return false, fmt.Errorf("%w: revision %d belongs to another operation", ErrRevisionConflict, revision)
		}
		if compensation != strings.HasPrefix(key, "rollback:") {
			return false, fmt.Errorf("%w: compensation mutation identity is invalid", ErrRevisionConflict)
		}
		if current, exists := f.latest.Mutations[key]; exists {
			if current.Fingerprint != fingerprint {
				return false, fmt.Errorf("%w: replay payload changed", ErrRevisionConflict)
			}
			return current.State == "committed", nil
		}
		if len(f.latest.Mutations) >= maxRevisionMutations {
			return false, fmt.Errorf("%w: mutation limit exceeded for one revision", ErrRevisionConflict)
		}
		next := f.latest
		if next.Mutations == nil {
			next.Mutations = make(map[string]revisionMutation)
		}
		next.Mutations[key] = revisionMutation{Fingerprint: fingerprint, State: "pending"}
		if err := f.persist(next); err != nil {
			return false, err
		}
		f.latest = next
		return false, nil
	}
	next := revisionRecord{Version: revisionStateVersion, Revision: revision, OperationID: operationID, Mutations: map[string]revisionMutation{key: {Fingerprint: fingerprint, State: "pending"}}}
	if err := f.persist(next); err != nil {
		return false, err
	}
	f.latest = next
	return false, nil
}

// Commit marks a reserved mutation complete. A completed compensation makes
// its original mutation replayable in the same way as the runtime revision fence.
func (f *RevisionFence) Commit(revision int64, operationID, key, fingerprint string) error {
	if f == nil {
		return errors.New("Xray revision fence is unavailable")
	}
	mutation, exists := f.latest.Mutations[key]
	compensation := operationID == f.latest.OperationID+"-rollback"
	if f.latest.Revision != revision || (f.latest.OperationID != operationID && !compensation) || compensation != strings.HasPrefix(key, "rollback:") || !exists || mutation.Fingerprint != fingerprint || mutation.State != "pending" {
		return fmt.Errorf("%w: fence changed before commit", ErrRevisionConflict)
	}
	next := f.latest
	mutation.State = "committed"
	next.Mutations[key] = mutation
	if strings.HasPrefix(key, "rollback:") {
		originalKey := strings.TrimPrefix(key, "rollback:")
		if original, ok := next.Mutations[originalKey]; ok {
			original.State = "pending"
			next.Mutations[originalKey] = original
		}
	}
	if err := f.persist(next); err != nil {
		return err
	}
	f.latest = next
	return nil
}

// persist performs the operation represented by its name.
func (f *RevisionFence) persist(record revisionRecord) error {
	if f.path == "" {
		return nil
	}
	directory := filepath.Dir(f.path)
	if err := f.fileSystem.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("%w: create Xray revision state directory: %v", ErrRevisionIO, err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encode Xray revision state: %v", ErrRevisionIO, err)
	}
	temporary, err := f.fileSystem.CreateTemp(directory, ".runtime-revision-*")
	if err != nil {
		return fmt.Errorf("%w: create Xray revision state temporary file: %v", ErrRevisionIO, err)
	}
	defer f.fileSystem.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: secure Xray revision state: %v", ErrRevisionIO, err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write Xray revision state: %v", ErrRevisionIO, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync Xray revision state: %v", ErrRevisionIO, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close Xray revision state: %v", ErrRevisionIO, err)
	}
	if err := f.fileSystem.Rename(temporary.Name(), f.path); err != nil {
		return fmt.Errorf("%w: replace Xray revision state: %v", ErrRevisionIO, err)
	}
	directoryHandle, err := f.fileSystem.OpenDirectory(directory)
	if err != nil {
		return fmt.Errorf("%w: open Xray revision state directory: %v", ErrRevisionIO, err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("%w: sync Xray revision state directory: %v", ErrRevisionIO, err)
	}
	return nil
}

// payloadFingerprint performs the operation represented by its name.
func payloadFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		var size [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(size[:], uint64(len(part)))
		_, _ = hash.Write(size[:n])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
