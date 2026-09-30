package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type revisionRecord struct {
	Revision    int64                       `json:"revision"`
	OperationID string                      `json:"operation_id"`
	Mutations   map[string]revisionMutation `json:"mutations"`
}

type revisionMutation struct {
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
}

// revisionFence persists only the last Xray mutation identity and its status.
// It is operational metadata, not a second copy of desired application state.
type revisionFence struct {
	path   string
	latest revisionRecord
	err    error
}

func newRevisionFence(path string) revisionFence {
	fence := revisionFence{path: path}
	if strings.TrimSpace(path) == "" {
		fence.err = errors.New("revision state path is required")
		return fence
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fence
	}
	if err != nil {
		fence.err = fmt.Errorf("read revision state: %w", err)
		return fence
	}
	if err := json.Unmarshal(data, &fence.latest); err != nil {
		fence.err = fmt.Errorf("decode revision state: %w", err)
		return fence
	}
	if fence.latest.Revision < 0 || (fence.latest.Revision == 0 && (fence.latest.OperationID != "" || len(fence.latest.Mutations) != 0)) || (fence.latest.Revision > 0 && (fence.latest.OperationID == "" || len(fence.latest.Mutations) == 0)) {
		fence.err = errors.New("revision state has invalid fields")
	}
	if fence.err != nil {
		return fence
	}
	if fence.latest.Revision > 0 {
		// Xray has just restarted from active.json. Runtime-only inbound changes
		// may not be present in that file, so allow a replay of this revision to
		// reapply them after the service restart.
		for key, mutation := range fence.latest.Mutations {
			if key == "" || mutation.Fingerprint == "" || (mutation.State != "pending" && mutation.State != "committed") {
				fence.err = errors.New("revision state contains an invalid mutation")
				return fence
			}
			mutation.State = "pending"
			fence.latest.Mutations[key] = mutation
		}
		if err := fence.persist(fence.latest); err != nil {
			fence.err = fmt.Errorf("reset revision mutation state after restart: %w", err)
		}
	}
	return fence
}

// begin reserves a revision before a runtime mutation. The same operation may
// resume a pending revision; a committed replay is already complete.
func (f *revisionFence) begin(revision int64, operationID, mutationKey, fingerprint string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if revision < 1 || strings.TrimSpace(operationID) == "" || strings.TrimSpace(mutationKey) == "" || fingerprint == "" {
		return false, errors.New("positive state revision, operation ID, mutation key, and fingerprint are required")
	}
	if revision < f.latest.Revision {
		return false, fmt.Errorf("stale Xray config revision %d; latest is %d", revision, f.latest.Revision)
	}
	if revision == f.latest.Revision {
		compensation := operationID == f.latest.OperationID+"-rollback"
		if operationID != f.latest.OperationID && !compensation {
			return false, fmt.Errorf("Xray config revision %d is already owned by another operation", revision)
		}
		if compensation != strings.HasPrefix(mutationKey, "rollback:") {
			return false, errors.New("Xray compensation mutation identity is invalid")
		}
		if current, exists := f.latest.Mutations[mutationKey]; exists {
			if current.Fingerprint != fingerprint {
				return false, fmt.Errorf("Xray operation %q changed its %s mutation at revision %d", operationID, mutationKey, revision)
			}
			return current.State == "committed", nil
		}
		if f.latest.Mutations == nil {
			f.latest.Mutations = make(map[string]revisionMutation)
		}
		f.latest.Mutations[mutationKey] = revisionMutation{Fingerprint: fingerprint, State: "pending"}
		if err := f.persist(f.latest); err != nil {
			return false, err
		}
		return false, nil
	}
	next := revisionRecord{Revision: revision, OperationID: operationID, Mutations: map[string]revisionMutation{mutationKey: {Fingerprint: fingerprint, State: "pending"}}}
	if err := f.persist(next); err != nil {
		return false, err
	}
	f.latest = next
	return false, nil
}

func (f *revisionFence) commit(revision int64, operationID, mutationKey, fingerprint string) error {
	if f.err != nil {
		return f.err
	}
	mutation, exists := f.latest.Mutations[mutationKey]
	compensation := operationID == f.latest.OperationID+"-rollback"
	if f.latest.Revision != revision || (f.latest.OperationID != operationID && !compensation) || compensation != strings.HasPrefix(mutationKey, "rollback:") || !exists || mutation.Fingerprint != fingerprint || mutation.State != "pending" {
		return errors.New("Xray revision fence changed before commit")
	}
	next := f.latest
	mutation.State = "committed"
	next.Mutations[mutationKey] = mutation
	if strings.HasPrefix(mutationKey, "rollback:") {
		originalKey := strings.TrimPrefix(mutationKey, "rollback:")
		if original, exists := next.Mutations[originalKey]; exists {
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

func (f *revisionFence) persist(record revisionRecord) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return fmt.Errorf("create revision state directory: %w", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode revision state: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(f.path), ".revision-state-*")
	if err != nil {
		return fmt.Errorf("create revision state temporary file: %w", err)
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure revision state file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write revision state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync revision state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close revision state: %w", err)
	}
	if err := os.Rename(temporary.Name(), f.path); err != nil {
		return fmt.Errorf("replace revision state: %w", err)
	}
	directory, err := os.Open(filepath.Dir(f.path))
	if err != nil {
		return fmt.Errorf("open revision state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync revision state directory: %w", err)
	}
	return nil
}
