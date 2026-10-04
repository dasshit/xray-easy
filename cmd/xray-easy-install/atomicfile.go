package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// installerTempFile is the minimal temporary-file API used by atomic installer writes.
type installerTempFile interface {
	// Name returns the path that must be removed or published after writing.
	Name() string
	// Chmod secures the staged file before it is populated.
	Chmod(os.FileMode) error
	// Write appends bytes to the staged file.
	Write([]byte) (int, error)
	// Sync flushes staged bytes to storage before publication.
	Sync() error
	// Close releases the staged file descriptor.
	Close() error
}

// writePrivateAtomic writes content to a private temporary file and publishes
// it only after the file has been synced and closed successfully.
func writePrivateAtomic(path, pattern string, content []byte, mode os.FileMode, publish func(string, string) error) error {
	return writePrivateAtomicWith(path, pattern, content, mode,
		func(dir, pattern string) (installerTempFile, error) { return os.CreateTemp(dir, pattern) },
		os.Remove, publish)
}

// writePrivateAtomicWith creates and secures a temporary file before syncing and publishing it.
func writePrivateAtomicWith(path, pattern string, content []byte, mode os.FileMode,
	createTemp func(string, string) (installerTempFile, error), remove func(string) error,
	publish func(string, string) error,
) error {
	tmp, err := createTemp(filepath.Dir(path), pattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	written, err := tmp.Write(content)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if written != len(content) {
		_ = tmp.Close()
		return io.ErrShortWrite
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if publish == nil {
		return errors.New("atomic file publisher is required")
	}
	return publish(tmpName, path)
}
