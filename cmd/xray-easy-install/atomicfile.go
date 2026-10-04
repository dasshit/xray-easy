package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type installerTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// writePrivateAtomic writes content to a private temporary file and publishes
// it only after the file has been synced and closed successfully.
func writePrivateAtomic(path, pattern string, content []byte, mode os.FileMode, publish func(string, string) error) error {
	return writePrivateAtomicWith(path, pattern, content, mode,
		func(dir, pattern string) (installerTempFile, error) { return os.CreateTemp(dir, pattern) },
		os.Remove, publish)
}

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
