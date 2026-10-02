// Package diagnostics provides the diagnostics functionality used by Xray-easy.
package diagnostics

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CreateBundle writes a private gzip tar archive containing the supplied
// already-redacted report files and returns its absolute path.
func CreateBundle(dataDir string, files map[string][]byte, now time.Time) (string, error) {
	return createBundleWith(dataDir, files, now, func(dir, pattern string) (bundleFile, error) {
		return os.CreateTemp(dir, pattern)
	}, os.Remove, os.Rename)
}

// bundleFile is an internal type used by the package.
type bundleFile interface {
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

// createBundleWith creates the requested value.
func createBundleWith(dataDir string, files map[string][]byte, now time.Time, createTemp func(string, string) (bundleFile, error), remove func(string) error, rename func(string, string) error) (string, error) {
	if len(files) == 0 {
		return "", errors.New("doctor bundle is empty")
	}
	directory, err := filepath.Abs(filepath.Join(dataDir, "diagnostics"))
	if err != nil {
		return "", fmt.Errorf("resolve diagnostics directory: %w", err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create diagnostics directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("secure diagnostics directory: %w", err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	name := "doctor-" + now.Format("20060102T150405.000000000Z") + ".tar.gz"
	temporary, err := createTemp(directory, ".doctor-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create doctor bundle: %w", err)
	}
	temporaryPath := temporary.Name()
	defer remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("secure doctor bundle: %w", err)
	}
	zipper := gzip.NewWriter(temporary)
	archive := tar.NewWriter(zipper)
	for fileName, contents := range files {
		if !safeArchiveName(fileName) {
			_ = archive.Close()
			_ = zipper.Close()
			_ = temporary.Close()
			return "", fmt.Errorf("invalid doctor bundle file name %q", fileName)
		}
		header := &tar.Header{Name: fileName, Mode: 0o600, Size: int64(len(contents)), ModTime: now, Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			_ = archive.Close()
			_ = zipper.Close()
			_ = temporary.Close()
			return "", fmt.Errorf("write doctor bundle header: %w", err)
		}
		if _, err := archive.Write(contents); err != nil {
			_ = archive.Close()
			_ = zipper.Close()
			_ = temporary.Close()
			return "", fmt.Errorf("write doctor bundle file: %w", err)
		}
	}
	if err := archive.Close(); err != nil {
		_ = zipper.Close()
		_ = temporary.Close()
		return "", fmt.Errorf("finish doctor bundle archive: %w", err)
	}
	if err := zipper.Close(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("compress doctor bundle: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("sync doctor bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close doctor bundle: %w", err)
	}
	path := filepath.Join(directory, name)
	if err := rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("publish doctor bundle: %w", err)
	}
	return path, nil
}

// safeArchiveName performs the operation represented by its name.
func safeArchiveName(name string) bool {
	if name == "" || strings.Contains(name, "\\") || filepath.IsAbs(name) {
		return false
	}
	clean := filepath.Clean(name)
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}
