package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type installerFileStub struct {
	*os.File
	failure string
}

func (f *installerFileStub) Chmod(mode os.FileMode) error {
	if f.failure == "chmod" {
		return errors.New("injected chmod failure")
	}
	return f.File.Chmod(mode)
}

func (f *installerFileStub) Write(data []byte) (int, error) {
	switch f.failure {
	case "write":
		return 0, errors.New("injected write failure")
	case "short-write":
		return len(data) - 1, nil
	}
	return f.File.Write(data)
}

func (f *installerFileStub) Sync() error {
	if f.failure == "sync" {
		return errors.New("injected sync failure")
	}
	return f.File.Sync()
}

func (f *installerFileStub) Close() error {
	actualErr := f.File.Close()
	if f.failure == "close" {
		return errors.New("injected close failure")
	}
	return actualErr
}

func TestWritePrivateAtomicPropagatesFailuresAndCleansTemporaryFiles(t *testing.T) {
	for _, failure := range []string{"create", "chmod", "write", "short-write", "sync", "close", "publish", "missing-publisher"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "target")
			var temporary string
			createTemp := func(dir, pattern string) (installerTempFile, error) {
				if failure == "create" {
					return nil, errors.New("injected create failure")
				}
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				temporary = file.Name()
				return &installerFileStub{File: file, failure: failure}, nil
			}
			publish := func(source, destination string) error {
				if failure == "publish" {
					return errors.New("injected publish failure")
				}
				return os.Rename(source, destination)
			}
			if failure == "missing-publisher" {
				publish = nil
			}
			err := writePrivateAtomicWith(path, ".tmp-*", []byte("private data"), 0o600, createTemp, os.Remove, publish)
			if err == nil {
				t.Fatal("writePrivateAtomicWith accepted injected failure")
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("failed write published target: stat error = %v", statErr)
			}
			if temporary != "" {
				if _, statErr := os.Stat(temporary); !os.IsNotExist(statErr) {
					t.Fatalf("failed write left temporary file: stat error = %v", statErr)
				}
			}
		})
	}
}

func TestWritePrivateAtomicPublishesSyncedPrivateFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "target")
	if err := writePrivateAtomic(path, ".tmp-*", []byte("private data"), 0o600, os.Rename); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private data" {
		t.Fatalf("published content = %q, %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("published file mode = %v, %v", info, err)
	}
}

func TestWritePrivateAtomicShortWriterReturnsIOErrShortWrite(t *testing.T) {
	root := t.TempDir()
	err := writePrivateAtomicWith(filepath.Join(root, "target"), ".tmp-*", []byte("x"), 0o600,
		func(dir, pattern string) (installerTempFile, error) {
			file, createErr := os.CreateTemp(dir, pattern)
			if createErr != nil {
				return nil, createErr
			}
			return &installerFileStub{File: file, failure: "short-write"}, nil
		}, os.Remove, os.Rename)
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short writer error = %v, want io.ErrShortWrite", err)
	}
}
