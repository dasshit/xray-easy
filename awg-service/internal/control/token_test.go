package control

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingTokenFile struct {
	*os.File
	writeErr error
	syncErr  error
	closeErr error
}

func (f *failingTokenFile) WriteString(value string) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.WriteString(value)
}

func (f *failingTokenFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *failingTokenFile) Close() error {
	err := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return err
}

func TestLoadOrCreateTokenCreatesPrivateTokenAndValidatesExistingToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "control.token")
	created, err := LoadOrCreateToken(path)
	if err != nil || len(mustDecodeToken(t, created)) != 32 {
		t.Fatalf("LoadOrCreateToken() = token length %d, %v", len(created), err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("created token mode = %v, %v", info, err)
	}
	loaded, err := LoadOrCreateToken(path)
	if err != nil || loaded != created {
		t.Fatalf("existing token = %q, %v; want %q", loaded, err, created)
	}

	for _, test := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{name: "not base64", data: []byte("not-a-token"), mode: 0o600},
		{name: "too short", data: []byte(base64.StdEncoding.EncodeToString([]byte("short"))), mode: 0o600},
		{name: "group writable", data: []byte(created), mode: 0o660},
		{name: "world writable", data: []byte(created), mode: 0o606},
	} {
		t.Run(test.name, func(t *testing.T) {
			badPath := filepath.Join(t.TempDir(), "control.token")
			if err := os.WriteFile(badPath, test.data, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(badPath, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreateToken(badPath); err == nil || !strings.Contains(err.Error(), "no group/world write permission") {
				t.Fatalf("unsafe token accepted: %v", err)
			}
		})
	}
}

func TestLoadOrCreateTokenReportsReadErrorsWhenTokenPathIsUnavailable(t *testing.T) {
	directory := t.TempDir()
	if _, err := LoadOrCreateToken(directory); err == nil || !strings.Contains(err.Error(), "read AWG control token") {
		t.Fatalf("directory token path error = %v", err)
	}
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(filepath.Join(parentFile, "control.token")); err == nil || !strings.Contains(err.Error(), "read AWG control token") {
		t.Fatalf("unreadable token parent error = %v", err)
	}
}

func TestLoadOrCreateTokenPropagatesCreationFailuresAndCleansUp(t *testing.T) {
	for _, test := range []struct {
		name string
		fail string
	}{
		{name: "random source", fail: "random"},
		{name: "open file", fail: "open"},
		{name: "write file", fail: "write"},
		{name: "sync file", fail: "sync"},
		{name: "close file", fail: "close"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			wantErr := errors.New("injected " + test.fail + " failure")
			readRandom := func(buffer []byte) (int, error) {
				if test.fail == "random" {
					return 0, wantErr
				}
				for i := range buffer {
					buffer[i] = byte(i + 1)
				}
				return len(buffer), nil
			}
			openFile := func(path string, flag int, mode os.FileMode) (tokenFile, error) {
				if test.fail == "open" {
					return nil, wantErr
				}
				file, err := os.OpenFile(path, flag, mode)
				if err != nil {
					return nil, err
				}
				failing := &failingTokenFile{File: file}
				switch test.fail {
				case "write":
					failing.writeErr = wantErr
				case "sync":
					failing.syncErr = wantErr
				case "close":
					failing.closeErr = wantErr
				}
				return failing, nil
			}
			token, err := loadOrCreateTokenWith(path, readRandom, openFile, os.Remove)
			if err == nil || !strings.Contains(err.Error(), "injected "+test.fail+" failure") {
				t.Fatalf("loadOrCreateTokenWith() = %q, %v; want injected %s error", token, err, test.fail)
			}
			if test.fail == "random" || test.fail == "open" {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("token file unexpectedly exists after %s failure: %v", test.fail, statErr)
				}
				return
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("partial token file was not removed after %s failure: %v", test.fail, statErr)
			}
		})
	}
}

func mustDecodeToken(t *testing.T, token string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
