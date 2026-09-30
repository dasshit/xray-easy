package control

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type tokenFile interface {
	WriteString(string) (int, error)
	Sync() error
	Close() error
}

// LoadOrCreateToken creates a private control API token on first start.
func LoadOrCreateToken(path string) (string, error) {
	return loadOrCreateTokenWith(path, func(value []byte) (int, error) { return io.ReadFull(rand.Reader, value) }, func(path string, flag int, mode os.FileMode) (tokenFile, error) {
		return os.OpenFile(path, flag, mode)
	}, os.Remove)
}

func loadOrCreateTokenWith(path string, readRandom func([]byte) (int, error), openFile func(string, int, os.FileMode) (tokenFile, error), removeFile func(string) error) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(data))
		decoded, decodeErr := base64.StdEncoding.DecodeString(token)
		info, statErr := os.Stat(path)
		if decodeErr != nil || len(decoded) < 32 || statErr != nil || info.Mode().Perm()&0022 != 0 {
			return "", fmt.Errorf("AWG control token must be base64 with at least 32 bytes and no group/world write permission")
		}
		return token, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("read AWG control token: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", fmt.Errorf("create AWG data directory: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := readRandom(raw); err != nil {
		return "", fmt.Errorf("generate AWG control token: %w", err)
	}
	token := base64.StdEncoding.EncodeToString(raw) + "\n"
	file, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return "", fmt.Errorf("create AWG control token: %w", err)
	}
	if _, err := file.WriteString(token); err != nil {
		file.Close()
		removeFile(path)
		return "", fmt.Errorf("write AWG control token: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		removeFile(path)
		return "", fmt.Errorf("sync AWG control token: %w", err)
	}
	if err := file.Close(); err != nil {
		removeFile(path)
		return "", fmt.Errorf("close AWG control token: %w", err)
	}
	return strings.TrimSpace(token), nil
}
