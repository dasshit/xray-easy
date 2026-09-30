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

// LoadOrCreateToken creates a private control API token on first start.
func LoadOrCreateToken(path string) (string, error) {
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
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate AWG control token: %w", err)
	}
	token := base64.StdEncoding.EncodeToString(raw) + "\n"
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return "", fmt.Errorf("create AWG control token: %w", err)
	}
	if _, err := file.WriteString(token); err != nil {
		file.Close()
		os.Remove(path)
		return "", fmt.Errorf("write AWG control token: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return "", fmt.Errorf("sync AWG control token: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("close AWG control token: %w", err)
	}
	return strings.TrimSpace(token), nil
}
