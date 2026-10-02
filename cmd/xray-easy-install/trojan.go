package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func trojanConfigurationChanged(before, after configuration) bool {
	return before.trojan != after.trojan || before.trojanEnabled != after.trojanEnabled
}

func updateTrojanConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	port := cfg.trojan
	if port == 0 {
		port = defaultTrojanPort(cfg.public, cfg.vmess, cfg.shadowsocks, cfg.ui)
	}
	updates := map[string]string{"XRAY_TROJAN_PORT": strconv.Itoa(port), "XRAY_TROJAN_ENABLED": strconv.FormatBool(cfg.trojanEnabled)}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	seen := map[string]bool{}
	for index, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if value, found := updates[strings.TrimSpace(key)]; found {
			key = strings.TrimSpace(key)
			if seen[key] {
				return fmt.Errorf("duplicate %s in .env", key)
			}
			lines[index] = key + "=" + value
			seen[key] = true
		}
	}
	for _, key := range []string{"XRAY_TROJAN_PORT", "XRAY_TROJAN_ENABLED"} {
		if !seen[key] {
			lines = append(lines, key+"="+updates[key])
		}
	}
	tmp, err := os.CreateTemp(root, ".env-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
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
	return os.Rename(tmp.Name(), path)
}
