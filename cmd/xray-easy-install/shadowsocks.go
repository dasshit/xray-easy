package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xray-easy/internal/domain"
)

const (
	defaultShadowsocksMethod  = domain.ShadowsocksMethodChaCha20Poly1305
	defaultShadowsocksNetwork = domain.ShadowsocksNetworkTCPUDP
)

func shadowsocksConfigurationChanged(before, after configuration) bool {
	return before.shadowsocks != after.shadowsocks ||
		before.shadowsocksEnabled != after.shadowsocksEnabled ||
		before.shadowsocksMethod != after.shadowsocksMethod ||
		before.shadowsocksNetwork != after.shadowsocksNetwork
}

func updateShadowsocksConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	port := cfg.shadowsocks
	if port == 0 {
		port = defaultShadowsocksPort(cfg.public, cfg.vmess, cfg.ui)
	}
	updates := map[string]string{
		"XRAY_SHADOWSOCKS_PORT":    strconv.Itoa(port),
		"XRAY_SHADOWSOCKS_ENABLED": strconv.FormatBool(cfg.shadowsocksEnabled),
		"XRAY_SHADOWSOCKS_METHOD":  valueOr(cfg.shadowsocksMethod, defaultShadowsocksMethod),
		"XRAY_SHADOWSOCKS_NETWORK": valueOr(cfg.shadowsocksNetwork, defaultShadowsocksNetwork),
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	seen := make(map[string]bool, len(updates))
	for index, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if !ok {
			continue
		}
		if value, found := updates[key]; found {
			if seen[key] {
				return fmt.Errorf("duplicate %s in .env", key)
			}
			lines[index] = key + "=" + value
			seen[key] = true
		}
	}
	for _, key := range []string{"XRAY_SHADOWSOCKS_PORT", "XRAY_SHADOWSOCKS_ENABLED", "XRAY_SHADOWSOCKS_METHOD", "XRAY_SHADOWSOCKS_NETWORK"} {
		if !seen[key] {
			lines = append(lines, key+"="+updates[key])
		}
	}
	file, err := os.CreateTemp(root, ".env-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
