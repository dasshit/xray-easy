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
	// defaultShadowsocksMethod is an internal package constant.
	defaultShadowsocksMethod = domain.ShadowsocksMethod2022AES256GCM
	// defaultShadowsocksNetwork is an internal package constant.
	defaultShadowsocksNetwork = domain.ShadowsocksNetworkTCPUDP
)

// shadowsocksConfigurationChanged performs the operation represented by its name.
func shadowsocksConfigurationChanged(before, after configuration) bool {
	return before.shadowsocks != after.shadowsocks ||
		before.shadowsocksEnabled != after.shadowsocksEnabled ||
		before.shadowsocksMethod != after.shadowsocksMethod ||
		before.shadowsocksNetwork != after.shadowsocksNetwork
}

// updateShadowsocksConfiguration performs the operation represented by its name.
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
		"XRAY_SHADOWSOCKS_METHOD":  defaultShadowsocksMethod,
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
	return writePrivateAtomic(path, ".env-*", []byte(strings.Join(lines, "\n")+"\n"), 0o600, os.Rename)
}
