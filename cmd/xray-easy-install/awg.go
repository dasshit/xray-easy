package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xray-easy/internal/domain"
)

const defaultAWGPort = 51820

func awgConfigurationChanged(before, after configuration) bool {
	return before.awgEnabled != after.awgEnabled ||
		before.awgPublicHost != after.awgPublicHost ||
		before.awgPublicPort != after.awgPublicPort
}

func validateAWGConfiguration(cfg configuration) error {
	port := cfg.awgPublicPort
	if port == 0 {
		port = defaultAWGPort
	}
	if port < 1 || port > 65535 {
		return errors.New("AWG_PUBLIC_PORT must be between 1 and 65535")
	}
	if cfg.awgEnabled && port == cfg.public {
		return errors.New("AWG_PUBLIC_PORT must differ from XRAY_PUBLIC_PORT because both publish UDP")
	}
	if cfg.awgEnabled {
		if _, err := domain.NormalizePublicHost(cfg.awgPublicHost); err != nil {
			return fmt.Errorf("AWG_PUBLIC_HOST: %w", err)
		}
	}
	return nil
}

func updateAWGConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	profile, publicHost := "", ""
	if cfg.awgEnabled {
		profile, publicHost = "awg", cfg.awgPublicHost
	}
	port := cfg.awgPublicPort
	if port == 0 {
		port = defaultAWGPort
	}
	updates := map[string]string{
		"COMPOSE_PROFILES": profile,
		"AWG_PUBLIC_HOST":  publicHost,
		"AWG_PUBLIC_PORT":  strconv.Itoa(port),
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
	for _, key := range []string{"COMPOSE_PROFILES", "AWG_PUBLIC_HOST", "AWG_PUBLIC_PORT"} {
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
