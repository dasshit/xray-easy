package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"xray-easy/internal/domain"
)

// defaultAWGPort is an internal package constant.
const defaultAWGPort = 1234

// awgConfigurationChanged performs the operation represented by its name.
func awgConfigurationChanged(before, after configuration) bool {
	return before.awgEnabled != after.awgEnabled ||
		before.awgPublicHost != after.awgPublicHost ||
		before.awgPublicPort != after.awgPublicPort
}

// validateAWGConfiguration validates the supplied value.
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

// updateAWGConfiguration performs the operation represented by its name.
func updateAWGConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	profile := managedComposeProfiles(environmentValue(data, "COMPOSE_PROFILES"), cfg)
	publicHost := ""
	if cfg.awgEnabled {
		publicHost = cfg.awgPublicHost
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
	return updateEnvironmentFile(root, data, updates)
}

// updateLeaseConfiguration enables the optional lease profile without dropping
// AmneziaWG or unrelated Compose profiles.
func updateLeaseConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updates := map[string]string{
		"COMPOSE_PROFILES":           managedComposeProfiles(environmentValue(data, "COMPOSE_PROFILES"), cfg),
		"XRAY_LEASE_SERVICE_ENABLED": strconv.FormatBool(cfg.leaseEnabled),
		"XRAY_LEASE_MAX_ACTIVE":      valueOr(environmentValue(data, "XRAY_LEASE_MAX_ACTIVE"), "2"),
		"XRAY_LEASE_GRACE":           valueOr(environmentValue(data, "XRAY_LEASE_GRACE"), "30s"),
		"XRAY_LEASE_RETRY_DELAY":     valueOr(environmentValue(data, "XRAY_LEASE_RETRY_DELAY"), "1s"),
	}
	return updateEnvironmentFile(root, data, updates)
}

// managedComposeProfiles preserves unrelated profiles and applies managed toggles.
func managedComposeProfiles(existing string, cfg configuration) string {
	profiles := make([]string, 0, 4)
	seen := make(map[string]bool)
	for _, profile := range strings.Split(existing, ",") {
		profile = strings.TrimSpace(profile)
		switch profile {
		case "", "awg", "awg-prototype", "lease":
			continue
		}
		if !seen[profile] {
			profiles = append(profiles, profile)
			seen[profile] = true
		}
	}
	if cfg.awgEnabled {
		profiles = append(profiles, "awg")
	}
	if cfg.leaseEnabled {
		profiles = append(profiles, "lease")
	}
	return strings.Join(profiles, ",")
}

// environmentValue returns the first plain KEY=value entry from an env file.
func environmentValue(data []byte, key string) string {
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// updateEnvironmentFile atomically updates selected values while preserving other entries.
func updateEnvironmentFile(root string, data []byte, updates map[string]string) error {
	path := filepath.Join(root, ".env")
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
	var missing []string
	for key := range updates {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		lines = append(lines, key+"="+updates[key])
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
