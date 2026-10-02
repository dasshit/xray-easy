package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xray-easy/internal/domain"
)

// hysteriaConfigurationChanged performs the operation represented by its name.
func hysteriaConfigurationChanged(before, after configuration) bool {
	return before.hysteriaEnabled != after.hysteriaEnabled ||
		before.hysteriaMode != after.hysteriaMode ||
		before.hysteriaCertIP != after.hysteriaCertIP ||
		before.hysteriaServerName != after.hysteriaServerName
}

// validateHysteriaConfiguration validates the supplied value.
func validateHysteriaConfiguration(cfg configuration) error {
	if !cfg.hysteriaEnabled {
		return nil
	}
	switch cfg.hysteriaMode {
	case "legacy":
		return nil // Existing installations keep their old URI until the TUI selects an explicit mode.
	case "self-signed":
		ip, err := netip.ParseAddr(cfg.hysteriaCertIP)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.String() != cfg.hysteriaCertIP {
			return errors.New("self-signed Hysteria 2 TLS requires a public IPv4 certificate address")
		}
		if cfg.hysteriaServerName != "" {
			return errors.New("self-signed Hysteria 2 TLS must use its IPv4 address as SNI")
		}
	case "custom":
		if cfg.hysteriaCertIP != "" {
			return errors.New("custom Hysteria 2 TLS must not set a mkcert IPv4 address")
		}
		if cfg.hysteriaServerName != "" {
			if _, err := domain.NormalizePublicHost(cfg.hysteriaServerName); err != nil {
				return fmt.Errorf("invalid Hysteria 2 TLS server name: %w", err)
			}
		}
	default:
		return errors.New("Hysteria 2 TLS mode must be self-signed or custom")
	}
	return nil
}

// hysteriaEnvironment performs the operation represented by its name.
func hysteriaEnvironment(cfg configuration) string {
	return fmt.Sprintf("XRAY_HYSTERIA2_ENABLED=%t\nXRAY_HYSTERIA2_TLS_MODE=%s\nXRAY_HYSTERIA2_CERT_IP=%s\nXRAY_HYSTERIA2_TLS_SERVER_NAME=%s\n", cfg.hysteriaEnabled, cfg.hysteriaMode, cfg.hysteriaCertIP, cfg.hysteriaServerName)
}

// resolveHysteriaSource performs the operation represented by its name.
func resolveHysteriaSource(root, input, defaultName string) string {
	if input == "" {
		return filepath.Join(root, "secrets", "hysteria", defaultName)
	}
	if strings.HasPrefix(input, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, input[2:])
		}
	}
	if filepath.IsAbs(input) {
		return filepath.Clean(input)
	}
	return filepath.Join(root, input)
}

// updateHysteriaConfiguration performs the operation represented by its name.
func updateHysteriaConfiguration(root string, cfg configuration) error {
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updates := map[string]string{
		"XRAY_HYSTERIA2_ENABLED":         fmt.Sprint(cfg.hysteriaEnabled),
		"XRAY_HYSTERIA2_TLS_MODE":        cfg.hysteriaMode,
		"XRAY_HYSTERIA2_CERT_IP":         cfg.hysteriaCertIP,
		"XRAY_HYSTERIA2_TLS_SERVER_NAME": cfg.hysteriaServerName,
	}
	var lines []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if ok {
			if value, found := updates[key]; found {
				if seen[key] {
					return fmt.Errorf("duplicate %s in .env", key)
				}
				line = key + "=" + value
				seen[key] = true
			}
		}
		lines = append(lines, line)
	}
	for _, key := range []string{"XRAY_HYSTERIA2_ENABLED", "XRAY_HYSTERIA2_TLS_MODE", "XRAY_HYSTERIA2_CERT_IP", "XRAY_HYSTERIA2_TLS_SERVER_NAME"} {
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
		file.Close()
		return err
	}
	if _, err := file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// importHysteriaCertificate performs the operation represented by its name.
func importHysteriaCertificate(root string, cfg configuration) (bool, error) {
	certPath := cfg.hysteriaCertSource
	keyPath := cfg.hysteriaKeySource
	if certPath == "" {
		certPath = resolveHysteriaSource(root, "", "fullchain.pem")
	}
	if keyPath == "" {
		keyPath = resolveHysteriaSource(root, "", "privkey.pem")
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Errorf("read Hysteria 2 certificate: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return false, fmt.Errorf("read Hysteria 2 private key: %w", err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return false, fmt.Errorf("Hysteria 2 certificate and key are invalid or do not match: %w", err)
	}
	parsed, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("parse Hysteria 2 certificate: %w", err)
	}
	if time.Now().Before(parsed.NotBefore) || !time.Now().Before(parsed.NotAfter) {
		return false, errors.New("Hysteria 2 certificate is not currently valid")
	}
	if cfg.hysteriaServerName != "" {
		if err := parsed.VerifyHostname(cfg.hysteriaServerName); err != nil {
			return false, fmt.Errorf("Hysteria 2 certificate does not cover TLS server name: %w", err)
		}
	}
	dir := filepath.Join(root, "secrets", "hysteria")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	existingCert, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	existingKey, _ := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if string(existingCert) == string(cert) && string(existingKey) == string(key) {
		return false, nil
	}
	if err := writeImportedFile(filepath.Join(dir, "fullchain.pem"), cert, 0o644); err != nil {
		return false, err
	}
	if err := writeImportedFile(filepath.Join(dir, "privkey.pem"), key, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// writeImportedFile writes the supplied value.
func writeImportedFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".hysteria-import-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
