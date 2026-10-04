package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrojanConfigurationRoundTrip(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{project: defaultProject, version: defaultVersion, public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.trojan != 10443 || loaded.trojanEnabled {
		t.Fatalf("default Trojan settings = %+v", loaded)
	}
	loaded.trojanEnabled = true
	loaded.trojan = 11445
	if err := updateTrojanConfiguration(root, loaded); err != nil {
		t.Fatal(err)
	}
	updated, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.trojanEnabled || updated.trojan != 11445 {
		t.Fatalf("updated Trojan settings = %+v", updated)
	}
}

func TestTrojanTUISelection(t *testing.T) {
	var output bytes.Buffer
	w := newWizard(strings.NewReader("\x1b[B\n\n"), &output)
	defer w.close()
	w.step(2, "Configuration")
	cfg, err := w.trojan(context.Background(), configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080})
	if err != nil || !cfg.trojanEnabled || cfg.trojan != 10443 {
		t.Fatalf("Trojan selection: cfg=%+v err=%v", cfg, err)
	}
	if !strings.Contains(output.String(), "Trojan") || !strings.Contains(output.String(), "10443") {
		t.Fatal("Trojan settings were not visible in the installer")
	}
}

func TestTrojanTUIAllowsCustomPort(t *testing.T) {
	var output bytes.Buffer
	w := newWizard(strings.NewReader("\x1b[B\n\x7f\x7f\x7f\x7f\x7f10445\n"), &output)
	defer w.close()
	w.step(2, "Configuration")
	cfg, err := w.trojan(context.Background(), configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 10443})
	if err != nil || !cfg.trojanEnabled || cfg.trojan != 10445 {
		t.Fatalf("custom Trojan port: cfg=%+v err=%v", cfg, err)
	}
}

func TestTrojanTUIRejectsConflictingPortAndAcceptsReplacement(t *testing.T) {
	var output bytes.Buffer
	// Select Trojan, replace the current value with VMess's port (9443), then
	// replace it again with a distinct valid port after the conflict warning.
	w := newWizard(strings.NewReader("\x1b[B\n\x7f\x7f\x7f\x7f\x7f9443\n\x7f\x7f\x7f\x7f10445\n"), &output)
	defer w.close()
	w.step(2, "Configuration")
	cfg, err := w.trojan(context.Background(), configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 10443})
	if err != nil || !cfg.trojanEnabled || cfg.trojan != 10445 {
		t.Fatalf("Trojan port after conflict: cfg=%+v err=%v", cfg, err)
	}
	if !strings.Contains(output.String(), "must differ") {
		t.Fatal("installer did not explain the port conflict")
	}
}

func TestTrojanTUIChoicesDefaultsAndInputErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input       string
		before      configuration
		wantEnabled bool
		wantPort    int
		wantNotice  string
	}{
		{name: "disabled", input: "\n", before: configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080}, wantPort: 10443},
		{name: "already enabled with default port", input: "\n\n", before: configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojanEnabled: true}, wantEnabled: true, wantPort: 10443},
		{name: "numeric enable and default port", input: "2\n\n", before: configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080}, wantEnabled: true, wantPort: 10443},
		{name: "empty custom port uses default", input: "\x1b[B\n" + strings.Repeat("\x7f", 5) + "\n", before: configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080}, wantEnabled: true, wantPort: 10443},
		{name: "invalid port can be corrected", input: "\x1b[B\n" + strings.Repeat("\x7f", 5) + "0\n\x7f10445\n", before: configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 10443}, wantEnabled: true, wantPort: 10445, wantNotice: "Enter a TCP port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			w := newWizard(strings.NewReader(tc.input), &output)
			defer w.close()
			got, err := w.trojan(context.Background(), tc.before)
			if err != nil || got.trojanEnabled != tc.wantEnabled || got.trojan != tc.wantPort {
				t.Fatalf("Trojan selection = %+v, %v; want enabled=%t port=%d", got, err, tc.wantEnabled, tc.wantPort)
			}
			if tc.wantNotice != "" && !strings.Contains(output.String(), tc.wantNotice) {
				t.Fatalf("missing notice %q in %q", tc.wantNotice, output.String())
			}
		})
	}
	t.Run("small terminal can only be cancelled", func(t *testing.T) {
		var output bytes.Buffer
		w := newWizard(strings.NewReader("x\x1b"), &output)
		defer w.close()
		w.width, w.height = 50, 18
		if _, err := w.trojan(context.Background(), configuration{}); !errors.Is(err, errCancelled) {
			t.Fatalf("small-terminal flow error = %v", err)
		}
		if !strings.Contains(output.String(), "Enlarge the terminal before continuing") {
			t.Fatal("small-terminal guidance missing")
		}
	})
	t.Run("closed input is reported", func(t *testing.T) {
		w := newWizard(strings.NewReader(""), &bytes.Buffer{})
		defer w.close()
		if _, err := w.trojan(context.Background(), configuration{}); err == nil || !strings.Contains(err.Error(), "input ended") {
			t.Fatalf("closed input error = %v", err)
		}
	})
}

func TestValidateTrojanConfiguration(t *testing.T) {
	base := configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 10443}
	if err := validateTrojanConfiguration(base); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []configuration{
		{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 443},
		{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 0xffff + 1},
	} {
		if err := validateTrojanConfiguration(invalid); err == nil {
			t.Fatalf("invalid settings accepted: %+v", invalid)
		}
	}
}

func TestUpdateTrojanConfigurationRejectsMissingAndDuplicateEnvironment(t *testing.T) {
	root := t.TempDir()
	if err := updateTrojanConfiguration(root, configuration{}); err == nil {
		t.Fatal("missing .env was accepted")
	}
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_TROJAN_PORT=10443\nXRAY_TROJAN_PORT=10444\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateTrojanConfiguration(root, configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojan: 10445}); err == nil || !strings.Contains(err.Error(), "duplicate XRAY_TROJAN_PORT") {
		t.Fatalf("duplicate Trojan setting error = %v", err)
	}
}

func TestUpdateTrojanConfigurationFillsMissingKeysAndDefaultsPort(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("# existing setting\nOTHER=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateTrojanConfiguration(root, configuration{public: 443, vmess: 9443, shadowsocks: 8388, ui: 8080, trojanEnabled: true}); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_TROJAN_PORT"] != "10443" || values["XRAY_TROJAN_ENABLED"] != "true" || values["OTHER"] != "value" {
		t.Fatalf("updated Trojan values = %#v", values)
	}
}

func TestUpdateTrojanConfigurationRejectsDuplicateEnabledKey(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_TROJAN_ENABLED=false\nXRAY_TROJAN_ENABLED=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateTrojanConfiguration(root, configuration{}); err == nil || !strings.Contains(err.Error(), "duplicate XRAY_TROJAN_ENABLED") {
		t.Fatalf("duplicate enabled key error = %v", err)
	}
}
