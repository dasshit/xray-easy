package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShadowsocksConfigurationRoundTrip(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{project: defaultProject, version: defaultVersion, public: 443, vmess: 9443, ui: 8080}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.shadowsocks != 8388 || loaded.shadowsocksMethod != defaultShadowsocksMethod || loaded.shadowsocksNetwork != defaultShadowsocksNetwork {
		t.Fatalf("default Shadowsocks settings = %+v", loaded)
	}
	loaded.shadowsocksEnabled = true
	loaded.shadowsocksMethod = defaultShadowsocksMethod
	loaded.shadowsocksNetwork = defaultShadowsocksNetwork
	if err := updateShadowsocksConfiguration(root, loaded); err != nil {
		t.Fatal(err)
	}
	updated, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.shadowsocksEnabled || updated.shadowsocks != 8388 {
		t.Fatalf("updated Shadowsocks settings = %+v", updated)
	}
}

func TestShadowsocksTUISelection(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		var output bytes.Buffer
		w := newWizard(strings.NewReader("\n"), &output)
		defer w.close()
		w.step(2, "Configuration")
		cfg, err := w.shadowsocks(context.Background(), configuration{public: 443, vmess: 9443, ui: 8080})
		if err != nil || cfg.shadowsocksEnabled || cfg.shadowsocks != 8388 {
			t.Fatalf("off selection: cfg=%+v err=%v", cfg, err)
		}
	})
	t.Run("on", func(t *testing.T) {
		var output bytes.Buffer
		w := newWizard(strings.NewReader("\x1b[B\n"), &output)
		defer w.close()
		w.step(2, "Configuration")
		cfg, err := w.shadowsocks(context.Background(), configuration{public: 443, vmess: 9443, ui: 8080})
		if err != nil || !cfg.shadowsocksEnabled {
			t.Fatalf("on selection: cfg=%+v err=%v", cfg, err)
		}
		if !strings.Contains(output.String(), "Shadowsocks") || !strings.Contains(output.String(), "8388") {
			t.Fatal("Shadowsocks settings were not visible in the installer")
		}
	})
}

func TestValidateShadowsocksConfiguration(t *testing.T) {
	base := configuration{public: 443, vmess: 9443, ui: 8080, shadowsocks: 8388}
	if err := validateShadowsocksConfiguration(base); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []configuration{
		{public: 443, vmess: 9443, ui: 8080, shadowsocks: 443},
		{public: 443, vmess: 9443, ui: 8080, shadowsocks: 8388, shadowsocksMethod: "2022-blake3-aes-128-gcm"},
		{public: 443, vmess: 9443, ui: 8080, shadowsocks: 8388, shadowsocksNetwork: "quic"},
	} {
		if err := validateShadowsocksConfiguration(invalid); err == nil {
			t.Fatalf("invalid settings accepted: %+v", invalid)
		}
	}
}

func TestUpdateShadowsocksConfigurationRejectsMissingAndDuplicateEnvironment(t *testing.T) {
	root := t.TempDir()
	if err := updateShadowsocksConfiguration(root, configuration{}); err == nil {
		t.Fatal("missing .env was accepted")
	}
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_SHADOWSOCKS_PORT=8388\nXRAY_SHADOWSOCKS_PORT=8389\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateShadowsocksConfiguration(root, configuration{shadowsocks: 8390}); err == nil || !strings.Contains(err.Error(), "duplicate XRAY_SHADOWSOCKS_PORT") {
		t.Fatalf("duplicate Shadowsocks setting error = %v", err)
	}
}
