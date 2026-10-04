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

func TestLegacyShadowsocksMethodIsReplacedWithoutChangingMasterKeyOrPorts(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{project: defaultProject, version: defaultVersion, public: 443, vmess: 9443, ui: 8080, shadowsocks: 8388}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".env")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(contents), "XRAY_SHADOWSOCKS_METHOD="+defaultShadowsocksMethod, "XRAY_SHADOWSOCKS_METHOD=chacha20-poly1305", 1)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.shadowsocksMethod != defaultShadowsocksMethod {
		t.Fatalf("legacy method was not normalized in memory: %q", loaded.shadowsocksMethod)
	}
	if err := updateShadowsocksConfiguration(root, loaded); err != nil {
		t.Fatal(err)
	}
	after, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if after["XRAY_SHADOWSOCKS_METHOD"] != defaultShadowsocksMethod || after["XRAY_EASY_MASTER_KEY"] != before["XRAY_EASY_MASTER_KEY"] || after["XRAY_PUBLIC_PORT"] != "443" || after["XRAY_SHADOWSOCKS_PORT"] != "8388" {
		t.Fatalf("legacy config migration changed or missed settings: before=%#v after=%#v", before, after)
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
	t.Run("preselected enabled", func(t *testing.T) {
		var output bytes.Buffer
		w := newWizard(strings.NewReader("\n"), &output)
		defer w.close()
		cfg, err := w.shadowsocks(context.Background(), configuration{shadowsocksEnabled: true, public: 443, vmess: 9443, ui: 8080})
		if err != nil || !cfg.shadowsocksEnabled {
			t.Fatalf("preselected setting: cfg=%+v err=%v", cfg, err)
		}
	})
	t.Run("numeric choice", func(t *testing.T) {
		for _, tc := range []struct {
			input string
			want  bool
		}{{"1\n", false}, {"2\n", true}} {
			w := newWizard(strings.NewReader(tc.input), &bytes.Buffer{})
			cfg, err := w.shadowsocks(context.Background(), configuration{public: 443, vmess: 9443, ui: 8080})
			w.close()
			if err != nil || cfg.shadowsocksEnabled != tc.want {
				t.Fatalf("choice %q: enabled=%t err=%v want=%t", tc.input, cfg.shadowsocksEnabled, err, tc.want)
			}
		}
	})
	t.Run("small terminal blocks changes until cancel", func(t *testing.T) {
		var output bytes.Buffer
		w := newWizard(strings.NewReader("x\x1b"), &output)
		defer w.close()
		w.width, w.height = 50, 18
		if _, err := w.shadowsocks(context.Background(), configuration{}); !errors.Is(err, errCancelled) {
			t.Fatalf("small-terminal flow error = %v", err)
		}
		if !strings.Contains(output.String(), "Enlarge the terminal before continuing") {
			t.Fatal("small-terminal guidance was not displayed")
		}
	})
	t.Run("input error propagates", func(t *testing.T) {
		w := newWizard(strings.NewReader(""), &bytes.Buffer{})
		defer w.close()
		if _, err := w.shadowsocks(context.Background(), configuration{}); err == nil || !strings.Contains(err.Error(), "input ended") {
			t.Fatalf("closed input error = %v", err)
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

func TestUpdateShadowsocksConfigurationFillsMissingKeysAndDefaultPort(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("# existing setting\nOTHER=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateShadowsocksConfiguration(root, configuration{public: 443, vmess: 9443, ui: 8080, shadowsocksEnabled: true}); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_SHADOWSOCKS_PORT"] != "8388" || values["XRAY_SHADOWSOCKS_ENABLED"] != "true" || values["XRAY_SHADOWSOCKS_METHOD"] != defaultShadowsocksMethod || values["XRAY_SHADOWSOCKS_NETWORK"] != defaultShadowsocksNetwork || values["OTHER"] != "value" {
		t.Fatalf("updated Shadowsocks values = %#v", values)
	}
}
