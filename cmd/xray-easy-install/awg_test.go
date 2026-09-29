package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAWGConfigurationChangedDetectsRuntimeEndpointChanges(t *testing.T) {
	before := configuration{awgEnabled: true, awgPublicHost: "old.example.test", awgPublicPort: defaultAWGPort}
	if awgConfigurationChanged(before, before) {
		t.Fatal("unchanged AmneziaWG settings reported a change")
	}
	for _, after := range []configuration{
		{awgEnabled: false, awgPublicHost: before.awgPublicHost, awgPublicPort: before.awgPublicPort},
		{awgEnabled: true, awgPublicHost: "new.example.test", awgPublicPort: before.awgPublicPort},
		{awgEnabled: true, awgPublicHost: before.awgPublicHost, awgPublicPort: before.awgPublicPort + 1},
	} {
		if !awgConfigurationChanged(before, after) {
			t.Errorf("settings change was not detected: before=%+v after=%+v", before, after)
		}
	}
}

func TestValidateAWGConfiguration(t *testing.T) {
	base := configuration{public: 443, awgEnabled: true, awgPublicHost: "89.169.13.234", awgPublicPort: 51820}
	if err := validateAWGConfiguration(base); err != nil {
		t.Fatalf("valid AmneziaWG settings: %v", err)
	}

	for _, test := range []struct {
		name string
		edit func(*configuration)
		want string
	}{
		{"invalid port", func(cfg *configuration) { cfg.awgPublicPort = 70000 }, "AWG_PUBLIC_PORT"},
		{"port collision", func(cfg *configuration) { cfg.awgPublicPort = 443 }, "must differ"},
		{"invalid host", func(cfg *configuration) { cfg.awgPublicHost = "not a host!" }, "AWG_PUBLIC_HOST"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			test.edit(&cfg)
			if err := validateAWGConfiguration(cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestUpdateAWGConfigurationPreservesOtherEnvironment(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	initial := "# keep this comment\nXRAY_PUBLIC_PORT=443\nCOMPOSE_PROFILES=old\nAWG_PUBLIC_HOST=old.example\nAWG_PUBLIC_PORT=1234\nOTHER=value\n"
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{awgEnabled: true, awgPublicHost: "vpn.example.com", awgPublicPort: 51821}
	if err := updateAWGConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"# keep this comment", "XRAY_PUBLIC_PORT=443", "COMPOSE_PROFILES=awg",
		"AWG_PUBLIC_HOST=vpn.example.com", "AWG_PUBLIC_PORT=51821", "OTHER=value",
	} {
		if !strings.Contains(string(data), line) {
			t.Errorf("updated .env omitted %q:\n%s", line, data)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf(".env permissions = %v, error = %v; want 0600", info, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ".env" {
		t.Fatalf("unexpected temporary files after update: %v", entries)
	}
}

func TestUpdateAWGConfigurationDisablesProfileAndRejectsDuplicateKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("COMPOSE_PROFILES=awg\nAWG_PUBLIC_HOST=vpn.example.com\nAWG_PUBLIC_PORT=51820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateAWGConfiguration(root, configuration{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "COMPOSE_PROFILES=awg") || !strings.Contains(string(data), "COMPOSE_PROFILES=\n") || !strings.Contains(string(data), "AWG_PUBLIC_HOST=\n") || !strings.Contains(string(data), "AWG_PUBLIC_PORT=1234\n") {
		t.Fatalf("AmneziaWG profile was not disabled:\n%s", data)
	}

	if err := os.WriteFile(path, []byte("AWG_PUBLIC_PORT=51820\nAWG_PUBLIC_PORT=51821\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateAWGConfiguration(root, configuration{}); err == nil || !strings.Contains(err.Error(), "duplicate AWG_PUBLIC_PORT") {
		t.Fatalf("duplicate setting error = %v", err)
	}
}

func TestLoadConfigurationReadsAWGComposeSettings(t *testing.T) {
	root := t.TempDir()
	if err := createConfiguration(root, configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080, tokenPath: newTokenPath}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("COMPOSE_PROFILES=other, awg\nAWG_PUBLIC_HOST=vpn.example.com\nAWG_PUBLIC_PORT=51822\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.awgEnabled || cfg.awgPublicHost != "vpn.example.com" || cfg.awgPublicPort != 51822 {
		t.Fatalf("AmneziaWG settings were not loaded: %+v", cfg)
	}
}

func TestAmneziaWGTUISelection(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		var output strings.Builder
		wizard := newWizard(strings.NewReader("\n"), &output)
		defer wizard.close()
		cfg, err := wizard.amneziaWG(t.Context(), configuration{awgPublicPort: defaultAWGPort})
		if err != nil || cfg.awgEnabled {
			t.Fatalf("default selection: config=%+v error=%v", cfg, err)
		}
	})

	t.Run("enable and accept suggested host", func(t *testing.T) {
		var output strings.Builder
		wizard := newWizard(strings.NewReader("\x1b[B\n\n"), &output)
		wizard.hysteriaSuggestedIP = "89.169.13.234"
		defer wizard.close()
		cfg, err := wizard.amneziaWG(t.Context(), configuration{awgPublicPort: defaultAWGPort})
		if err != nil || !cfg.awgEnabled || cfg.awgPublicHost != "89.169.13.234" {
			t.Fatalf("enabled selection: config=%+v error=%v", cfg, err)
		}
	})
}
