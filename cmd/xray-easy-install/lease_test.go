package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateLeaseConfigurationMergesComposeProfilesAndPreservesPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	initial := "COMPOSE_PROFILES=custom,awg\nXRAY_LEASE_SERVICE_ENABLED=false\nXRAY_LEASE_MAX_ACTIVE=2\nXRAY_LEASE_GRACE=45s\nXRAY_LEASE_RETRY_DELAY=2s\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	configuration := configuration{awgEnabled: true, leaseEnabled: true}
	if err := updateLeaseConfiguration(root, configuration); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["COMPOSE_PROFILES"] != "custom,awg,lease" || values["XRAY_LEASE_SERVICE_ENABLED"] != "true" || values["XRAY_LEASE_GRACE"] != "45s" || values["XRAY_LEASE_RETRY_DELAY"] != "2s" {
		t.Fatalf("enabled lease settings = %#v", values)
	}
	configuration.leaseEnabled = false
	if err := updateLeaseConfiguration(root, configuration); err != nil {
		t.Fatal(err)
	}
	values, err = readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["COMPOSE_PROFILES"] != "custom,awg" || values["XRAY_LEASE_SERVICE_ENABLED"] != "false" {
		t.Fatalf("disabled lease settings = %#v", values)
	}
	configuration.awgEnabled = false
	if err := updateAWGConfiguration(root, configuration); err != nil {
		t.Fatal(err)
	}
	values, err = readEnvironmentFile(path)
	if err != nil || values["COMPOSE_PROFILES"] != "custom" {
		t.Fatalf("managed profiles after disabling both services = %#v, %v", values, err)
	}
}

func TestUpdateLeaseConfigurationAddsDefaultsAndRejectsDuplicateKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_EASY_MASTER_KEY=key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateLeaseConfiguration(root, configuration{leaseEnabled: true}); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["COMPOSE_PROFILES"] != "lease" || values["XRAY_LEASE_SERVICE_ENABLED"] != "true" || values["XRAY_LEASE_MAX_ACTIVE"] != "2" || values["XRAY_LEASE_GRACE"] != "30s" || values["XRAY_LEASE_RETRY_DELAY"] != "1s" {
		t.Fatalf("new lease environment = %#v", values)
	}
	if err := os.WriteFile(path, []byte("XRAY_LEASE_GRACE=30s\nXRAY_LEASE_GRACE=45s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateLeaseConfiguration(root, configuration{}); err == nil || !strings.Contains(err.Error(), "duplicate XRAY_LEASE_GRACE") {
		t.Fatalf("duplicate lease setting error = %v", err)
	}
}

func TestLoadConfigurationDetectsLeaseComposeProfile(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.leaseEnabled = true
	if err := updateLeaseConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfiguration(root)
	if err != nil || !loaded.leaseEnabled {
		t.Fatalf("loaded lease profile = %t, %v", loaded.leaseEnabled, err)
	}
}

func TestLeaseServiceWizardSelection(t *testing.T) {
	for _, test := range []struct {
		name          string
		input         string
		want          bool
		enabledBefore bool
	}{
		{name: "off by default", input: "\n"},
		{name: "explicitly enabled", input: "\x1b[B\n", want: true},
		{name: "existing enabled setting can be disabled", input: "\x1b[A\n", want: false, enabledBefore: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output strings.Builder
			wizard := newWizard(strings.NewReader(test.input), &output)
			defer wizard.close()
			got, err := wizard.leaseService(context.Background(), configuration{leaseEnabled: test.enabledBefore})
			if err != nil || got.leaseEnabled != test.want {
				t.Fatalf("lease selection = %+v, %v", got, err)
			}
		})
	}
}

func TestValidateLeaseConfigurationChecksOptionalPolicyAndDurations(t *testing.T) {
	root := t.TempDir()
	if err := validateLeaseConfiguration(root, configuration{}); err != nil {
		t.Fatalf("disabled lease validation = %v", err)
	}
	if err := validateLeaseConfiguration(root, configuration{leaseEnabled: true}); err != nil {
		t.Fatalf("default lease configuration = %v", err)
	}
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_LEASE_MAX_ACTIVE=2\nXRAY_LEASE_GRACE=45s\nXRAY_LEASE_RETRY_DELAY=2s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateLeaseConfiguration(root, configuration{leaseEnabled: true}); err != nil {
		t.Fatalf("valid custom lease policy = %v", err)
	}
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{"unsupported limit", "XRAY_LEASE_MAX_ACTIVE=3\n", "maximum active leases must be 2"},
		{"malformed duration", "XRAY_LEASE_GRACE=soon\n", "XRAY_LEASE_GRACE"},
		{"zero duration", "XRAY_LEASE_RETRY_DELAY=0s\n", "retry delay must be between 0 and 1 minute"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.value), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateLeaseConfiguration(root, configuration{leaseEnabled: true}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid lease policy error=%v, want %q", err, test.want)
			}
		})
	}
}
