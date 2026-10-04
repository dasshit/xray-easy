package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prepareExistingOptionalServices(t *testing.T, awg, lease bool) string {
	t.Helper()
	root := t.TempDir()
	cfg := configuration{
		project: defaultProject, version: defaultVersion, public: 443, vmess: 9443,
		shadowsocks: 8388, ui: 8080, hysteriaMode: "custom",
		awgEnabled: awg, awgPublicHost: "vpn.example.test", awgPublicPort: defaultAWGPort,
		leaseEnabled: lease,
	}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := updateAWGConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := updateLeaseConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRunInstallDisablesOptionalServicesAndStopsThem(t *testing.T) {
	root := prepareExistingOptionalServices(t, true, true)
	runner := &fakeRunner{}
	var output bytes.Buffer
	// Keep Hysteria, Shadowsocks, and Trojan disabled; disable AWG and leases;
	// accept the resulting Compose changes.
	input := "\n1\n\n\n1\n\n"
	result, err := runInstall(context.Background(), root, strings.NewReader(input), &output, runner)
	if err != nil {
		t.Fatal(err)
	}
	if !result.started || result.config.awgEnabled || result.config.leaseEnabled {
		t.Fatalf("installer result = %+v, want started without optional services", result)
	}
	calls := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"compose --profile awg -f compose.yaml stop amneziawg-service",
		"compose --profile lease -f compose.yaml stop xray-lease-service",
		"compose -f compose.yaml exec -T control-plane xray-easy doctor",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("installer did not run %q: %s", want, calls)
		}
	}
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["AWG_PUBLIC_HOST"] != "" || values["XRAY_LEASE_SERVICE_ENABLED"] != "false" || strings.Contains(values["COMPOSE_PROFILES"], "awg") || strings.Contains(values["COMPOSE_PROFILES"], "lease") {
		t.Fatalf("optional services remain enabled in .env: %#v", values)
	}
}

func TestRunInstallReportsOptionalServiceStopFailures(t *testing.T) {
	for _, test := range []struct {
		name         string
		awg          bool
		lease        bool
		input        string
		failOn       string
		wantContains string
	}{
		{
			name: "AmneziaWG stop", awg: true, lease: false,
			input: "\n1\n\n\n\n\n", failOn: "stop amneziawg-service",
			wantContains: "stop AmneziaWG before disabling it",
		},
		{
			name: "lease service stop", awg: false, lease: true,
			input: "\n\n\n\n1\n\n", failOn: "stop xray-lease-service",
			wantContains: "stop lease service before disabling it",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := prepareExistingOptionalServices(t, test.awg, test.lease)
			runner := &fakeRunner{failOn: test.failOn}
			var output bytes.Buffer
			_, err := runInstall(context.Background(), root, strings.NewReader(test.input), &output, runner)
			if err == nil || !strings.Contains(err.Error(), test.wantContains) {
				t.Fatalf("runInstall() error = %v, want %q", err, test.wantContains)
			}
		})
	}
}

func TestRunInstallRejectsInvalidPersistedLeasePolicyBeforeCompose(t *testing.T) {
	root := prepareExistingOptionalServices(t, false, true)
	envPath := filepath.Join(root, ".env")
	file, err := os.OpenFile(envPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("XRAY_LEASE_MAX_ACTIVE=0\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	var output bytes.Buffer
	_, err = runInstall(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "invalid Xray lease policy") {
		t.Fatalf("runInstall() error = %v, want lease-policy validation error", err)
	}
	if strings.Contains(strings.Join(runner.calls, "\n"), "compose -f compose.yaml config") {
		t.Fatalf("Compose ran with an invalid lease policy: %v", runner.calls)
	}
}

func TestRunInstallReportsDuplicateHysteriaEnvironmentSetting(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{
		project: defaultProject, version: defaultVersion, public: 443, vmess: 9443,
		shadowsocks: 8388, ui: 8080, hysteriaEnabled: true, hysteriaMode: "custom",
	}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	file, err := os.OpenFile(envPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("XRAY_HYSTERIA2_ENABLED=true\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	var output bytes.Buffer
	_, err = runInstall(context.Background(), root, strings.NewReader("1\n\n\n\n\n\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "duplicate XRAY_HYSTERIA2_ENABLED") {
		t.Fatalf("runInstall() error = %v, want duplicate Hysteria setting error", err)
	}
}

func TestRunInstallReportsXrayReloadFailureAfterSelfSignedCertificateChange(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{
		project: defaultProject, version: defaultVersion, public: 443, vmess: 9443,
		shadowsocks: 8388, ui: 8080, hysteriaEnabled: true, hysteriaMode: "self-signed",
		hysteriaCertIP: "8.8.8.8",
	}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failOn: "--force-recreate xray-core-service"}
	var output bytes.Buffer
	_, err := runInstall(context.Background(), root, strings.NewReader("\n\n\n\n\n\n\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "Xray could not reload the Hysteria 2 TLS certificate") {
		t.Fatalf("runInstall() error = %v, want Xray certificate reload failure", err)
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "--force-recreate xray-core-service") {
		t.Fatalf("installer did not attempt the Xray-only reload: %v", runner.calls)
	}
}

func TestRunInstallWizardCancellationAndInputFailures(t *testing.T) {
	for _, test := range []struct {
		name         string
		previousPage int
		cancel       bool
	}{
		{name: "Hysteria input ends"},
		{name: "AmneziaWG input ends", previousPage: 1},
		{name: "Shadowsocks input ends", previousPage: 2},
		{name: "Trojan input ends", previousPage: 3},
		{name: "lease input ends", previousPage: 4},
		{name: "confirmation input ends", previousPage: 5},
		{name: "Hysteria cancelled", cancel: true},
		{name: "AmneziaWG cancelled", previousPage: 1, cancel: true},
		{name: "Shadowsocks cancelled", previousPage: 2, cancel: true},
		{name: "Trojan cancelled", previousPage: 3, cancel: true},
		{name: "lease cancelled", previousPage: 4, cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := createConfiguration(root, configuration{
				project: defaultProject, version: defaultVersion, public: 443,
				vmess: 9443, shadowsocks: 8388, ui: 8080, hysteriaMode: "custom",
			}); err != nil {
				t.Fatal(err)
			}
			input := strings.Repeat("\n", test.previousPage)
			if test.cancel {
				input += "\x1b"
			}
			runner := &fakeRunner{}
			var output bytes.Buffer
			result, err := runInstall(context.Background(), root, strings.NewReader(input), &output, runner)
			if test.cancel {
				if err != nil || result.started {
					t.Fatalf("cancelled installation = %+v, %v; want a clean cancellation", result, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "terminal input ended") {
				t.Fatalf("input failure = %v, want terminal EOF", err)
			}
			if len(runner.calls) != 2 {
				t.Fatalf("wizard continued to Docker after early exit: %v", runner.calls)
			}
		})
	}

	t.Run("ports cancelled", func(t *testing.T) {
		root := t.TempDir()
		runner := &fakeRunner{}
		var output bytes.Buffer
		result, err := runInstall(context.Background(), root, strings.NewReader("\x1b"), &output, runner)
		if err != nil || result.started {
			t.Fatalf("cancelled port setup = %+v, %v; want a clean cancellation", result, err)
		}
		if len(runner.calls) != 2 {
			t.Fatalf("cancelled port setup continued to Docker: %v", runner.calls)
		}
	})
}
