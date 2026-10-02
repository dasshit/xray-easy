package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallerSelectsMkcertIPv4AndPreservesItOnRetry(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n\n2\n89.169.13.234\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	before := readPrivateFile(t, filepath.Join(root, ".env"))
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_HYSTERIA2_ENABLED"] != "true" || values["XRAY_HYSTERIA2_TLS_MODE"] != "self-signed" || values["XRAY_HYSTERIA2_CERT_IP"] != "89.169.13.234" {
		t.Fatalf("mkcert mode was not saved: %#v", values)
	}
	runner.calls = nil
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	if got := readPrivateFile(t, filepath.Join(root, ".env")); got != before {
		t.Fatal("retry changed .env")
	}
	calls := strings.Join(runner.calls, "\n")
	if !strings.Contains(calls, "--no-deps --force-recreate xray-core-service") {
		t.Fatal("retry must rerun mkcert expiry check and recreate Xray")
	}
	if strings.Contains(calls, "--force-recreate control-plane") || strings.Contains(calls, "--force-recreate amneziawg-service") {
		t.Fatalf("TLS certificate reload unexpectedly force-recreated another service: %s", calls)
	}
}

func TestInstallerCanSwitchExistingHysteriaModeWithoutChangingMasterKey(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	before := readPrivateFile(t, filepath.Join(root, ".env"))
	key := strings.Split(strings.Split(before, "XRAY_EASY_MASTER_KEY=")[1], "\n")[0]
	runner.calls = nil
	if err := run(context.Background(), root, strings.NewReader("2\n89.169.13.234\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	after := readPrivateFile(t, filepath.Join(root, ".env"))
	if !strings.Contains(after, "XRAY_EASY_MASTER_KEY="+key+"\n") || !strings.Contains(after, "XRAY_HYSTERIA2_CERT_IP=89.169.13.234\n") {
		t.Fatal("switching TLS mode lost the master key or IPv4")
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "--force-recreate") {
		t.Fatal("switching TLS mode must recreate Xray")
	}
}

func TestLegacyHysteriaRequiresExplicitCertificateChoice(t *testing.T) {
	root := t.TempDir()
	if err := createConfiguration(root, configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080, hysteriaMode: "custom"}); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	oldEnv := readPrivateFile(t, envPath)
	var legacyLines []string
	for _, line := range strings.Split(strings.TrimSuffix(oldEnv, "\n"), "\n") {
		if !strings.HasPrefix(line, "XRAY_HYSTERIA2_") {
			legacyLines = append(legacyLines, line)
		}
	}
	legacy := strings.Join(append(legacyLines, "XRAY_HYSTERIA2_ENABLED=true"), "\n") + "\n"
	if err := os.WriteFile(envPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfiguration(root)
	if err != nil || cfg.hysteriaMode != "legacy" {
		t.Fatalf("legacy mode: cfg=%+v err=%v", cfg, err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n"), &output, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "input ended") {
		t.Fatalf("legacy mode should require a selection, got %v", err)
	}
	if got := readPrivateFile(t, envPath); got != legacy {
		t.Fatal("incomplete selection changed the legacy environment")
	}
	if err := run(context.Background(), root, strings.NewReader("2\n89.169.13.234\n\n\n\n\n"), &output, &fakeRunner{}); err != nil {
		t.Fatal(err)
	}
	if got := readPrivateFile(t, envPath); !strings.Contains(got, "XRAY_HYSTERIA2_TLS_MODE=self-signed\n") {
		t.Fatal("explicit mode was not saved")
	}
}

func TestInstallerCancellationAtHysteriaChoiceLeavesNoSecrets(t *testing.T) {
	root := t.TempDir()
	var output bytes.Buffer
	result, err := runInstall(context.Background(), root, strings.NewReader("\n\n\x1b"), &output, &fakeRunner{})
	if err != nil || result.started {
		t.Fatalf("cancelled installation: result=%+v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled installation wrote configuration: %v", err)
	}
}

func TestInstallerCancellationAtPortsAndReviewLeavesNoSecrets(t *testing.T) {
	for _, input := range []string{"\x1b", "\n\n\n"} {
		root := t.TempDir()
		var output bytes.Buffer
		result, err := runInstall(context.Background(), root, strings.NewReader(input), &output, &fakeRunner{})
		if input == "\x1b" {
			if err != nil || result.started {
				t.Fatalf("port cancellation: result=%+v err=%v", result, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "input ended") {
			t.Fatalf("closed review input: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled installation wrote configuration: %v", err)
		}
	}
}

func TestInstallerRejectsInvalidCustomCertificateBeforeSavingEnvironment(t *testing.T) {
	root := t.TempDir()
	certPath := filepath.Join(root, "bad-cert.pem")
	keyPath := filepath.Join(root, "bad-key.pem")
	if err := os.WriteFile(certPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	input := "\n\n3\n" + certPath + "\n" + keyPath + "\nvpn.example.com\n\n\n\n\n"
	if err := run(context.Background(), root, strings.NewReader(input), &output, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "certificate and key are invalid") {
		t.Fatalf("invalid PEM error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid certificate wrote configuration: %v", err)
	}
}

func TestCustomCertificateImportValidatesNameAndKey(t *testing.T) {
	root := t.TempDir()
	cert, key := makeTestCertificate(t, "vpn.example.com")
	certSource := filepath.Join(root, "source-cert.pem")
	keySource := filepath.Join(root, "source-key.pem")
	if err := os.WriteFile(certSource, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keySource, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaServerName: "vpn.example.com", hysteriaCertSource: certSource, hysteriaKeySource: keySource}
	changed, err := importHysteriaCertificate(root, cfg)
	if err != nil || !changed {
		t.Fatalf("valid certificate import: changed=%t err=%v", changed, err)
	}
	if info, err := os.Stat(filepath.Join(root, "secrets/hysteria/privkey.pem")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("imported private key permissions: info=%v err=%v", info, err)
	}
	changed, err = importHysteriaCertificate(root, cfg)
	if err != nil || changed {
		t.Fatalf("unchanged import: changed=%t err=%v", changed, err)
	}
	cfg.hysteriaServerName = "other.example.com"
	if _, err := importHysteriaCertificate(root, cfg); err == nil {
		t.Fatal("certificate accepted a DNS name outside its SAN")
	}
}

func TestInstallerImportsAndRenewsCustomCertificate(t *testing.T) {
	root := t.TempDir()
	certPath := filepath.Join(root, "provided-cert.pem")
	keyPath := filepath.Join(root, "provided-key.pem")
	writeCertificate := func() {
		cert, key := makeTestCertificate(t, "vpn.example.com")
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCertificate()
	runner := &fakeRunner{}
	var output bytes.Buffer
	input := "\n\n3\n" + certPath + "\n" + keyPath + "\nvpn.example.com\n\n\n\n\n"
	if err := run(context.Background(), root, strings.NewReader(input), &output, runner); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_HYSTERIA2_TLS_MODE"] != "custom" || values["XRAY_HYSTERIA2_TLS_SERVER_NAME"] != "vpn.example.com" {
		t.Fatalf("custom mode was not saved: %#v", values)
	}
	importedPath := filepath.Join(root, "secrets/hysteria/fullchain.pem")
	before, err := os.ReadFile(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	writeCertificate()
	runner.calls = nil
	input = "\n" + certPath + "\n" + keyPath + "\n\n\n\n\n\n"
	if err := run(context.Background(), root, strings.NewReader(input), &output, runner); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(importedPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) || !strings.Contains(strings.Join(runner.calls, "\n"), "--force-recreate") {
		t.Fatal("renewed custom certificate did not update files and recreate Xray")
	}
}

func TestHysteriaWizardRepromptsInvalidIPv4(t *testing.T) {
	var output bytes.Buffer
	input := "2\n127.0.0.1\n" + strings.Repeat("\x7f", len("127.0.0.1")) + "89.169.13.234\n"
	wizard := newWizard(strings.NewReader(input), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteriaMode != "self-signed" || cfg.hysteriaCertIP != "89.169.13.234" || !strings.Contains(output.String(), "Enter the public IPv4 address") {
		t.Fatalf("invalid address handling: cfg=%+v", cfg)
	}
}

func TestHysteriaWizardAcceptsSuggestedIPv4OnEnter(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("2\n\n"), &output)
	defer wizard.close()
	wizard.hysteriaSuggestedIP = "89.169.13.234"
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteriaCertIP != "89.169.13.234" || !strings.Contains(output.String(), "89.169.13.234 (Enter to use)") {
		t.Fatalf("suggested address was not accepted: %+v", cfg)
	}
}

func TestHysteriaWizardManualIPv4OverridesSuggestion(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("2\n8.8.8.8\n"), &output)
	defer wizard.close()
	wizard.hysteriaSuggestedIP = "89.169.13.234"
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteriaCertIP != "8.8.8.8" {
		t.Fatalf("manual address did not override suggestion: %+v", cfg)
	}
}

func TestHysteriaWizardRequiresManualIPv4WithoutSuggestion(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("2\n\n89.169.13.234\n"), &output)
	defer wizard.close()
	wizard.hysteriaSuggestedIP = ""
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteriaCertIP != "89.169.13.234" || !strings.Contains(output.String(), "Enter the public IPv4 address") {
		t.Fatalf("missing suggestion did not require manual input: %+v", cfg)
	}
}

func TestUniquePublicIPv4Suggestion(t *testing.T) {
	parse := func(values ...string) []netip.Addr {
		addresses := make([]netip.Addr, 0, len(values))
		for _, value := range values {
			addresses = append(addresses, netip.MustParseAddr(value))
		}
		return addresses
	}
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
		want      string
	}{
		{"one public address", parse("127.0.0.1", "172.20.0.1", "89.169.13.234", "fe80::1"), "89.169.13.234"},
		{"duplicate public address", parse("89.169.13.234", "89.169.13.234"), "89.169.13.234"},
		{"ambiguous public addresses", parse("89.169.13.234", "8.8.8.8"), ""},
		{"no public address", parse("10.0.0.1", "100.64.0.1", "192.0.2.5", "fe80::1"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := uniquePublicIPv4(test.addresses); got != test.want {
				t.Fatalf("uniquePublicIPv4() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHysteriaWizardImportsCustomCertificatePaths(t *testing.T) {
	root := t.TempDir()
	cert, key := makeTestCertificate(t, "vpn.example.com")
	certPath := filepath.Join(root, "cert.pem")
	keyPath := filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	input := "\x1b[B\x1b[B\n" + certPath + "x\x7f\t\x1b[A\x1b[B" + keyPath + "\nvpn.example.com\n"
	wizard := newWizard(strings.NewReader(input), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), root, configuration{hysteriaMode: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.hysteriaEnabled || cfg.hysteriaMode != "custom" || cfg.hysteriaCertSource != certPath || cfg.hysteriaKeySource != keyPath || cfg.hysteriaServerName != "vpn.example.com" {
		t.Fatalf("custom certificate choice was lost: %+v", cfg)
	}
}

func TestHysteriaWizardRequiresCertificateServerName(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "secrets", "hysteria")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cert, key := makeTestCertificate(t, "vpn.example.com")
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("3\n\n\n\nvpn.example.com\n"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), root, configuration{hysteriaMode: "custom"})
	if err != nil || cfg.hysteriaServerName != "vpn.example.com" || !strings.Contains(output.String(), "Enter the DNS name or IP address") {
		t.Fatalf("certificate name prompt: cfg=%+v err=%v", cfg, err)
	}
}

func TestHysteriaWizardExplainsMissingCustomFiles(t *testing.T) {
	root := t.TempDir()
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("3\n\n\n\n\x1b"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	_, err := wizard.hysteria(context.Background(), root, configuration{hysteriaMode: "custom"})
	if !errors.Is(err, errCancelled) || !strings.Contains(output.String(), "Certificate file is missing") {
		t.Fatalf("missing certificate guidance: %v", err)
	}
}

func TestHysteriaWizardExplainsMissingPrivateKey(t *testing.T) {
	root := t.TempDir()
	certPath := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(certPath, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("3\n"+certPath+"\n\n\n\x1b"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	_, err := wizard.hysteria(context.Background(), root, configuration{hysteriaMode: "custom"})
	if !errors.Is(err, errCancelled) || !strings.Contains(output.String(), "Private key file is missing") {
		t.Fatalf("missing key guidance: %v", err)
	}
}

func TestHysteriaWizardRequestsLargerTerminal(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("2\x1b"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	wizard.mu.Lock()
	wizard.width, wizard.height = 50, 18
	wizard.mu.Unlock()
	_, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaMode: "custom"})
	if !errors.Is(err, errCancelled) || !strings.Contains(output.String(), "Enlarge the terminal") {
		t.Fatalf("small terminal handling: %v", err)
	}
}

func TestHysteriaWizardCanDisableExistingInbound(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("\x1b[A\n"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	cfg, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaEnabled: true, hysteriaMode: "self-signed", hysteriaCertIP: "89.169.13.234"})
	if err != nil || cfg.hysteriaEnabled {
		t.Fatalf("disable choice: cfg=%+v err=%v", cfg, err)
	}
}

func TestLegacyHysteriaChoiceCanNavigateToCustomCertificate(t *testing.T) {
	var output bytes.Buffer
	wizard := newWizard(strings.NewReader("\x1b[A\x1b"), &output)
	defer wizard.close()
	wizard.step(2, "Configuration")
	_, err := wizard.hysteria(context.Background(), t.TempDir(), configuration{hysteriaEnabled: true, hysteriaMode: "legacy"})
	if !errors.Is(err, errCancelled) {
		t.Fatalf("legacy mode keyboard navigation: %v", err)
	}
	if !strings.Contains(output.String(), "My TLS certificate") {
		t.Fatal("custom certificate option was not displayed")
	}
}

func TestCustomCertificateImportRejectsMissingAndMismatchedFiles(t *testing.T) {
	root := t.TempDir()
	cert, key := makeTestCertificate(t, "vpn.example.com")
	_, otherKey := makeTestCertificate(t, "vpn.example.com")
	certPath := filepath.Join(root, "cert.pem")
	keyPath := filepath.Join(root, "key.pem")
	cfg := configuration{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaCertSource: certPath, hysteriaKeySource: keyPath}
	if _, err := importHysteriaCertificate(root, cfg); err == nil || !strings.Contains(err.Error(), "read Hysteria 2 certificate") {
		t.Fatalf("missing cert error: %v", err)
	}
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importHysteriaCertificate(root, cfg); err == nil || !strings.Contains(err.Error(), "read Hysteria 2 private key") {
		t.Fatalf("missing key error: %v", err)
	}
	if err := os.WriteFile(keyPath, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importHysteriaCertificate(root, cfg); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched key error: %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secrets"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := importHysteriaCertificate(root, cfg); err == nil {
		t.Fatal("blocked secrets directory was accepted")
	}
}

func TestCustomCertificateImportRejectsExpiredCertificate(t *testing.T) {
	root := t.TempDir()
	cert, key := makeTestCertificateWithValidity(t, "vpn.example.com", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	certPath := filepath.Join(root, "cert.pem")
	keyPath := filepath.Join(root, "key.pem")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaCertSource: certPath, hysteriaKeySource: keyPath}
	if _, err := importHysteriaCertificate(root, cfg); err == nil || !strings.Contains(err.Error(), "not currently valid") {
		t.Fatalf("expired certificate error: %v", err)
	}
}

func TestUpdateHysteriaConfigurationRejectsDuplicateEnvironmentKeys(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("XRAY_HYSTERIA2_ENABLED=false\nXRAY_HYSTERIA2_ENABLED=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateHysteriaConfiguration(root, configuration{hysteriaMode: "custom"}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate environment key error: %v", err)
	}
}

func TestHysteriaConfigurationRejectsMissingEnvironmentFile(t *testing.T) {
	if err := updateHysteriaConfiguration(t.TempDir(), configuration{hysteriaMode: "custom"}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing environment file: %v", err)
	}
}

func TestCustomCertificateImportUsesExistingProjectFilesByDefault(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "secrets", "hysteria")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cert, key := makeTestCertificate(t, "vpn.example.com")
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := importHysteriaCertificate(root, configuration{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaServerName: "vpn.example.com"})
	if err != nil || changed {
		t.Fatalf("existing project certificate: changed=%t err=%v", changed, err)
	}
}

func TestHysteriaNextStepsIncludeUDPFirewall(t *testing.T) {
	var output bytes.Buffer
	printNextSteps(&output, configuration{public: 443, ui: 8080, hysteriaEnabled: true})
	if !strings.Contains(output.String(), "Allow inbound UDP 443") {
		t.Fatal("Hysteria 2 firewall guidance is missing")
	}
}

func TestHysteriaConfigurationRejectsUnsafeModesAndNames(t *testing.T) {
	for _, cfg := range []configuration{
		{hysteriaEnabled: true, hysteriaMode: "self-signed"},
		{hysteriaEnabled: true, hysteriaMode: "self-signed", hysteriaCertIP: "127.0.0.1"},
		{hysteriaEnabled: true, hysteriaMode: "self-signed", hysteriaCertIP: "89.169.13.234", hysteriaServerName: "vpn.example.com"},
		{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaCertIP: "89.169.13.234"},
		{hysteriaEnabled: true, hysteriaMode: "custom", hysteriaServerName: "vpn.example.com;bad"},
		{hysteriaEnabled: true, hysteriaMode: "unexpected"},
	} {
		if err := validateHysteriaConfiguration(cfg); err == nil {
			t.Fatalf("invalid Hysteria 2 configuration accepted: %+v", cfg)
		}
	}
}

func TestHysteriaCertificatePathsResolveFromRepositoryOrHome(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, test := range []struct{ input, want string }{
		{"", filepath.Join(root, "secrets/hysteria/fullchain.pem")},
		{"certs/fullchain.pem", filepath.Join(root, "certs/fullchain.pem")},
		{"~/fullchain.pem", filepath.Join(home, "fullchain.pem")},
		{filepath.Join(root, "custom.pem"), filepath.Join(root, "custom.pem")},
	} {
		if got := resolveHysteriaSource(root, test.input, "fullchain.pem"); got != test.want {
			t.Errorf("resolveHysteriaSource(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func makeTestCertificate(t *testing.T, name string) ([]byte, []byte) {
	return makeTestCertificateWithValidity(t, name, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func makeTestCertificateWithValidity(t *testing.T, name string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
