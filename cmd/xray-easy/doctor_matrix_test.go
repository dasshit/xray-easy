package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/store"
)

type doctorProbeFile struct {
	path     string
	closeErr error
}

func (f doctorProbeFile) Name() string { return f.path }
func (f doctorProbeFile) Close() error { return f.closeErr }

func TestDoctorFormattingHelpersSanitizeVersionsPortsAndOptionalServices(t *testing.T) {
	t.Setenv("XRAY_EASY_VERSION", "bad version")
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	t.Setenv("XRAY_VMESS_PORT", "bad")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "10443")
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("AWG_PUBLIC_PORT", "1234")
	if got := safeRuntimeXrayVersion("not an Xray version"); got != "unknown" {
		t.Fatalf("safe runtime version = %q", got)
	}
	if got := safeDoctorVersion("XRAY_EASY_VERSION", "dev"); got != "invalid" {
		t.Fatalf("safe doctor version = %q", got)
	}
	if got := safeDoctorPort("XRAY_VMESS_PORT", "9443"); got != "invalid" {
		t.Fatalf("safe doctor port = %q", got)
	}
	if _, err := doctorConfiguredPort("XRAY_VMESS_PORT", "9443"); err == nil {
		t.Fatal("invalid doctor port was accepted")
	}
	var report bytes.Buffer
	writeDoctorHeader(&report)
	for _, want := range []string{"Shadowsocks TCP+UDP: 8388", "Trojan TCP: 10443", "AmneziaWG public UDP: 1234", "Xray image: 26.7.28"} {
		if !strings.Contains(report.String(), want) {
			t.Fatalf("doctor header omitted %q: %s", want, report.String())
		}
	}
}

func TestDoctorHysteriaCustomTLSHintRequiresTrustedCertificate(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	setDoctorEnvironment(t, key)
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	checks := collectDoctorChecks(context.Background(), dataDir, configDir,
		&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 1}},
		&doctorHandlerStub{}, &doctorStatsStub{})
	check := findDoctorCheck(checks, "Hysteria 2 UDP firewall")
	if check == nil || !strings.Contains(check.hint, "supplied certificate must be trusted") {
		t.Fatalf("custom certificate guidance = %+v", check)
	}
}

func TestDoctorCLIRequiresControllerAddressBeforeDialing(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	if err := runDoctorCLI(context.Background(), nil, t.TempDir(), t.TempDir(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "XRAY_CONTROLLER_ADDR must be configured") {
		t.Fatalf("doctor CLI without Controller address = %v", err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "bad address")
	if err := runDoctorCLI(context.Background(), nil, t.TempDir(), t.TempDir(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "initialize Controller") {
		t.Fatalf("doctor CLI invalid Controller address = %v", err)
	}
}

func doctorCheckContains(checks []doctorCheck, name, detail string) bool {
	for _, check := range checks {
		if check.name == name && strings.Contains(check.detail, detail) {
			return true
		}
	}
	return false
}

func TestDoctorChecksExplainVolumeDatabaseTokenAndRuntimeFailures(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		checkName  string
		wantDetail string
		mutate     func(*testing.T, *string, *string, *doctorXrayRuntimeStub, *doctorHandlerStub)
	}{
		{"missing data volume", "Data volume", "not accessible", func(t *testing.T, data, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			*data = filepath.Join(t.TempDir(), "missing")
		}},
		{"missing config volume", "Xray config volume", "not accessible", func(t *testing.T, _, config *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			*config = filepath.Join(t.TempDir(), "missing")
		}},
		{"missing candidates", "Candidate config directory", "not accessible", func(t *testing.T, _, config *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			if err := os.RemoveAll(filepath.Join(*config, "candidates")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing database", "SQLite database", "missing, unreadable", func(t *testing.T, data, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			if err := os.Remove(filepath.Join(*data, "state.db")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing token", "Controller secret", "missing or inaccessible", func(t *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
		}},
		{"token directory", "Controller secret", "not a regular file", func(t *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", t.TempDir())
		}},
		{"empty token", "Controller secret", "unreadable or empty", func(t *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			path := filepath.Join(t.TempDir(), "empty-token")
			if err := os.WriteFile(path, nil, 0o400); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", path)
		}},
		{"health failure", "Controller connection", "health check failed", func(_ *testing.T, _, _ *string, sup *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			sup.healthErr = errors.New("offline")
		}},
		{"no config state", "Embedded Xray runtime", "waiting for its first", func(_ *testing.T, _, _ *string, sup *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			sup.status.State = "no-config"
		}},
		{"version mismatch", "Xray compatibility", "Compose selects", func(t *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			t.Setenv("XRAY_VERSION", "26.9.8")
		}},
		{"unverified version", "Xray compatibility", "outside the project's verified", func(t *testing.T, _, _ *string, sup *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			t.Setenv("XRAY_VERSION", "26.9.8")
			sup.status.XrayVersion = "Xray 26.9.8"
		}},
		{"missing active config", "Active Xray config", "active.json is missing", func(t *testing.T, _, config *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			if err := os.Remove(filepath.Join(*config, "active.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"validation failure", "Active Xray config", "Xray rejected", func(_ *testing.T, _, _ *string, sup *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			sup.validateErr = errors.New("invalid config")
		}},
		{"handler failure", "Xray Handler API", "could not be read", func(_ *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, handler *doctorHandlerStub) {
			handler.err = errors.New("inbound unavailable")
		}},
		{"UDP firewall", "Hysteria 2 UDP firewall", "public UDP reachability", func(t *testing.T, _, _ *string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub) {
			t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
		}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
			t.Setenv("XRAY_CONTROLLER_ADDR", "controller.test:10088")
			t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
			t.Setenv("XRAY_VERSION", "26.7.28")
			t.Setenv("XRAY_HYSTERIA2_ENABLED", "false")
			sup := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28"}}
			handler := &doctorHandlerStub{}
			testcase.mutate(t, &dataDir, &configDir, sup, handler)
			checks := collectDoctorChecks(context.Background(), dataDir, configDir, sup, handler, &doctorStatsStub{})
			if !doctorCheckContains(checks, testcase.checkName, testcase.wantDetail) {
				t.Fatalf("missing %s (%q) check: %+v", testcase.checkName, testcase.wantDetail, checks)
			}
		})
	}
}

func TestDoctorChecksExplainIncompleteSettingsAndWrongMasterKey(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		wantCheck  string
		wantDetail string
		mutate     func(*testing.T, string)
	}{
		{"incomplete target", "Application setup", "settings are incomplete", func(t *testing.T, dataDir string) {
			db, err := store.Open(t.Context(), filepath.Join(dataDir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			settings, err := db.GetSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			settings.RealityTarget = ""
			if err := db.UpdateSettings(t.Context(), settings); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid host", "Public host", "endpoint is invalid", func(t *testing.T, dataDir string) {
			db, err := store.Open(t.Context(), filepath.Join(dataDir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			settings, err := db.GetSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			settings.PublicHost = "bad host"
			if err := db.UpdateSettings(t.Context(), settings); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong master key", "Encrypted REALITY key", "decryption failed", func(t *testing.T, _ string) {
			t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("another-key-0123456789abcdef0000")))
		}},
		{"missing master key", "Encrypted REALITY key", "without a valid master key", func(t *testing.T, _ string) { t.Setenv("XRAY_EASY_MASTER_KEY", "") }},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
			t.Setenv("XRAY_CONTROLLER_ADDR", "controller.test:10088")
			t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
			testcase.mutate(t, dataDir)
			checks := collectDoctorChecks(context.Background(), dataDir, configDir, &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running"}}, &doctorHandlerStub{}, &doctorStatsStub{})
			if !doctorCheckContains(checks, testcase.wantCheck, testcase.wantDetail) {
				t.Fatalf("missing %s (%q) check: %+v", testcase.wantCheck, testcase.wantDetail, checks)
			}
		})
	}
}

func TestDoctorClassifiesIPv4AndRejectsInvalidWritableDirectory(t *testing.T) {
	if got := publicHostKind("203.0.113.5"); got != "IPv4 literal" {
		t.Fatalf("IPv4 host classification = %q", got)
	}
	root := t.TempDir()
	if err := probeWritableDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing directory was reported writable")
	}
	file := filepath.Join(root, "regular-file")
	if err := os.WriteFile(file, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeWritableDirectory(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("regular file writable-directory probe = %v", err)
	}
	if _, err := os.Stat("/proc"); err == nil {
		if err := probeWritableDirectory("/proc"); err == nil {
			t.Fatal("read-only proc filesystem was reported writable")
		}
	}
}

func TestProbeWritableDirectoryReportsCreateCloseAndRemoveErrors(t *testing.T) {
	root := t.TempDir()
	createErr := errors.New("create probe failed")
	if err := probeWritableDirectoryWith(root, func(string, string) (writableProbeFile, error) {
		return nil, createErr
	}, os.Remove); !errors.Is(err, createErr) {
		t.Fatalf("probe creation error = %v", err)
	}

	closeErr := errors.New("close probe failed")
	removedAfterClose := false
	err := probeWritableDirectoryWith(root, func(_, _ string) (writableProbeFile, error) {
		return doctorProbeFile{path: filepath.Join(root, "probe"), closeErr: closeErr}, nil
	}, func(string) error {
		removedAfterClose = true
		return nil
	})
	if !errors.Is(err, closeErr) || !removedAfterClose {
		t.Fatalf("probe close error/removal = %v, removed=%t", err, removedAfterClose)
	}

	removeErr := errors.New("remove probe failed")
	err = probeWritableDirectoryWith(root, func(_, _ string) (writableProbeFile, error) {
		return doctorProbeFile{path: filepath.Join(root, "probe")}, nil
	}, func(string) error { return removeErr })
	if !errors.Is(err, removeErr) {
		t.Fatalf("probe removal error = %v", err)
	}
}
