package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestDoctorAdditionalRuntimeAndOptionalTransportFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		check     string
		level     doctorLevel
		configure func(*testing.T, string, string, *doctorXrayRuntimeStub, *doctorHandlerStub, *doctorStatsStub)
	}{
		{
			name:  "runtime status error",
			check: "Xray runtime status",
			level: doctorFail,
			configure: func(_ *testing.T, _, _ string, runtime *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				runtime.statusErr = errors.New("status unavailable")
			},
		},
		{
			name:  "runtime stopped",
			check: "Embedded Xray runtime",
			level: doctorFail,
			configure: func(_ *testing.T, _, _ string, runtime *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				runtime.status.State = "stopped"
			},
		},
		{
			name:  "ipv6 probe error",
			check: "IPv6 egress",
			level: doctorWarn,
			configure: func(_ *testing.T, _, _ string, runtime *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				runtime.ipv6Err = errors.New("no route")
			},
		},
		{
			name:  "target probe error",
			check: "REALITY target",
			level: doctorFail,
			configure: func(_ *testing.T, _, _ string, runtime *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				runtime.probeErr = errors.New("target unavailable")
			},
		},
		{
			name:  "statistics unavailable",
			check: "Embedded statistics capability",
			level: doctorWarn,
			configure: func(_ *testing.T, _, _ string, runtime *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				runtime.status.StatsAvailable = false
			},
		},
		{
			name:  "telemetry polling error",
			check: "Embedded Xray telemetry",
			level: doctorWarn,
			configure: func(_ *testing.T, _, _ string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub, stats *doctorStatsStub) {
				stats.err = errors.New("telemetry unavailable")
			},
		},
		{
			name:  "invalid Shadowsocks port",
			check: "Shadowsocks port",
			level: doctorFail,
			configure: func(t *testing.T, _, _ string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
				t.Setenv("XRAY_SHADOWSOCKS_PORT", "443")
			},
		},
		{
			name:  "valid Shadowsocks port",
			check: "Shadowsocks TCP/UDP port",
			level: doctorPass,
			configure: func(t *testing.T, _, _ string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
				t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
			},
		},
		{
			name:  "invalid Trojan port",
			check: "Trojan TCP port",
			level: doctorFail,
			configure: func(t *testing.T, _, _ string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				t.Setenv("XRAY_TROJAN_ENABLED", "true")
				t.Setenv("XRAY_TROJAN_PORT", "9443")
			},
		},
		{
			name:  "valid Trojan port and header",
			check: "Trojan TCP port",
			level: doctorPass,
			configure: func(t *testing.T, _, _ string, _ *doctorXrayRuntimeStub, _ *doctorHandlerStub, _ *doctorStatsStub) {
				t.Setenv("XRAY_TROJAN_ENABLED", "true")
				t.Setenv("XRAY_TROJAN_PORT", "10443")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			setDoctorEnvironment(t, key)
			runtime := &doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 3, StatsAvailable: true}}
			handler := &doctorHandlerStub{}
			stats := &doctorStatsStub{}
			test.configure(t, dataDir, configDir, runtime, handler, stats)
			checks := collectDoctorChecks(context.Background(), dataDir, configDir, runtime, handler, stats)
			if !hasDoctorCheck(checks, test.check, test.level) {
				t.Fatalf("missing %s %s check: %+v", test.level, test.check, checks)
			}
		})
	}
}

func TestDoctorAdditionalAmneziaWGFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		host      string
		port      string
		clientErr error
		awg       *doctorAWGStub
		check     string
	}{
		{name: "invalid host", host: "not a host", port: "1234", awg: &doctorAWGStub{}, check: "AmneziaWG public endpoint"},
		{name: "invalid port", host: "vpn.example.test", port: "0", awg: &doctorAWGStub{}, check: "AmneziaWG public endpoint"},
		{name: "controller error", host: "vpn.example.test", port: "1234", clientErr: errors.New("unavailable"), check: "AmneziaWG control API"},
		{name: "client missing", host: "vpn.example.test", port: "1234", check: "AmneziaWG control API"},
		{name: "status error", host: "vpn.example.test", port: "1234", awg: &doctorAWGStub{statusErr: errors.New("offline")}, check: "AmneziaWG service"},
		{name: "interface stopped", host: "vpn.example.test", port: "1234", awg: &doctorAWGStub{status: domain.AmneziaWGStatus{}}, check: "AmneziaWG service"},
		{name: "peer list error", host: "vpn.example.test", port: "1234", awg: &doctorAWGStub{status: domain.AmneziaWGStatus{Running: true}, peersErr: errors.New("state unavailable")}, check: "AmneziaWG peers"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			setDoctorEnvironment(t, key)
			t.Setenv("AWG_PUBLIC_HOST", test.host)
			t.Setenv("AWG_PUBLIC_PORT", test.port)
			var awg doctorAWG
			if test.awg != nil {
				awg = test.awg
			}
			checks := collectDoctorChecksWithAWG(
				context.Background(), dataDir, configDir,
				&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 3, StatsAvailable: true}},
				&doctorHandlerStub{}, &doctorStatsStub{}, awg, test.clientErr,
			)
			if !hasDoctorCheck(checks, test.check, doctorFail) {
				t.Fatalf("missing %s failure check: %+v", test.check, checks)
			}
		})
	}
}

func TestDoctorLeasePolicyFailureAndConnectedUnreadyTelemetry(t *testing.T) {
	for _, test := range []struct {
		name       string
		maxActive  string
		grace      string
		health     leaseHealthStatus
		wantDetail string
	}{
		{name: "invalid duration", maxActive: "2", grace: "soon", wantDetail: "environment values are invalid"},
		{name: "unsupported maximum", maxActive: "3", grace: "30s", wantDetail: "outside supported limits"},
		{name: "connected but telemetry is not ready", maxActive: "2", grace: "30s", health: leaseHealthStatus{ControllerStreamConnected: true}, wantDetail: "telemetry is not ready"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			setDoctorEnvironment(t, key)
			t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "true")
			t.Setenv("XRAY_LEASE_MAX_ACTIVE", test.maxActive)
			t.Setenv("XRAY_LEASE_GRACE", test.grace)
			previousProbe := leaseHealthProbe
			leaseHealthProbe = func(context.Context, string) (leaseHealthStatus, error) { return test.health, nil }
			t.Cleanup(func() { leaseHealthProbe = previousProbe })
			checks := collectDoctorChecks(context.Background(), dataDir, configDir,
				&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 3, StatsAvailable: true}},
				&doctorHandlerStub{}, &doctorStatsStub{})
			if !doctorCheckContains(checks, "Xray lease policy", test.wantDetail) && !doctorCheckContains(checks, "Xray lease service", test.wantDetail) {
				t.Fatalf("missing lease diagnostic %q: %+v", test.wantDetail, checks)
			}
		})
	}
}

func TestDoctorDetectsUnreadableActivePathAndMalformedTrojanConfig(t *testing.T) {
	t.Run("active config path cannot be inspected", func(t *testing.T) {
		dataDir, configDir, key := prepareDoctorState(t, true)
		setDoctorEnvironment(t, key)
		if err := os.RemoveAll(configDir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configDir, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		checks := collectDoctorChecks(context.Background(), dataDir, configDir,
			&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 3}},
			&doctorHandlerStub{}, &doctorStatsStub{})
		if !doctorCheckContains(checks, "Active Xray config", "cannot be inspected") {
			t.Fatalf("active config path error was not reported: %+v", checks)
		}
	})

	t.Run("malformed active Trojan config", func(t *testing.T) {
		dataDir, configDir, key := prepareDoctorState(t, true)
		setDoctorEnvironment(t, key)
		t.Setenv("XRAY_TROJAN_ENABLED", "true")
		if err := os.WriteFile(filepath.Join(configDir, "active.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		checks := collectDoctorChecks(context.Background(), dataDir, configDir,
			&doctorXrayRuntimeStub{status: domain.XrayRuntimeStatus{State: "running", XrayVersion: "Xray 26.7.28", ActiveRevision: 3}},
			&doctorHandlerStub{}, &doctorStatsStub{})
		if !doctorCheckContains(checks, "Trojan inbound", "could not be inspected") {
			t.Fatalf("malformed Trojan config was not reported: %+v", checks)
		}
	})
}

func TestDoctorActiveConfigComparatorsRejectMalformedAndMismatchedTags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := activeConfigHasInbound(path, "trojan", "trojan-tls"); err == nil {
		t.Fatal("malformed active config was accepted")
	}
	if err := sameSortedStrings([]string{"one"}, []string{"one", "two"}); err == nil || !strings.Contains(err.Error(), "count differs") {
		t.Fatalf("different inbound tag counts = %v", err)
	}
}

func setDoctorEnvironment(t *testing.T, key []byte) {
	t.Helper()
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_CONTROLLER_ADDR", "controller.test:10088")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", writeControllerToken(t, 0o400))
	t.Setenv("XRAY_VERSION", "26.7.28")
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "false")
	t.Setenv("XRAY_TROJAN_ENABLED", "false")
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "false")
	t.Setenv("XRAY_LEASE_SERVICE_ENABLED", "false")
	t.Setenv("COMPOSE_PROFILES", "")
}

var _ = strings.TrimSpace
