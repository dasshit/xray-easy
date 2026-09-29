package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"xray-easy/internal/diagnostics"
	"xray-easy/internal/domain"
	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/supervisor"
	"xray-easy/internal/xray"
	"xray-easy/internal/xrayapi"
)

type doctorLevel string

const (
	doctorPass doctorLevel = "PASS"
	doctorWarn doctorLevel = "WARN"
	doctorFail doctorLevel = "FAIL"
)

type doctorCheck struct {
	level  doctorLevel
	name   string
	detail string
	hint   string
}

var doctorVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$`)
var xrayReleasePattern = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)

type doctorSupervisor interface {
	Health(context.Context) error
	Status(context.Context) (supervisor.Status, error)
	Validate(context.Context, string, string) error
	ProbeTarget(context.Context, string, string) error
	ProbeIPv6(context.Context) error
}

type doctorBundleSupervisor interface {
	doctorSupervisor
	Logs(context.Context) ([]string, error)
}

type doctorHandler interface {
	Users(context.Context) ([]string, error)
}

type doctorStats interface {
	Poll(context.Context) ([]xrayapi.UserStats, error)
}

// runDoctorCLI dispatches state-preserving checks or explicitly requested
// support-bundle generation for the control plane and its Xray dependencies.
// It returns an error when any check fails so scripts can detect an unhealthy
// installation even when a diagnostic bundle was successfully saved.
func runDoctorCLI(ctx context.Context, args []string, dataDir, configDir string, out io.Writer) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "bundle" {
		return cliUsageError()
	}
	handler := xrayapi.NewHandlerClient(envOr("XRAY_API_LISTEN", "127.0.0.1:10085"))
	defer handler.Close()
	stats := xrayapi.NewStatsClient(envOr("XRAY_API_LISTEN", "127.0.0.1:10085"))
	defer stats.Close()
	sup := supervisor.Client{
		BaseURL:   envOr("XRAY_SUPERVISOR_URL", "http://127.0.0.1:10086"),
		TokenFile: envOr("XRAY_SUPERVISOR_TOKEN_FILE", "/run/secrets/xray_supervisor_token"),
	}
	if len(args) == 1 {
		return runDoctorBundle(ctx, dataDir, configDir, out, sup, handler, stats)
	}
	return runDoctor(ctx, dataDir, configDir, out, sup, handler, stats)
}

func runDoctor(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorSupervisor, handler doctorHandler, stats doctorStats) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	checks := collectDoctorChecks(ctx, dataDir, configDir, sup, handler, stats)
	failures, warnings := 0, 0
	writeDoctorHeader(out)
	if status, err := sup.Status(ctx); err == nil {
		fmt.Fprintf(out, "  Running Xray binary: %s\n", safeRuntimeXrayVersion(status.XrayVersion))
	} else {
		fmt.Fprintln(out, "  Running Xray binary: unavailable")
	}
	fmt.Fprintln(out, "Checks (no persistent changes)")
	for _, check := range checks {
		fmt.Fprintf(out, "%-5s %s: %s\n", check.level, check.name, check.detail)
		if check.hint != "" {
			fmt.Fprintf(out, "      Next: %s\n", check.hint)
		}
		switch check.level {
		case doctorFail:
			failures++
		case doctorWarn:
			warnings++
		}
	}
	if failures > 0 {
		fmt.Fprintf(out, "Result: FAIL (%d failure(s), %d warning(s))\n", failures, warnings)
		return fmt.Errorf("doctor found %d failing check(s)", failures)
	}
	fmt.Fprintf(out, "Result: PASS (%d warning(s))\n", warnings)
	return nil
}

func writeDoctorHeader(out io.Writer) {
	fmt.Fprintln(out, "Xray-easy doctor report")
	fmt.Fprintln(out, "Versions from active Compose environment:")
	fmt.Fprintf(out, "  Xray-easy build: %s (XRAY_EASY_VERSION)\n", safeDoctorVersion("XRAY_EASY_VERSION", "dev"))
	fmt.Fprintf(out, "  Xray image: %s (XRAY_VERSION)\n", safeDoctorVersion("XRAY_VERSION", "unknown"))
	fmt.Fprintf(out, "  Xray UDP public port: %s -> container UDP 8443\n", safeDoctorPort("XRAY_PUBLIC_PORT", "443"))
	fmt.Fprintln(out, "Host ports from active Compose environment:")
	fmt.Fprintf(out, "  Xray public TCP: %s -> container TCP 8443\n", safeDoctorPort("XRAY_PUBLIC_PORT", "443"))
	fmt.Fprintf(out, "  Web UI loopback: %s -> container TCP 8080\n", safeDoctorPort("XRAY_EASY_UI_PORT", "8080"))
}

func safeRuntimeXrayVersion(value string) string {
	match := xrayReleasePattern.FindString(value)
	if match == "" {
		return "unknown"
	}
	return match
}

func safeDoctorVersion(name, fallback string) string {
	value := envOr(name, fallback)
	if !doctorVersionPattern.MatchString(value) {
		return "invalid"
	}
	return value
}

func safeDoctorPort(name, fallback string) string {
	value := envOr(name, fallback)
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return "invalid"
	}
	return strconv.Itoa(port)
}

func runDoctorBundle(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorBundleSupervisor, handler doctorHandler, stats doctorStats) error {
	var report bytes.Buffer
	doctorErr := runDoctor(ctx, dataDir, configDir, &report, sup, handler, stats)
	if _, err := io.Copy(out, &report); err != nil {
		return fmt.Errorf("write doctor report: %w", err)
	}

	files := map[string][]byte{"doctor-report.txt": report.Bytes()}
	var notes []string
	extraCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err := sup.Status(extraCtx)
	if err != nil {
		statusJSON, marshalErr := json.MarshalIndent(map[string]any{"available": false, "error": diagnostics.Redact(err.Error())}, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("encode unavailable Xray status: %w", marshalErr)
		}
		files["xray-status.json"] = append(statusJSON, '\n')
		notes = append(notes, "Xray supervisor status could not be collected.")
	} else {
		status.LastError = diagnostics.Redact(status.LastError)
		status.LastExit = diagnostics.Redact(status.LastExit)
		statusJSON, marshalErr := json.MarshalIndent(status, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("encode Xray status: %w", marshalErr)
		}
		files["xray-status.json"] = append(statusJSON, '\n')
	}
	logs, logsErr := sup.Logs(extraCtx)
	if logsErr != nil {
		files["xray-errors.log"] = []byte("Could not collect Xray logs.\n")
		notes = append(notes, "Recent Xray logs could not be collected.")
	} else {
		if len(logs) > 100 {
			logs = logs[len(logs)-100:]
		}
		var safeLogs strings.Builder
		for _, line := range logs {
			if len(line) > 4096 {
				line = line[:4096] + " [truncated]"
			}
			safeLogs.WriteString(diagnostics.Redact(line))
			safeLogs.WriteByte('\n')
		}
		files["xray-errors.log"] = []byte(safeLogs.String())
	}

	activeConfig := filepath.Join(configDir, "active.json")
	if info, statErr := os.Lstat(activeConfig); statErr == nil && info.Mode().IsRegular() && info.Size() <= 2<<20 {
		config, readErr := os.ReadFile(activeConfig)
		if readErr == nil {
			if redacted, redactErr := diagnostics.RedactJSON(config); redactErr == nil {
				files["active-config.redacted.json"] = append(redacted, '\n')
			} else {
				notes = append(notes, "Active Xray configuration was omitted because it is not valid JSON.")
			}
		} else {
			notes = append(notes, "Active Xray configuration could not be read.")
		}
	} else if statErr != nil || !info.Mode().IsRegular() {
		notes = append(notes, "Active Xray configuration was not available.")
	} else {
		notes = append(notes, "Active Xray configuration was omitted because it exceeds 2 MiB.")
	}
	if len(notes) > 0 {
		files["bundle-notes.txt"] = []byte(strings.Join(notes, "\n") + "\n")
	}
	bundlePath, err := diagnostics.CreateBundle(dataDir, files, time.Now())
	if err != nil {
		return fmt.Errorf("create doctor bundle: %w", err)
	}
	fmt.Fprintf(out, "Bundle saved: %s\n", bundlePath)
	if doctorErr != nil {
		return fmt.Errorf("doctor checks failed; redacted report saved: %w", doctorErr)
	}
	return nil
}

func collectDoctorChecks(ctx context.Context, dataDir, configDir string, sup doctorSupervisor, handler doctorHandler, stats doctorStats) []doctorCheck {
	checks := make([]doctorCheck, 0, 12)
	appendCheck := func(level doctorLevel, name, detail, hint string) {
		checks = append(checks, doctorCheck{level: level, name: name, detail: detail, hint: hint})
	}

	masterKey, keyErr := loadMasterKey()
	if keyErr != nil {
		detail := "XRAY_EASY_MASTER_KEY is missing"
		if strings.TrimSpace(os.Getenv("XRAY_EASY_MASTER_KEY")) != "" {
			detail = "XRAY_EASY_MASTER_KEY is not valid base64 containing at least 32 bytes"
		}
		appendCheck(doctorFail, "Master key", detail, "Restore the original value in .env; generate a new key only for a brand-new installation.")
	} else {
		appendCheck(doctorPass, "Master key", "valid key is loaded", "")
	}
	if port, err := configuredPublicPort(); err != nil {
		appendCheck(doctorFail, "Public TCP port", "XRAY_PUBLIC_PORT is invalid", "Set XRAY_PUBLIC_PORT in .env to a port from 1 to 65535, then rerun Compose.")
	} else {
		appendCheck(doctorPass, "Public TCP port", fmt.Sprintf("port %d is configured", port), "")
	}

	if err := probeWritableDirectory(dataDir); err != nil {
		appendCheck(doctorFail, "Data volume", "not accessible for read/write", "Check ownership and permissions of the app_data volume.")
	} else {
		appendCheck(doctorPass, "Data volume", "directory is readable and writable", "")
	}
	if err := probeWritableDirectory(configDir); err != nil {
		appendCheck(doctorFail, "Xray config volume", "not accessible for read/write", "Check ownership and permissions of the xray_config volume.")
	} else if err := probeWritableDirectory(filepath.Join(configDir, "candidates")); err != nil {
		appendCheck(doctorFail, "Candidate config directory", "not accessible for read/write", "Check ownership and permissions of the xray_config volume.")
	} else {
		appendCheck(doctorPass, "Xray config volume", "active config is readable and candidate directory is writable", "")
	}

	databasePath := filepath.Join(dataDir, "state.db")
	databaseReady := false
	if err := store.ValidateDatabase(databasePath); err != nil {
		appendCheck(doctorFail, "SQLite database", "database is missing, unreadable, or has an incomplete schema", "Inspect xray-easy startup logs and the app_data volume.")
	} else {
		databaseReady = true
		appendCheck(doctorPass, "SQLite database", "database is readable and required tables are present", "")
	}

	var settingsReady bool
	var settingsErr error
	var settings store.Settings
	if databaseReady {
		settings, settingsErr = store.ReadSettingsFromDatabase(databasePath)
		switch {
		case errors.Is(settingsErr, store.ErrSettingsNotInitialized):
			appendCheck(doctorWarn, "Application setup", "initial Web UI setup is still pending", "Open the panel through the SSH tunnel and complete the first-run setup.")
		case settingsErr != nil:
			appendCheck(doctorFail, "Application setup", "node settings could not be read", "Inspect the SQLite database and xray-easy logs.")
		case settings.RealityPrivateKeyEnc == "" || settings.RealityTarget == "" || settings.RealitySNI == "" || settings.PublicHost == "":
			appendCheck(doctorWarn, "Application setup", "server settings are incomplete", "Complete the first-run setup in the Web UI.")
		default:
			settingsReady = true
			if err := domain.ValidatePublicHost(settings.PublicHost); err != nil {
				appendCheck(doctorFail, "Public host", "configured endpoint is invalid", "Enter an IPv4 address, IPv6 address without brackets, or DNS name in Settings.")
			} else {
				appendCheck(doctorPass, "Public host", publicHostKind(settings.PublicHost)+" configured", "")
			}
			if keyErr != nil {
				appendCheck(doctorFail, "Encrypted REALITY key", "cannot verify encrypted settings without a valid master key", "Correct XRAY_EASY_MASTER_KEY before using the existing state.")
			} else if _, err := secret.Open(masterKey, settings.RealityPrivateKeyEnc, "reality_private_key"); err != nil {
				appendCheck(doctorFail, "Encrypted REALITY key", "key decryption failed; the master key may not match this data volume", "Restore the original XRAY_EASY_MASTER_KEY from .env or a secure backup.")
			} else {
				appendCheck(doctorPass, "Encrypted REALITY key", "stored key decrypts successfully", "")
			}
		}
	}
	if !databaseReady {
		appendCheck(doctorWarn, "Application setup", "database state could not be inspected", "Start xray-easy and inspect its startup logs.")
	}

	tokenPath := envOr("XRAY_SUPERVISOR_TOKEN_FILE", "/run/secrets/xray_supervisor_token")
	tokenReady := false
	info, err := os.Lstat(tokenPath)
	switch {
	case err != nil:
		appendCheck(doctorFail, "Supervisor secret", "secret file is missing or inaccessible", "Check init-supervisor-secret and the xray_supervisor_token_data volume.")
	case !info.Mode().IsRegular():
		appendCheck(doctorFail, "Supervisor secret", "secret path is not a regular file", "Recreate the supervisor secret from the host-side secret file.")
	case info.Mode().Perm() != 0o400:
		appendCheck(doctorFail, "Supervisor secret", "expected mode 0400 inside the container", "Recreate the supervisor secret volume with the Compose init-supervisor-secret service.")
	default:
		contents, readErr := os.ReadFile(tokenPath)
		if readErr != nil || len(strings.TrimSpace(string(contents))) == 0 {
			appendCheck(doctorFail, "Supervisor secret", "secret file is unreadable or empty", "Check the secret file and xray_supervisor_token_data volume.")
		} else {
			tokenReady = true
			appendCheck(doctorPass, "Supervisor secret", "readable and mode is 0400", "")
		}
	}

	var supervisorStatus supervisor.Status
	supervisorReady := false
	if !tokenReady {
		appendCheck(doctorFail, "Supervisor connection", "not checked because the secret file is unavailable", "Fix the Supervisor secret check above.")
	} else if err := sup.Health(ctx); err != nil {
		appendCheck(doctorFail, "Supervisor connection", "authenticated health check failed", "Check xray container health, the supervisor URL, and the shared secret.")
	} else {
		supervisorStatus, err = sup.Status(ctx)
		if err != nil {
			appendCheck(doctorFail, "Supervisor status", "status request failed", "Inspect xray container logs and verify the supervisor API is healthy.")
		} else {
			switch supervisorStatus.State {
			case "running":
				supervisorReady = true
				appendCheck(doctorPass, "Supervisor status", "Xray process is running", "")
			case "no-config":
				supervisorReady = true
				appendCheck(doctorWarn, "Supervisor status", "Xray is waiting for its first active configuration", "Complete the first-run setup in the Web UI.")
			default:
				appendCheck(doctorFail, "Supervisor status", "Xray process is not running", "Inspect xray container logs and the active Xray configuration.")
			}
			runtimeVersion := safeRuntimeXrayVersion(supervisorStatus.XrayVersion)
			configuredVersion := safeRuntimeXrayVersion(envOr("XRAY_VERSION", ""))
			switch {
			case runtimeVersion == "unknown":
				appendCheck(doctorWarn, "Xray compatibility", "supervisor could not identify the running Xray binary version", "Rebuild and recreate the Xray container, then rerun doctor.")
			case configuredVersion != "unknown" && configuredVersion != runtimeVersion:
				appendCheck(doctorWarn, "Xray compatibility", fmt.Sprintf("Compose selects %s but the running binary is %s", configuredVersion, runtimeVersion), "Rebuild and recreate the Xray container so its binary matches XRAY_VERSION.")
			case runtimeVersion != xray.VerifiedCoreVersion:
				appendCheck(doctorWarn, "Xray compatibility", fmt.Sprintf("Xray %s is outside the project's verified compatibility matrix", runtimeVersion), fmt.Sprintf("Use the verified XRAY_VERSION=%s or verify this exact Xray and V2RAGE combination before relying on it.", xray.VerifiedCoreVersion))
			default:
				appendCheck(doctorPass, "Xray compatibility", fmt.Sprintf("runtime binary matches the verified Xray %s compatibility entry", xray.VerifiedCoreVersion), "")
			}
		}
	}

	if !supervisorReady {
		appendCheck(doctorWarn, "IPv6 egress", "probe skipped because Xray is unavailable", "Fix the supervisor and Xray status checks above.")
	} else if err := sup.ProbeIPv6(ctx); err != nil {
		appendCheck(doctorWarn, "IPv6 egress", "outbound IPv6 TCP probe failed", "Check IPv6 routing and firewall rules for the Docker host and egress network. IPv4 traffic can still work.")
	} else {
		appendCheck(doctorPass, "IPv6 egress", "outbound IPv6 TCP connection succeeded from the Xray container", "")
	}

	activeConfig := filepath.Join(configDir, "active.json")
	if _, err := os.Stat(activeConfig); errors.Is(err, os.ErrNotExist) {
		level := doctorFail
		hint := "Restore the active config from a backup or complete first-run setup."
		if !settingsReady {
			level = doctorWarn
			hint = "Complete the first-run setup in the Web UI."
		}
		appendCheck(level, "Active Xray config", "active.json is missing", hint)
	} else if err != nil {
		appendCheck(doctorFail, "Active Xray config", "active.json cannot be inspected", "Check the xray_config volume permissions.")
	} else if !supervisorReady {
		appendCheck(doctorWarn, "Active Xray config", "validation skipped because supervisor is unavailable", "Fix the supervisor checks above.")
	} else if supervisorStatus.State == "no-config" {
		appendCheck(doctorWarn, "Active Xray config", "supervisor has no active configuration", "Complete the first-run setup in the Web UI.")
	} else if err := sup.Validate(ctx, activeConfig, "doctor"); err != nil {
		appendCheck(doctorFail, "Active Xray config", "Xray rejected the active configuration", "Review xray container logs and correct the configuration in the Web UI.")
	} else {
		appendCheck(doctorPass, "Active Xray config", "Xray config test passed", "")
	}

	if !settingsReady {
		appendCheck(doctorWarn, "Xray Handler API", "inbound check skipped until server setup is complete", "Complete the first-run setup in the Web UI.")
		appendCheck(doctorWarn, "Xray statistics API", "stats check skipped until server setup is complete", "Complete the first-run setup in the Web UI.")
	} else if !supervisorReady {
		appendCheck(doctorWarn, "Xray API", "gRPC checks skipped because Xray is unavailable", "Fix the supervisor and Xray status checks above.")
	} else {
		if err := sup.ProbeTarget(ctx, settings.RealityTarget, settings.RealitySNI); err != nil {
			appendCheck(doctorFail, "REALITY target", "DNS/TLS probe from the Xray network failed", "Verify the configured target and SNI, DNS resolution, outbound TCP access, and the VDS system clock.")
		} else {
			appendCheck(doctorPass, "REALITY target", "DNS resolution and TLS connection from the Xray network succeeded", "")
		}
		if _, err := handler.Users(ctx); err != nil {
			appendCheck(doctorFail, "Xray Handler API", "inbound users could not be read", "Verify the Xray HandlerService and vless-reality inbound in the active config.")
		} else {
			appendCheck(doctorPass, "Xray Handler API", "inbound HandlerService is responding", "")
		}
		if _, err := stats.Poll(ctx); err != nil {
			appendCheck(doctorWarn, "Xray statistics API", "GetUsersStats is unavailable; device traffic counters may not update", "Check whether the pinned XRAY_VERSION supports the StatsService method used by this release.")
		} else {
			appendCheck(doctorPass, "Xray statistics API", "StatsService is responding", "")
		}
	}
	appendCheck(doctorWarn, "Inbound firewall", "public TCP reachability cannot be checked from inside the Compose network", fmt.Sprintf("Allow inbound TCP %s for IPv4 and IPv6 in the VDS firewall/security group and verify a VLESS client connection.", envOr("XRAY_PUBLIC_PORT", "443")))
	if hysteria2Enabled() {
		hint := fmt.Sprintf("Allow inbound UDP %s for IPv4 and IPv6 and verify a Hysteria 2 client connection.", envOr("XRAY_PUBLIC_PORT", "443"))
		if mode := envOr("XRAY_HYSTERIA2_TLS_MODE", xray.HysteriaTLSLegacy); mode == xray.HysteriaTLSSelfSigned || mode == xray.HysteriaTLSLegacy {
			hint += " mkcert mode uses insecure=1, so the client does not authenticate the server certificate."
		} else {
			hint += " The supplied certificate must be trusted and cover the Hysteria 2 TLS server name."
		}
		appendCheck(doctorWarn, "Hysteria 2 UDP firewall", "public UDP reachability cannot be checked from inside the Compose network", hint)
	}

	return checks
}

func publicHostKind(host string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(host))
	if err == nil {
		if address.Is6() {
			return "IPv6 literal"
		}
		return "IPv4 literal"
	}
	return "DNS name"
}

func probeWritableDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	probe, err := os.CreateTemp(path, ".xray-easy-doctor-*")
	if err != nil {
		return err
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return err
	}
	if err := os.Remove(probePath); err != nil {
		return err
	}
	return nil
}
