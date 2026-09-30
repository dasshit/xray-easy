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
	"sort"
	"strconv"
	"strings"
	"time"

	"xray-easy/internal/controller"
	"xray-easy/internal/diagnostics"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
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

type doctorAWG interface {
	Status(context.Context) (domain.AmneziaWGStatus, error)
	ListPeers(context.Context) ([]domain.AmneziaWGPeer, error)
}

// runDoctorCLI dispatches state-preserving checks or explicitly requested
// support-bundle generation for the control plane and its Xray dependencies.
// It returns an error when any check fails so scripts can detect an unhealthy
// installation even when a diagnostic bundle was successfully saved.
func runDoctorCLI(ctx context.Context, args []string, dataDir, configDir string, out io.Writer) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "bundle" {
		return cliUsageError()
	}
	var handler doctorHandler
	var stats doctorStats
	var sup doctorBundleSupervisor
	var closeRuntime func()
	var awg doctorAWG
	var awgErr error
	address := strings.TrimSpace(os.Getenv("XRAY_CONTROLLER_ADDR"))
	if address == "" {
		return errors.New("XRAY_CONTROLLER_ADDR must be configured; direct runtime connections from the backend are disabled")
	}
	client, err := controller.Dial(address, envOr("XRAY_CONTROLLER_TOKEN_FILE", "/run/controller-auth/controller.token"))
	if err != nil {
		return fmt.Errorf("initialize Controller gRPC client: %w", err)
	}
	sup, handler, stats, closeRuntime = client, client, client, func() { _ = client.Close() }
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		awg = client.AWG()
	}
	defer closeRuntime()
	if len(args) == 1 {
		return runDoctorBundleWithAWG(ctx, dataDir, configDir, out, sup, handler, stats, awg, awgErr)
	}
	return runDoctorWithAWG(ctx, dataDir, configDir, out, sup, handler, stats, awg, awgErr)
}

func runDoctor(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorSupervisor, handler doctorHandler, stats doctorStats) error {
	return runDoctorWithAWG(ctx, dataDir, configDir, out, sup, handler, stats, nil, nil)
}

func runDoctorWithAWG(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorSupervisor, handler doctorHandler, stats doctorStats, awg doctorAWG, awgErr error) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	checks := collectDoctorChecksWithAWG(ctx, dataDir, configDir, sup, handler, stats, awg, awgErr)
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
	fmt.Fprintf(out, "  VMess TCP: %s -> container TCP 8444\n", safeDoctorPort("XRAY_VMESS_PORT", "9443"))
	fmt.Fprintf(out, "  Web UI loopback: %s -> container TCP 8080\n", safeDoctorPort("XRAY_EASY_UI_PORT", "8080"))
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		fmt.Fprintf(out, "  AmneziaWG public UDP: %s -> container UDP 51820\n", safeDoctorPort("AWG_PUBLIC_PORT", "1234"))
	}
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

func doctorConfiguredPort(name, fallback string) (int, error) {
	port, err := strconv.Atoi(envOr(name, fallback))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return port, nil
}

func runDoctorBundle(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorBundleSupervisor, handler doctorHandler, stats doctorStats) error {
	return runDoctorBundleWithAWG(ctx, dataDir, configDir, out, sup, handler, stats, nil, nil)
}

func runDoctorBundleWithAWG(ctx context.Context, dataDir, configDir string, out io.Writer, sup doctorBundleSupervisor, handler doctorHandler, stats doctorStats, awg doctorAWG, awgErr error) error {
	var report bytes.Buffer
	doctorErr := runDoctorWithAWG(ctx, dataDir, configDir, &report, sup, handler, stats, awg, awgErr)
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
	return collectDoctorChecksWithAWG(ctx, dataDir, configDir, sup, handler, stats, nil, nil)
}

func collectDoctorChecksWithAWG(ctx context.Context, dataDir, configDir string, sup doctorSupervisor, handler doctorHandler, stats doctorStats, awg doctorAWG, awgErr error) []doctorCheck {
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
	if port, err := configuredVMessPort(); err != nil {
		appendCheck(doctorFail, "VMess TCP port", err.Error(), "Set XRAY_VMESS_PORT to a free host port distinct from XRAY_PUBLIC_PORT and XRAY_EASY_UI_PORT, then rerun Compose.")
	} else {
		appendCheck(doctorPass, "VMess TCP port", fmt.Sprintf("port %d is configured", port), "")
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

	controllerConfigured := strings.TrimSpace(os.Getenv("XRAY_CONTROLLER_ADDR")) != ""
	// Tests and embedded doctor callers may inject fake runtime adapters without
	// a Controller address. The executable always requires Controller config in
	// runDoctorCLI, so secret validation is meaningful whenever it is configured.
	controllerTokenReady := true
	if controllerConfigured {
		controllerTokenPath := envOr("XRAY_CONTROLLER_TOKEN_FILE", "/run/controller-auth/controller.token")
		controllerInfo, controllerErr := os.Lstat(controllerTokenPath)
		switch {
		case controllerErr != nil:
			controllerTokenReady = false
			appendCheck(doctorFail, "Controller secret", "secret file is missing or inaccessible", "Check init-controller-token and the controller_token volume.")
		case !controllerInfo.Mode().IsRegular():
			controllerTokenReady = false
			appendCheck(doctorFail, "Controller secret", "secret path is not a regular file", "Recreate the Controller token volume through Compose.")
		case controllerInfo.Mode().Perm() != 0o400:
			controllerTokenReady = false
			appendCheck(doctorFail, "Controller secret", "expected mode 0400 inside the container", "Recreate the Controller token volume through Compose.")
		default:
			contents, readErr := os.ReadFile(controllerTokenPath)
			if readErr != nil || len(strings.TrimSpace(string(contents))) == 0 {
				controllerTokenReady = false
				appendCheck(doctorFail, "Controller secret", "secret file is unreadable or empty", "Check init-controller-token and the controller_token volume.")
			} else {
				appendCheck(doctorPass, "Controller secret", "readable and mode is 0400", "")
			}
		}
	}

	var supervisorStatus supervisor.Status
	supervisorReady := false
	if !controllerTokenReady {
		appendCheck(doctorFail, "Controller connection", "not checked because the secret file is unavailable", "Fix the Controller secret check above.")
	} else if err := sup.Health(ctx); err != nil {
		appendCheck(doctorFail, "Controller connection", "authenticated health check failed", "Check controller container health, its private address/token, and the Xray runtime dependency.")
	} else {
		appendCheck(doctorPass, "Controller connection", "authenticated runtime health check succeeded", "")
		supervisorStatus, err = sup.Status(ctx)
		if err != nil {
			appendCheck(doctorFail, "Xray runtime status", "status request failed", "Inspect xray and Controller container logs, then verify the private runtime API is healthy.")
		} else {
			statusCheckName := "Supervisor status"
			if supervisorStatus.Protocol == "embedded-core" {
				statusCheckName = "Embedded Xray runtime"
			}
			switch supervisorStatus.State {
			case "running":
				supervisorReady = true
				appendCheck(doctorPass, statusCheckName, "Xray core is running", "")
			case "no-config":
				supervisorReady = true
				appendCheck(doctorWarn, statusCheckName, "Xray is waiting for its first active configuration", "Complete the first-run setup in the Web UI.")
			default:
				appendCheck(doctorFail, statusCheckName, "Xray core is not running", "Inspect xray container logs and the active Xray configuration.")
			}
			runtimeVersion := safeRuntimeXrayVersion(supervisorStatus.XrayVersion)
			configuredVersion := safeRuntimeXrayVersion(envOr("XRAY_VERSION", ""))
			switch {
			case runtimeVersion == "unknown":
				appendCheck(doctorWarn, "Xray compatibility", "runtime could not identify the running Xray core version", "Rebuild and recreate the Xray container, then rerun doctor.")
			case configuredVersion != "unknown" && configuredVersion != runtimeVersion:
				appendCheck(doctorWarn, "Xray compatibility", fmt.Sprintf("Compose selects %s but the running binary is %s", configuredVersion, runtimeVersion), "Rebuild and recreate the Xray container so its binary matches XRAY_VERSION.")
			case runtimeVersion != xray.VerifiedCoreVersion:
				appendCheck(doctorWarn, "Xray compatibility", fmt.Sprintf("Xray %s is outside the project's verified compatibility matrix", runtimeVersion), fmt.Sprintf("Use the verified XRAY_VERSION=%s or verify this exact Xray and V2RAGE combination before relying on it.", xray.VerifiedCoreVersion))
			default:
				appendCheck(doctorPass, "Xray compatibility", fmt.Sprintf("runtime binary matches the verified Xray %s compatibility entry", xray.VerifiedCoreVersion), "")
			}
			if supervisorStatus.Protocol == "embedded-core" {
				if supervisorStatus.ActiveRevision > 0 {
					appendCheck(doctorPass, "Embedded config revision", fmt.Sprintf("runtime has applied revision %d", supervisorStatus.ActiveRevision), "")
				} else {
					appendCheck(doctorWarn, "Embedded config revision", "runtime has not applied a persisted configuration revision yet", "Complete first-run setup in the Web UI, then refresh diagnostics.")
				}
				if err := matchEmbeddedInboundTags(filepath.Join(configDir, "active.json"), supervisorStatus.InboundTags); err != nil {
					appendCheck(doctorFail, "Embedded inbound tags", "runtime inbound tags do not match active.json", "Apply the active configuration again and inspect Controller/Xray runtime logs.")
				} else {
					appendCheck(doctorPass, "Embedded inbound tags", "runtime reports the same supported inbound tags as active.json", "")
				}
				if supervisorStatus.StatsAvailable {
					appendCheck(doctorPass, "Embedded statistics capability", "runtime reports per-user statistics support", "")
				} else {
					appendCheck(doctorWarn, "Embedded statistics capability", "runtime reports per-user statistics as unavailable", "Verify the active Xray stats and policy configuration, then rebuild with the verified Xray version.")
				}
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
		appendCheck(doctorWarn, "Active Xray config", "validation skipped because the Xray runtime is unavailable", "Fix the runtime checks above.")
	} else if supervisorStatus.State == "no-config" {
		appendCheck(doctorWarn, "Active Xray config", "supervisor has no active configuration", "Complete the first-run setup in the Web UI.")
	} else {
		operationID, operationErr := interaction.NewRequestID()
		if operationErr != nil {
			appendCheck(doctorFail, "Active Xray config", "could not create a validation operation ID", "Check system entropy and rerun doctor.")
		} else {
			revision := supervisorStatus.ActiveRevision
			if revision < 1 {
				// Config validation is read-only. A positive sentinel keeps older
				// runtimes with no persisted revision compatible with Controller.
				revision = 1
			}
			validationContext := interaction.WithStateRevision(ctx, revision)
			if err := sup.Validate(validationContext, activeConfig, operationID); err != nil {
				appendCheck(doctorFail, "Active Xray config", "Xray rejected the active configuration", "Review xray container logs and correct the configuration in the Web UI.")
			} else {
				appendCheck(doctorPass, "Active Xray config", "Xray config test passed", "")
			}
		}
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
	appendCheck(doctorWarn, "Inbound firewall", "public TCP reachability cannot be checked from inside the Compose network", fmt.Sprintf("Allow inbound TCP %s (VLESS) and TCP %s (VMess, when used) for IPv4 and IPv6 in the VDS firewall/security group; verify a client connection.", envOr("XRAY_PUBLIC_PORT", "443"), envOr("XRAY_VMESS_PORT", "9443")))
	if hysteria2Enabled() {
		hint := fmt.Sprintf("Allow inbound UDP %s for IPv4 and IPv6 and verify a Hysteria 2 client connection.", envOr("XRAY_PUBLIC_PORT", "443"))
		if mode := envOr("XRAY_HYSTERIA2_TLS_MODE", xray.HysteriaTLSLegacy); mode == xray.HysteriaTLSSelfSigned || mode == xray.HysteriaTLSLegacy {
			hint += " mkcert mode uses insecure=1, so the client does not authenticate the server certificate."
		} else {
			hint += " The supplied certificate must be trusted and cover the Hysteria 2 TLS server name."
		}
		appendCheck(doctorWarn, "Hysteria 2 UDP firewall", "public UDP reachability cannot be checked from inside the Compose network", hint)
	}
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		if _, hostErr := domain.NormalizePublicHost(os.Getenv("AWG_PUBLIC_HOST")); hostErr != nil {
			appendCheck(doctorFail, "AmneziaWG public endpoint", "AWG_PUBLIC_HOST is invalid", "Set AWG_PUBLIC_HOST to the public IP address or DNS name in .env, then rerun the installer.")
		} else if _, portErr := doctorConfiguredPort("AWG_PUBLIC_PORT", "1234"); portErr != nil {
			appendCheck(doctorFail, "AmneziaWG public endpoint", "AWG_PUBLIC_PORT is invalid", "Set AWG_PUBLIC_PORT to a UDP port from 1 to 65535 in .env, then rerun the installer.")
		} else if awgErr != nil {
			appendCheck(doctorFail, "AmneziaWG control API", "configured service cannot be reached", "Check the Controller and awg container health, then inspect their private gRPC logs.")
		} else if awg == nil {
			appendCheck(doctorFail, "AmneziaWG control API", "client is not configured", "Check the Controller configuration and AWG_PUBLIC_HOST in the Compose environment.")
		} else {
			status, statusErr := awg.Status(ctx)
			if statusErr != nil {
				appendCheck(doctorFail, "AmneziaWG service", "authenticated status request failed", "Check awg container health, its gRPC listener, and the shared control token.")
			} else if !status.Running {
				appendCheck(doctorFail, "AmneziaWG service", "AmneziaWG interface is not running", "Inspect awg container logs and verify /dev/net/tun and NET_ADMIN permissions.")
			} else {
				peers, peersErr := awg.ListPeers(ctx)
				if peersErr != nil {
					appendCheck(doctorFail, "AmneziaWG peers", "peer state could not be read", "Inspect awg service logs and its persistent awg_data volume.")
				} else {
					appendCheck(doctorPass, "AmneziaWG service", fmt.Sprintf("interface is running; %d peer(s) are configured", len(peers)), "")
				}
			}
		}
		appendCheck(doctorWarn, "AmneziaWG UDP firewall", "public UDP reachability cannot be checked from inside the Compose network", fmt.Sprintf("Allow inbound UDP %s for IPv4 and IPv6 in the VDS firewall/security group, then verify an AmneziaWG client connection.", safeDoctorPort("AWG_PUBLIC_PORT", "1234")))
	}

	return checks
}

func matchEmbeddedInboundTags(configPath string, runtimeTags []string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var configuration struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &configuration); err != nil {
		return err
	}
	expected := make([]string, 0, len(configuration.Inbounds))
	for _, inbound := range configuration.Inbounds {
		if inbound.Protocol != "vless" && inbound.Protocol != "vmess" && inbound.Protocol != "hysteria" {
			continue
		}
		if strings.TrimSpace(inbound.Tag) == "" {
			return errors.New("supported inbound tag is empty")
		}
		expected = append(expected, strings.TrimSpace(inbound.Tag))
	}
	return sameSortedStrings(expected, runtimeTags)
}

func sameSortedStrings(left, right []string) error {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for index := 1; index < len(left); index++ {
		if left[index] == left[index-1] {
			return errors.New("active configuration contains duplicate inbound tags")
		}
	}
	for index := 1; index < len(right); index++ {
		if right[index] == right[index-1] {
			return errors.New("runtime reports duplicate inbound tags")
		}
	}
	if len(left) != len(right) {
		return errors.New("inbound tag count differs")
	}
	for index := range left {
		if left[index] != right[index] {
			return errors.New("inbound tags differ")
		}
	}
	return nil
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
