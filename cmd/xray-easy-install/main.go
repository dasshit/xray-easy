// Package main provides the interactive Xray-easy installation wizard.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"xray-easy/internal/domain"
)

const (
	// defaultVersion is an internal package constant.
	defaultVersion = "26.7.28"
	// defaultProject is an internal package constant.
	defaultProject = "xray-easy"
	// legacyProject is an internal package constant.
	legacyProject = "xray-easy-stage1"
	// startupRecoveryCommands is an internal package constant.
	startupRecoveryCommands = `Useful commands from the repository directory:
  docker compose -f compose.yaml ps --all
  docker compose -f compose.yaml logs --tail=100 --timestamps
  docker compose -f compose.yaml exec -T control-plane xray-easy doctor
  docker compose -f compose.yaml exec -T control-plane xray-easy doctor bundle

If xray-easy is stopped, create a report with a one-off container:
  docker compose -f compose.yaml run --rm --no-deps control-plane doctor bundle`
)

// configuration is an internal type used by the package.
type configuration struct {
	project            string
	version            string
	public             int
	vmess              int
	shadowsocks        int
	shadowsocksEnabled bool
	shadowsocksMethod  string
	shadowsocksNetwork string
	trojan             int
	trojanEnabled      bool
	ui                 int
	hysteriaEnabled    bool
	hysteriaMode       string
	hysteriaCertIP     string
	hysteriaServerName string
	hysteriaCertSource string
	hysteriaKeySource  string
	awgEnabled         bool
	awgPublicHost      string
	awgPublicPort      int
	leaseEnabled       bool
}

// commandRunner is an internal type used by the package.
type commandRunner interface {
	// run defines part of the interface contract.
	run(context.Context, string, bool, ...string) error
	// capture defines part of the interface contract.
	capture(context.Context, string, ...string) (string, error)
}

// dockerRunner is an internal type used by the package.
type dockerRunner struct{ output io.Writer }

// run runs the requested operation.
func (r dockerRunner) run(ctx context.Context, dir string, visible bool, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	cmd.Env = composeEnvironment()
	var captured strings.Builder
	if visible {
		cmd.Stdout = r.output
		cmd.Stderr = r.output
	} else {
		cmd.Stdout = &captured
		cmd.Stderr = &captured
	}
	if err := cmd.Run(); err != nil {
		if visible {
			return fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(captured.String()))
	}
	return nil
}

// capture performs the operation represented by its name.
func (r dockerRunner) capture(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	cmd.Env = composeEnvironment()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

// Let Compose read these settings from the local .env, even when the shell has
// different XRAY_* or project values exported.
func composeEnvironment() []string {
	excluded := map[string]bool{
		"COMPOSE_PROJECT_NAME":           true,
		"COMPOSE_ENV_FILES":              true,
		"COMPOSE_DISABLE_ENV_FILE":       true,
		"XRAY_EASY_PROJECT_NAME":         true,
		"XRAY_EASY_IMAGE_NAMESPACE":      true,
		"XRAY_EASY_IMAGE_TAG":            true,
		"XRAY_VERSION":                   true,
		"XRAY_PUBLIC_PORT":               true,
		"XRAY_VMESS_PORT":                true,
		"XRAY_SHADOWSOCKS_PORT":          true,
		"XRAY_SHADOWSOCKS_ENABLED":       true,
		"XRAY_SHADOWSOCKS_METHOD":        true,
		"XRAY_SHADOWSOCKS_NETWORK":       true,
		"XRAY_TROJAN_PORT":               true,
		"XRAY_TROJAN_ENABLED":            true,
		"XRAY_EASY_UI_PORT":              true,
		"XRAY_EASY_MASTER_KEY":           true,
		"XRAY_HYSTERIA2_ENABLED":         true,
		"XRAY_HYSTERIA2_TLS_MODE":        true,
		"XRAY_HYSTERIA2_CERT_IP":         true,
		"XRAY_HYSTERIA2_TLS_SERVER_NAME": true,
		"COMPOSE_PROFILES":               true,
		"AWG_PUBLIC_HOST":                true,
		"AWG_PUBLIC_PORT":                true,
		"XRAY_LEASE_SERVICE_ENABLED":     true,
		"XRAY_LEASE_MAX_ACTIVE":          true,
		"XRAY_LEASE_GRACE":               true,
		"XRAY_LEASE_RETRY_DELAY":         true,
	}
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !excluded[key] {
			env = append(env, entry)
		}
	}
	return env
}

// main starts the program.
func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// runMain runs the requested operation.
func runMain(args []string, input, output *os.File, errorsOut io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(errorsOut, "usage: xray-easy-install <repository-directory>")
		return 2
	}
	restore, err := enterTerminal(input, output)
	if err != nil {
		fmt.Fprintln(errorsOut, "Cannot open terminal:", err)
		return 1
	}
	ctx, stop := installerContext()
	result, err := runInstall(ctx, args[0], input, output, dockerRunner{output: output})
	stop()
	restore()
	if err != nil {
		fmt.Fprintln(errorsOut, "Installation stopped:", err)
		return 1
	}
	if !result.started {
		fmt.Fprintln(output, "Installation cancelled. No containers were changed.")
		return 0
	}
	printNextSteps(output, result.config)
	return 0
}

// run runs the requested operation.
func run(ctx context.Context, root string, input io.Reader, output io.Writer, runner commandRunner) error {
	_, err := runInstall(ctx, root, input, output, runner)
	return err
}

// installResult is an internal type used by the package.
type installResult struct {
	config  configuration
	started bool
}

// runInstall runs the requested operation.
func runInstall(ctx context.Context, root string, input io.Reader, output io.Writer, runner commandRunner) (installResult, error) {
	ui := newWizard(input, output)
	defer ui.close()
	if docker, ok := runner.(dockerRunner); ok {
		docker.output = ui
		runner = docker
	}
	ui.step(1, "Checking Docker")
	composeVersion, err := runner.capture(ctx, root, "compose", "version", "--short")
	if err != nil {
		return installResult{}, fmt.Errorf("Docker Compose v2 is required: %w", err)
	}
	engineVersion, err := runner.capture(ctx, root, "info", "--format", "{{.ServerVersion}}")
	if err != nil {
		return installResult{}, fmt.Errorf("cannot reach the Docker daemon: %w", err)
	}
	if !versionAtLeast(engineVersion, "28.0.0") {
		return installResult{}, fmt.Errorf("Docker Engine 28.0.0 or newer is required for IPv6 egress routing; found %q. Upgrade Docker Engine and rerun ./install.sh", engineVersion)
	}
	if !versionAtLeast(composeVersion, "2.33.1") {
		return installResult{}, fmt.Errorf("Docker Compose 2.33.1 or newer is required for IPv6 egress routing; found %q. Upgrade the Compose plugin and rerun ./install.sh", composeVersion)
	}
	ui.message(fmt.Sprintf("Docker Engine %s and Compose %s are available; IPv6 egress routing is supported", engineVersion, composeVersion))

	envPath := filepath.Join(root, ".env")
	_, statErr := os.Stat(envPath)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return installResult{}, statErr
	}
	existing := statErr == nil
	ui.step(2, "Configuration")
	var cfg configuration
	if existing {
		cfg, err = loadConfiguration(root)
		if err != nil {
			return installResult{}, fmt.Errorf("existing .env is invalid; fix it without replacing the master key: %w", err)
		}
		ui.message("Existing .env and master key found; they will be reused.")
	} else {
		cfg = configuration{
			project:            defaultProject,
			version:            defaultVersion,
			hysteriaMode:       "custom",
			awgPublicPort:      defaultAWGPort,
			shadowsocksMethod:  defaultShadowsocksMethod,
			shadowsocksNetwork: "tcp,udp",
		}
		cfg.public, cfg.ui, err = ui.ports(ctx, 443, 8080)
		if err != nil {
			if errors.Is(err, errCancelled) {
				return installResult{}, nil
			}
			return installResult{}, err
		}
		cfg.vmess = defaultVMessPort(cfg.public, cfg.ui)
		cfg.shadowsocks = defaultShadowsocksPort(cfg.public, cfg.vmess, cfg.ui)
		cfg.trojan = defaultTrojanPort(cfg.public, cfg.vmess, cfg.shadowsocks, cfg.ui)
	}
	previous := cfg
	cfg, err = ui.hysteria(ctx, root, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}
	cfg, err = ui.amneziaWG(ctx, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}
	cfg, err = ui.shadowsocks(ctx, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}
	cfg, err = ui.trojan(ctx, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}
	cfg, err = ui.leaseService(ctx, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}

	ui.review(cfg)
	if !existing {
		ui.message("A master key will be generated and saved locally.")
	}
	proceed, err := ui.confirm(ctx)
	if err != nil {
		return installResult{}, err
	}
	if !proceed {
		return installResult{}, nil
	}
	if err := ctx.Err(); err != nil {
		return installResult{}, err
	}
	if err := validateHysteriaConfiguration(cfg); err != nil {
		return installResult{}, err
	}
	if err := validateAWGConfiguration(cfg); err != nil {
		return installResult{}, err
	}
	if err := validateShadowsocksConfiguration(cfg); err != nil {
		return installResult{}, err
	}
	if err := validateTrojanConfiguration(cfg); err != nil {
		return installResult{}, err
	}
	if err := validateLeaseConfiguration(root, cfg); err != nil {
		return installResult{}, err
	}
	certificateChanged := false
	if cfg.hysteriaEnabled && cfg.hysteriaMode == "custom" {
		certificateChanged, err = importHysteriaCertificate(root, cfg)
		if err != nil {
			return installResult{}, err
		}
	}
	if !existing {
		if err := createConfiguration(root, cfg); err != nil {
			return installResult{}, err
		}
		ui.message("Saved .env with private file permissions")
	} else if hysteriaConfigurationChanged(previous, cfg) {
		if err := updateHysteriaConfiguration(root, cfg); err != nil {
			return installResult{}, err
		}
		ui.message("Updated Hysteria 2 settings in .env; existing keys were preserved")
	}
	if existing {
		if err := updateShadowsocksConfiguration(root, cfg); err != nil {
			return installResult{}, fmt.Errorf("save Shadowsocks settings: %w", err)
		}
		if err := updateTrojanConfiguration(root, cfg); err != nil {
			return installResult{}, fmt.Errorf("save Trojan settings: %w", err)
		}
		if trojanConfigurationChanged(previous, cfg) {
			ui.message("Updated Trojan settings in .env; existing keys were preserved")
		}
		if shadowsocksConfigurationChanged(previous, cfg) {
			ui.message("Updated Shadowsocks settings in .env; existing keys were preserved")
		}
	}
	if existing && previous.awgEnabled && !cfg.awgEnabled {
		if err := runner.run(ctx, root, false, "compose", "--profile", "awg", "-f", "compose.yaml", "stop", "amneziawg-service"); err != nil {
			return installResult{}, fmt.Errorf("stop AmneziaWG before disabling it: %w", err)
		}
	}
	if existing && previous.leaseEnabled && !cfg.leaseEnabled {
		if err := runner.run(ctx, root, false, "compose", "--profile", "lease", "-f", "compose.yaml", "stop", "xray-lease-service"); err != nil {
			return installResult{}, fmt.Errorf("stop lease service before disabling it: %w", err)
		}
	}
	if err := updateAWGConfiguration(root, cfg); err != nil {
		return installResult{}, fmt.Errorf("save AmneziaWG Compose settings: %w", err)
	}
	if err := updateLeaseConfiguration(root, cfg); err != nil {
		return installResult{}, fmt.Errorf("save Xray lease-service settings: %w", err)
	}
	if existing && awgConfigurationChanged(previous, cfg) && cfg.awgEnabled {
		ui.message("AmneziaWG settings changed. After startup, open each existing device profile in the Web UI and import the refreshed profile; exported copies keep their old endpoint and preset.")
	}

	ui.step(4, "Building and starting containers")
	if err := runner.run(ctx, root, false, "compose", "-f", "compose.yaml", "config", "--quiet"); err != nil {
		return installResult{}, fmt.Errorf("Compose configuration is invalid: %w", err)
	}
	ui.message("Pulling published service images")
	pullErr := runner.run(ctx, root, true, "compose", "-f", "compose.yaml", "pull")
	upArgs := []string{"compose", "-f", "compose.yaml", "up", "-d"}
	if pullErr != nil {
		ui.message("Published images are unavailable; building the services locally from this checkout.")
		upArgs = append(upArgs, "--build")
	}
	upArgs = append(upArgs, "--remove-orphans", "--wait", "--wait-timeout", "180")
	if err := runner.run(ctx, root, true, upArgs...); err != nil {
		ui.step(4, "Collecting startup diagnostics")
		ui.message("Compose did not become healthy. Collecting service state and recent logs; containers and configuration are preserved.")
		collectStartupDiagnostics(ctx, root, runner, ui)
		return installResult{}, fmt.Errorf("Compose could not start; containers and configuration were kept for troubleshooting: %w%s\n\n%s", err, ui.logTail(12), startupRecoveryCommands)
	}
	if existing && (certificateChanged || cfg.hysteriaEnabled && cfg.hysteriaMode == "self-signed") {
		ui.step(4, "Reloading Xray TLS certificate")
		reloadArgs := []string{"compose", "-f", "compose.yaml", "up", "-d", "--wait", "--wait-timeout", "180", "--no-deps", "--force-recreate", "xray-core-service"}
		if err := runner.run(ctx, root, true, reloadArgs...); err != nil {
			ui.step(4, "Collecting startup diagnostics")
			ui.message("Xray did not become healthy after the TLS certificate reload. Collecting service state and recent logs; containers and configuration are preserved.")
			collectStartupDiagnostics(ctx, root, runner, ui)
			return installResult{}, fmt.Errorf("Xray could not reload the Hysteria 2 TLS certificate; containers and configuration were kept for troubleshooting: %w%s\n\n%s", err, ui.logTail(12), startupRecoveryCommands)
		}
	}
	ui.step(4, "Verifying the installation")
	if err := runner.run(ctx, root, true, "compose", "-f", "compose.yaml", "exec", "-T", "control-plane", "xray-easy", "doctor"); err != nil {
		ui.step(4, "Doctor checks failed")
		ui.message("Doctor found failures. The services and configuration are preserved for troubleshooting.")
		return installResult{}, fmt.Errorf("post-install doctor failed: %w; rerun after fixing with: docker compose -f compose.yaml exec -T control-plane xray-easy doctor", err)
	}
	ui.step(4, "Doctor checks completed")
	ui.message("Doctor completed. Review any warnings above; Xray-easy is running.")
	return installResult{config: cfg, started: true}, nil
}

// collectStartupDiagnostics shows the current Compose state and recent service
// logs in the installer's terminal after startup or health-check failure.
func collectStartupDiagnostics(ctx context.Context, root string, runner commandRunner, ui *wizard) {
	commands := [][]string{
		{"compose", "-f", "compose.yaml", "ps", "--all"},
		{"compose", "-f", "compose.yaml", "logs", "--tail=100", "--timestamps"},
	}
	for _, args := range commands {
		ui.message("Running docker " + strings.Join(args, " "))
		if err := runner.run(ctx, root, true, args...); err != nil {
			ui.message("Could not collect one diagnostic command; recovery commands are shown after the installer exits.")
		}
	}
}

// printNextSteps performs the operation represented by its name.
func printNextSteps(output io.Writer, cfg configuration) {
	fmt.Fprintf(output, "Xray-easy is running.\n\nOn your computer:\n  ssh -N -L %d:127.0.0.1:%d user@your-vds\n\nOpen http://127.0.0.1:%d to create the admin and first device.\nAllow inbound TCP %d (VLESS) and TCP %d (VMess, if used) through the VDS firewall.\n", cfg.ui, cfg.ui, cfg.ui, cfg.public, cfg.vmess)
	if cfg.shadowsocksEnabled {
		fmt.Fprintf(output, "Allow inbound TCP and UDP %d through the VDS firewall for Shadowsocks.\n", cfg.shadowsocks)
	}
	if cfg.hysteriaEnabled {
		fmt.Fprintf(output, "Allow inbound UDP %d through the VDS firewall for Hysteria 2.\n", cfg.public)
	}
	if cfg.awgEnabled {
		fmt.Fprintf(output, "Allow inbound UDP %d through the VDS firewall for AmneziaWG.\n", cfg.awgPublicPort)
	}
	if cfg.trojanEnabled {
		fmt.Fprintf(output, "Allow inbound TCP %d through the VDS firewall for Trojan.\n", cfg.trojan)
	}
}

// parsePort parses the supplied value.
func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return port, nil
}

// defaultVMessPort performs the operation represented by its name.
func defaultVMessPort(publicPort, uiPort int) int {
	for port := 9443; port <= 65535; port++ {
		if port != publicPort && port != uiPort {
			return port
		}
	}
	for port := 1; port < 9443; port++ {
		if port != publicPort && port != uiPort {
			return port
		}
	}
	return 0
}

// versionAtLeast performs the operation represented by its name.
func versionAtLeast(version, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		var result [3]int
		value = strings.TrimSpace(strings.TrimLeft(value, "vV"))
		parts := strings.Split(value, ".")
		if len(parts) < len(result) {
			return result, false
		}
		for i := range result {
			end := 0
			for end < len(parts[i]) && parts[i][end] >= '0' && parts[i][end] <= '9' {
				end++
			}
			if end == 0 {
				return result, false
			}
			component, err := strconv.Atoi(parts[i][:end])
			if err != nil {
				return result, false
			}
			result[i] = component
		}
		return result, true
	}

	got, ok := parse(version)
	if !ok {
		return false
	}
	want, ok := parse(minimum)
	if !ok {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return got[i] > want[i]
		}
	}
	return true
}

// createConfiguration creates the requested value.
func createConfiguration(root string, cfg configuration) error {
	if cfg.vmess == 0 {
		cfg.vmess = defaultVMessPort(cfg.public, cfg.ui)
	}
	if cfg.shadowsocks == 0 {
		cfg.shadowsocks = defaultShadowsocksPort(cfg.public, cfg.vmess, cfg.ui)
		cfg.trojan = defaultTrojanPort(cfg.public, cfg.vmess, cfg.shadowsocks, cfg.ui)
	}
	if cfg.trojan == 0 {
		cfg.trojan = defaultTrojanPort(cfg.public, cfg.vmess, cfg.shadowsocks, cfg.ui)
	}
	// SS2022 uses one fixed cipher; upgrade any legacy .env choice.
	cfg.shadowsocksMethod = defaultShadowsocksMethod
	cfg.shadowsocksNetwork = valueOr(cfg.shadowsocksNetwork, "tcp,udp")
	if cfg.vmess == cfg.public || cfg.vmess == cfg.ui {
		return errors.New("XRAY_VMESS_PORT must differ from the Xray and Web UI ports")
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets", "hysteria"), 0o700); err != nil {
		return fmt.Errorf("create Hysteria TLS directory: %w", err)
	}
	masterKey, err := randomBase64(32)
	if err != nil {
		return err
	}
	imageNamespace := valueOr(os.Getenv("XRAY_EASY_IMAGE_NAMESPACE"), "dasshit")
	imageTag := valueOr(os.Getenv("XRAY_EASY_IMAGE_TAG"), "latest")
	content := fmt.Sprintf("# Generated by ./install.sh. Keep this file and its master key private.\nXRAY_EASY_PROJECT_NAME=%s\nXRAY_EASY_IMAGE_NAMESPACE=%s\nXRAY_EASY_IMAGE_TAG=%s\nXRAY_VERSION=%s\nXRAY_PUBLIC_PORT=%d\nXRAY_VMESS_PORT=%d\nXRAY_SHADOWSOCKS_PORT=%d\nXRAY_SHADOWSOCKS_ENABLED=%t\nXRAY_SHADOWSOCKS_METHOD=%s\nXRAY_SHADOWSOCKS_NETWORK=%s\nXRAY_TROJAN_PORT=%d\nXRAY_TROJAN_ENABLED=%t\nXRAY_EASY_UI_PORT=%d\nXRAY_EASY_MASTER_KEY=%s\nXRAY_LEASE_SERVICE_ENABLED=%t\nXRAY_LEASE_MAX_ACTIVE=2\nXRAY_LEASE_GRACE=30s\nXRAY_LEASE_RETRY_DELAY=1s\n%s", cfg.project, imageNamespace, imageTag, cfg.version, cfg.public, cfg.vmess, cfg.shadowsocks, cfg.shadowsocksEnabled, cfg.shadowsocksMethod, cfg.shadowsocksNetwork, cfg.trojan, cfg.trojanEnabled, cfg.ui, masterKey, cfg.leaseEnabled, hysteriaEnvironment(cfg))
	if err := writeNewPrivateFile(filepath.Join(root, ".env"), content); err != nil {
		return fmt.Errorf("save .env: %w", err)
	}
	return nil
}

// randomBase64 performs the operation represented by its name.
func randomBase64(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// writeNewPrivateFile writes the supplied value.
func writeNewPrivateFile(path, content string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".xray-easy-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := io.WriteString(file, content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Link only if the destination is absent, so concurrent or repeated runs
	// cannot overwrite a key that may already protect existing state.
	return os.Link(file.Name(), path)
}

// loadConfiguration performs the operation represented by its name.
func loadConfiguration(root string) (configuration, error) {
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		return configuration{}, err
	}
	key := values["XRAY_EASY_MASTER_KEY"]
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) < 32 {
		return configuration{}, errors.New("XRAY_EASY_MASTER_KEY must contain a base64 key of at least 32 bytes")
	}
	publicValue := valueOr(values["XRAY_PUBLIC_PORT"], "443")
	publicPort, err := parsePort(publicValue)
	if err != nil {
		return configuration{}, fmt.Errorf("XRAY_PUBLIC_PORT: %w", err)
	}
	uiValue := valueOr(values["XRAY_EASY_UI_PORT"], "8080")
	uiPort, err := parsePort(uiValue)
	if err != nil {
		return configuration{}, fmt.Errorf("XRAY_EASY_UI_PORT: %w", err)
	}
	if publicPort == uiPort {
		return configuration{}, errors.New("public and Web UI ports must differ")
	}
	vmessValue := values["XRAY_VMESS_PORT"]
	if strings.TrimSpace(vmessValue) == "" {
		vmessValue = strconv.Itoa(defaultVMessPort(publicPort, uiPort))
	}
	vmessPort, err := parsePort(vmessValue)
	if err != nil {
		return configuration{}, fmt.Errorf("XRAY_VMESS_PORT: %w", err)
	}
	if vmessPort == publicPort || vmessPort == uiPort {
		return configuration{}, errors.New("XRAY_VMESS_PORT must differ from the Xray and Web UI ports")
	}
	ssValue := valueOr(values["XRAY_SHADOWSOCKS_PORT"], strconv.Itoa(defaultShadowsocksPort(publicPort, vmessPort, uiPort)))
	ssPort, err := parsePort(ssValue)
	if err != nil {
		return configuration{}, fmt.Errorf("XRAY_SHADOWSOCKS_PORT: %w", err)
	}
	if ssPort == publicPort || ssPort == vmessPort || ssPort == uiPort {
		return configuration{}, errors.New("XRAY_SHADOWSOCKS_PORT must differ from Xray, VMess, and Web UI ports")
	}
	trojanValue := valueOr(values["XRAY_TROJAN_PORT"], strconv.Itoa(defaultTrojanPort(publicPort, vmessPort, ssPort, uiPort)))
	trojanPort, err := parsePort(trojanValue)
	if err != nil {
		return configuration{}, fmt.Errorf("XRAY_TROJAN_PORT: %w", err)
	}
	if trojanPort == publicPort || trojanPort == vmessPort || trojanPort == ssPort || trojanPort == uiPort {
		return configuration{}, errors.New("XRAY_TROJAN_PORT must differ from Xray, VMess, Shadowsocks, and Web UI ports")
	}
	cfg := configuration{
		project:            valueOr(values["XRAY_EASY_PROJECT_NAME"], legacyProject),
		version:            valueOr(values["XRAY_VERSION"], defaultVersion),
		public:             publicPort,
		vmess:              vmessPort,
		shadowsocks:        ssPort,
		shadowsocksEnabled: strings.EqualFold(values["XRAY_SHADOWSOCKS_ENABLED"], "true"),
		shadowsocksMethod:  defaultShadowsocksMethod,
		shadowsocksNetwork: valueOr(values["XRAY_SHADOWSOCKS_NETWORK"], "tcp,udp"),
		trojan:             trojanPort,
		trojanEnabled:      strings.EqualFold(values["XRAY_TROJAN_ENABLED"], "true"),
		ui:                 uiPort,
		hysteriaEnabled:    strings.EqualFold(values["XRAY_HYSTERIA2_ENABLED"], "true"),
		hysteriaMode:       valueOr(values["XRAY_HYSTERIA2_TLS_MODE"], "legacy"),
		hysteriaCertIP:     values["XRAY_HYSTERIA2_CERT_IP"],
		hysteriaServerName: values["XRAY_HYSTERIA2_TLS_SERVER_NAME"],
		awgEnabled:         composeProfileEnabled(values["COMPOSE_PROFILES"], "awg") || composeProfileEnabled(values["COMPOSE_PROFILES"], "awg-prototype") || strings.TrimSpace(values["AWG_PUBLIC_HOST"]) != "",
		awgPublicHost:      strings.TrimSpace(values["AWG_PUBLIC_HOST"]),
		awgPublicPort:      defaultAWGPort,
		leaseEnabled:       strings.EqualFold(values["XRAY_LEASE_SERVICE_ENABLED"], "true") || composeProfileEnabled(values["COMPOSE_PROFILES"], "lease"),
	}
	if value := strings.TrimSpace(values["AWG_PUBLIC_PORT"]); value != "" {
		cfg.awgPublicPort, err = parsePort(value)
		if err != nil {
			return configuration{}, fmt.Errorf("AWG_PUBLIC_PORT: %w", err)
		}
	}
	if err := validateHysteriaConfiguration(cfg); err != nil {
		return configuration{}, err
	}
	if err := validateAWGConfiguration(cfg); err != nil {
		return configuration{}, err
	}
	if err := validateShadowsocksConfiguration(cfg); err != nil {
		return configuration{}, err
	}
	if err := validateTrojanConfiguration(cfg); err != nil {
		return configuration{}, err
	}
	return cfg, nil
}

// defaultShadowsocksPort performs the operation represented by its name.
func defaultShadowsocksPort(publicPort, vmessPort, uiPort int) int {
	for port := 8388; port <= 65535; port++ {
		if port != publicPort && port != vmessPort && port != uiPort {
			return port
		}
	}
	return 0
}

// validateShadowsocksConfiguration validates the supplied value.
func validateShadowsocksConfiguration(cfg configuration) error {
	port := cfg.shadowsocks
	if port == 0 {
		port = defaultShadowsocksPort(cfg.public, cfg.vmess, cfg.ui)
	}
	if port < 1 || port > 65535 {
		return errors.New("XRAY_SHADOWSOCKS_PORT must be between 1 and 65535")
	}
	if port == cfg.public || port == cfg.vmess || port == cfg.ui {
		return errors.New("XRAY_SHADOWSOCKS_PORT must differ from Xray, VMess, and Web UI ports")
	}
	method := defaultShadowsocksMethod
	if !domain.SupportsShadowsocksMethod(method) {
		return errors.New("unsupported XRAY_SHADOWSOCKS_METHOD")
	}
	network := valueOr(cfg.shadowsocksNetwork, "tcp,udp")
	if !domain.SupportsShadowsocksNetwork(network) {
		return errors.New("unsupported XRAY_SHADOWSOCKS_NETWORK")
	}
	return nil
}

// defaultTrojanPort performs the operation represented by its name.
func defaultTrojanPort(publicPort, vmessPort, shadowsocksPort, uiPort int) int {
	for port := 10443; port <= 65535; port++ {
		if port != publicPort && port != vmessPort && port != shadowsocksPort && port != uiPort {
			return port
		}
	}
	return 0
}

// validateTrojanConfiguration validates the supplied value.
func validateTrojanConfiguration(cfg configuration) error {
	port := cfg.trojan
	if port == 0 {
		port = defaultTrojanPort(cfg.public, cfg.vmess, cfg.shadowsocks, cfg.ui)
	}
	if port < 1 || port > 65535 {
		return errors.New("XRAY_TROJAN_PORT must be between 1 and 65535")
	}
	if port == cfg.public || port == cfg.vmess || port == cfg.shadowsocks || port == cfg.ui {
		return errors.New("XRAY_TROJAN_PORT must differ from Xray, VMess, Shadowsocks, and Web UI ports")
	}
	return nil
}

// composeProfileEnabled performs the operation represented by its name.
func composeProfileEnabled(value, profile string) bool {
	for _, current := range strings.Split(value, ",") {
		if strings.TrimSpace(current) == profile {
			return true
		}
	}
	return false
}

// readEnvironmentFile reads the requested value.
func readEnvironmentFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("malformed .env line (expected KEY=VALUE)")
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	return values, scanner.Err()
}

// valueOr performs the operation represented by its name.
func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
