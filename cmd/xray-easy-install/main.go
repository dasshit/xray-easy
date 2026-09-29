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
)

const (
	defaultVersion          = "26.7.28"
	defaultProject          = "xray-easy"
	legacyProject           = "xray-easy-stage1"
	newTokenPath            = "./secrets/xray_supervisor_token"
	oldTokenPath            = "./prototype/secrets/xray_supervisor_token"
	startupRecoveryCommands = `Useful commands from the repository directory:
  docker compose -f compose.yaml ps --all
  docker compose -f compose.yaml logs --tail=100 --timestamps xray xray-easy
  docker compose -f compose.yaml exec -T xray-easy xray-easy doctor
  docker compose -f compose.yaml exec -T xray-easy xray-easy doctor bundle

If xray-easy is stopped, create a report with a one-off container:
  docker compose -f compose.yaml run --rm --no-deps xray-easy doctor bundle`
)

type configuration struct {
	project            string
	version            string
	public             int
	ui                 int
	tokenPath          string
	hysteriaEnabled    bool
	hysteriaMode       string
	hysteriaCertIP     string
	hysteriaServerName string
	hysteriaCertSource string
	hysteriaKeySource  string
}

type commandRunner interface {
	run(context.Context, string, bool, ...string) error
	capture(context.Context, string, ...string) (string, error)
}

type dockerRunner struct{ output io.Writer }

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
		"XRAY_VERSION":                   true,
		"XRAY_PUBLIC_PORT":               true,
		"XRAY_EASY_UI_PORT":              true,
		"XRAY_EASY_MASTER_KEY":           true,
		"XRAY_SUPERVISOR_TOKEN_SOURCE":   true,
		"XRAY_HYSTERIA2_ENABLED":         true,
		"XRAY_HYSTERIA2_TLS_MODE":        true,
		"XRAY_HYSTERIA2_CERT_IP":         true,
		"XRAY_HYSTERIA2_TLS_SERVER_NAME": true,
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

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

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

func run(ctx context.Context, root string, input io.Reader, output io.Writer, runner commandRunner) error {
	_, err := runInstall(ctx, root, input, output, runner)
	return err
}

type installResult struct {
	config  configuration
	started bool
}

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
		ui.message("Existing .env and supervisor token found; they will be reused.")
	} else {
		cfg = configuration{project: defaultProject, version: defaultVersion, tokenPath: newTokenPath, hysteriaMode: "custom"}
		cfg.public, cfg.ui, err = ui.ports(ctx, 443, 8080)
		if err != nil {
			if errors.Is(err, errCancelled) {
				return installResult{}, nil
			}
			return installResult{}, err
		}
	}
	previous := cfg
	cfg, err = ui.hysteria(ctx, root, cfg)
	if err != nil {
		if errors.Is(err, errCancelled) {
			return installResult{}, nil
		}
		return installResult{}, err
	}

	ui.review(cfg)
	if !existing {
		ui.message("A master key and supervisor token will be generated and saved locally.")
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
		ui.message("Saved .env and supervisor token with private file permissions")
	} else if hysteriaConfigurationChanged(previous, cfg) {
		if err := updateHysteriaConfiguration(root, cfg); err != nil {
			return installResult{}, err
		}
		ui.message("Updated Hysteria 2 settings in .env; existing keys were preserved")
	}

	ui.step(4, "Building and starting containers")
	if err := runner.run(ctx, root, false, "compose", "-f", "compose.yaml", "config", "--quiet"); err != nil {
		return installResult{}, fmt.Errorf("Compose configuration is invalid: %w", err)
	}
	upArgs := []string{"compose", "-f", "compose.yaml", "up", "-d", "--build", "--wait", "--wait-timeout", "180"}
	if existing && (hysteriaConfigurationChanged(previous, cfg) || certificateChanged || cfg.hysteriaEnabled && cfg.hysteriaMode == "self-signed") {
		upArgs = append(upArgs, "--force-recreate")
	}
	if err := runner.run(ctx, root, true, upArgs...); err != nil {
		ui.step(4, "Collecting startup diagnostics")
		ui.message("Compose did not become healthy. Collecting service state and recent logs; containers and configuration are preserved.")
		collectStartupDiagnostics(ctx, root, runner, ui)
		return installResult{}, fmt.Errorf("Compose could not start; containers and configuration were kept for troubleshooting: %w%s\n\n%s", err, ui.logTail(12), startupRecoveryCommands)
	}
	ui.step(4, "Verifying the installation")
	if err := runner.run(ctx, root, true, "compose", "-f", "compose.yaml", "exec", "-T", "xray-easy", "xray-easy", "doctor"); err != nil {
		ui.step(4, "Doctor checks failed")
		ui.message("Doctor found failures. The services and configuration are preserved for troubleshooting.")
		return installResult{}, fmt.Errorf("post-install doctor failed: %w; rerun after fixing with: docker compose -f compose.yaml exec -T xray-easy xray-easy doctor", err)
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
		{"compose", "-f", "compose.yaml", "logs", "--tail=100", "--timestamps", "xray", "xray-easy"},
	}
	for _, args := range commands {
		ui.message("Running docker " + strings.Join(args, " "))
		if err := runner.run(ctx, root, true, args...); err != nil {
			ui.message("Could not collect one diagnostic command; recovery commands are shown after the installer exits.")
		}
	}
}

func printNextSteps(output io.Writer, cfg configuration) {
	fmt.Fprintf(output, "Xray-easy is running.\n\nOn your computer:\n  ssh -N -L %d:127.0.0.1:%d user@your-vds\n\nOpen http://127.0.0.1:%d to create the admin and first device.\nAllow inbound TCP %d through the VDS firewall for clients.\n", cfg.ui, cfg.ui, cfg.ui, cfg.public)
	if cfg.hysteriaEnabled {
		fmt.Fprintf(output, "Allow inbound UDP %d through the VDS firewall for Hysteria 2.\n", cfg.public)
	}
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return port, nil
}

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

func createConfiguration(root string, cfg configuration) error {
	secretPath := filepath.Join(root, newTokenPath)
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	if _, err := os.Stat(secretPath); errors.Is(err, os.ErrNotExist) {
		token, err := randomBase64(32)
		if err != nil {
			return err
		}
		if err := writeNewPrivateFile(secretPath, token+"\n"); err != nil {
			return fmt.Errorf("save supervisor token: %w", err)
		}
	} else if err != nil {
		return err
	} else if err := validateToken(secretPath); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets", "hysteria"), 0o700); err != nil {
		return fmt.Errorf("create Hysteria TLS directory: %w", err)
	}
	masterKey, err := randomBase64(32)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("# Generated by ./install.sh. Keep this file and its master key private.\nXRAY_EASY_PROJECT_NAME=%s\nXRAY_VERSION=%s\nXRAY_PUBLIC_PORT=%d\nXRAY_EASY_UI_PORT=%d\nXRAY_SUPERVISOR_TOKEN_SOURCE=%s\nXRAY_EASY_MASTER_KEY=%s\n%s", cfg.project, cfg.version, cfg.public, cfg.ui, cfg.tokenPath, masterKey, hysteriaEnvironment(cfg))
	if err := writeNewPrivateFile(filepath.Join(root, ".env"), content); err != nil {
		return fmt.Errorf("save .env: %w", err)
	}
	return nil
}

func randomBase64(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

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
	tokenPath := valueOr(values["XRAY_SUPERVISOR_TOKEN_SOURCE"], oldTokenPath)
	if err := validateToken(filepath.Join(root, tokenPath)); err != nil {
		return configuration{}, err
	}
	cfg := configuration{
		project:            valueOr(values["XRAY_EASY_PROJECT_NAME"], legacyProject),
		version:            valueOr(values["XRAY_VERSION"], defaultVersion),
		public:             publicPort,
		ui:                 uiPort,
		tokenPath:          tokenPath,
		hysteriaEnabled:    strings.EqualFold(values["XRAY_HYSTERIA2_ENABLED"], "true"),
		hysteriaMode:       valueOr(values["XRAY_HYSTERIA2_TLS_MODE"], "legacy"),
		hysteriaCertIP:     values["XRAY_HYSTERIA2_CERT_IP"],
		hysteriaServerName: values["XRAY_HYSTERIA2_TLS_SERVER_NAME"],
	}
	if err := validateHysteriaConfiguration(cfg); err != nil {
		return configuration{}, err
	}
	return cfg, nil
}

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

func validateToken(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("supervisor token %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("supervisor token %s must be a non-empty file", path)
	}
	return nil
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
