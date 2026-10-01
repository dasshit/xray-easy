package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls          []string
	failOn         string
	engineVersion  string
	composeVersion string
}

func (r *fakeRunner) run(_ context.Context, _ string, _ bool, args ...string) error {
	call := strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, r.failOn) && r.failOn != "" {
		return errors.New("simulated Docker failure")
	}
	return nil
}

func (r *fakeRunner) capture(_ context.Context, _ string, args ...string) (string, error) {
	call := strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if strings.Contains(call, r.failOn) && r.failOn != "" {
		return "", errors.New("simulated Docker failure")
	}
	switch call {
	case "compose version --short":
		if r.composeVersion != "" {
			return r.composeVersion, nil
		}
		return "v2.33.1", nil
	case "info --format {{.ServerVersion}}":
		if r.engineVersion != "" {
			return r.engineVersion, nil
		}
		return "28.0.0", nil
	default:
		return "", fmt.Errorf("unexpected output command: %s", call)
	}
}

func TestInstallAndRetryPreserveSecrets(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 6 || runner.calls[3] != "compose -f compose.yaml pull" || !strings.Contains(runner.calls[4], "up -d --remove-orphans --wait") || strings.Contains(runner.calls[4], "--build") || !strings.Contains(runner.calls[5], "exec -T control-plane xray-easy doctor") {
		t.Fatalf("unexpected Docker calls: %v", runner.calls)
	}
	if !strings.Contains(output.String(), "Doctor completed. Review any warnings above") {
		t.Fatal("installer did not show the completed doctor stage")
	}
	envPath := filepath.Join(root, ".env")
	firstEnv := readPrivateFile(t, envPath)
	if _, err := os.Stat(filepath.Join(root, "secrets", "xray_supervisor_token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installer created a legacy supervisor token: %v", err)
	}
	values, err := readEnvironmentFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.StdEncoding.DecodeString(values["XRAY_EASY_MASTER_KEY"])
	if err != nil || len(key) != 32 {
		t.Fatalf("invalid generated master key: len=%d err=%v", len(key), err)
	}
	if values["XRAY_EASY_PROJECT_NAME"] != defaultProject || values["XRAY_SUPERVISOR_TOKEN_SOURCE"] != "" {
		t.Fatalf("unexpected configuration: %#v", values)
	}
	if strings.Contains(output.String(), values["XRAY_EASY_MASTER_KEY"]) {
		t.Fatal("installation output leaked a secret")
	}

	runner.calls = nil
	output.Reset()
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	if got := readPrivateFile(t, envPath); got != firstEnv {
		t.Fatal("retry replaced .env")
	}
	if !strings.Contains(output.String(), "Existing .env") {
		t.Fatal("retry did not show existing configuration")
	}
}

func TestInstallBuildsServicesLocallyWhenImagePullFails(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{failOn: "compose -f compose.yaml pull"}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(runner.calls, "\n")
	if !strings.Contains(calls, "compose -f compose.yaml pull") || !strings.Contains(calls, "up -d --build --remove-orphans --wait") {
		t.Fatalf("failed image pull did not trigger a local service build: %v", runner.calls)
	}
	if !strings.Contains(output.String(), "Published images are unavailable; building the services locally") {
		t.Fatalf("local build fallback was not shown: %s", output.String())
	}
}

func TestChangingAmneziaWGEndpointDoesNotForceRecreateXray(t *testing.T) {
	root := t.TempDir()
	cfg := configuration{
		project: defaultProject, version: defaultVersion, public: 443, vmess: 9443, ui: 8080,
		hysteriaMode: "custom", awgEnabled: true,
		awgPublicHost: "vpn.old.example.test", awgPublicPort: defaultAWGPort,
	}
	if err := createConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := updateAWGConfiguration(root, cfg); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	var output bytes.Buffer
	input := "\n\n" + strings.Repeat("\x7f", len(cfg.awgPublicHost)) + "vpn.new.example.test\n\n\n\n"
	if err := run(context.Background(), root, strings.NewReader(input), &output, runner); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(runner.calls, "\n")
	if strings.Contains(calls, "--force-recreate") {
		t.Fatalf("AmneziaWG endpoint change forced unrelated container recreation: %s", calls)
	}
	if !strings.Contains(calls, "compose -f compose.yaml up -d --remove-orphans --wait --wait-timeout 180") {
		t.Fatalf("Compose did not apply the changed service configuration: %s", calls)
	}
	if !strings.Contains(output.String(), "open each existing device profile") {
		t.Fatalf("installer did not explain that exported AWG profiles need refresh: %s", output.String())
	}
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil || values["AWG_PUBLIC_HOST"] != "vpn.new.example.test" {
		t.Fatalf("updated AWG endpoint = %q, %v", values["AWG_PUBLIC_HOST"], err)
	}
}

func TestCancellationLeavesNoConfiguration(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n\nn\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("cancelled wizard ran Compose: %v", runner.calls)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled wizard created .env: %v", err)
	}
}

func TestInvalidPortsAreReprompted(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{}
	var output bytes.Buffer
	input := "65536\n4443\n4443\n8080\n\n\n\ny\n"
	if err := run(context.Background(), root, strings.NewReader(input), &output, runner); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_PUBLIC_PORT"] != "4443" || values["XRAY_VMESS_PORT"] != "9443" || values["XRAY_EASY_UI_PORT"] != "8080" {
		t.Fatalf("ports were not saved: %#v", values)
	}
	if !strings.Contains(output.String(), "Choose a different Web UI port") {
		t.Fatal("matching host ports were not explained")
	}
}

func TestDefaultVMessPortAvoidsInstallerPortSelections(t *testing.T) {
	if got := defaultVMessPort(443, 8080); got != 9443 {
		t.Fatalf("default VMess port = %d, want 9443", got)
	}
	if got := defaultVMessPort(9443, 8080); got != 9444 {
		t.Fatalf("VMess port collides with public port: %d", got)
	}
	if got := defaultVMessPort(443, 9443); got != 9444 {
		t.Fatalf("VMess port collides with Web UI port: %d", got)
	}
	if got := defaultVMessPort(9443, 9444); got != 9445 {
		t.Fatalf("VMess port skipped both configured values = %d, want 9445", got)
	}
}

func TestInvalidExistingKeyIsNeverReplaced(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("XRAY_EASY_MASTER_KEY=bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	var output bytes.Buffer
	err := run(context.Background(), root, strings.NewReader(""), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "master key") && !strings.Contains(err.Error(), "MASTER_KEY") {
		t.Fatalf("expected master key error, got %v", err)
	}
	if got := readPrivateFile(t, envPath); got != "XRAY_EASY_MASTER_KEY=bad\n" {
		t.Fatal("invalid existing key was replaced")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("invalid configuration ran Compose: %v", runner.calls)
	}
}

func TestLegacyConfigurationKeepsProjectAndIgnoresSupervisorToken(t *testing.T) {
	root := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("XRAY_EASY_MASTER_KEY="+key+"\nXRAY_SUPERVISOR_TOKEN_SOURCE=./prototype/secrets/old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.project != legacyProject || cfg.public != 443 {
		t.Fatalf("legacy config changed: %+v", cfg)
	}
}

func TestComposeFailureKeepsGeneratedConfigurationForRetry(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{failOn: "up -d"}
	var output bytes.Buffer
	err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "troubleshooting") || !strings.Contains(err.Error(), "docker compose -f compose.yaml logs --tail=100 --timestamps") {
		t.Fatalf("expected retryable Compose error, got %v", err)
	}
	for _, recoveryCommand := range []string{
		"docker compose -f compose.yaml exec -T control-plane xray-easy doctor bundle",
		"docker compose -f compose.yaml run --rm --no-deps control-plane doctor bundle",
	} {
		if !strings.Contains(err.Error(), recoveryCommand) {
			t.Errorf("Compose failure omitted recovery command %q: %v", recoveryCommand, err)
		}
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "compose -f compose.yaml ps --all") || !strings.Contains(strings.Join(runner.calls, "\n"), "compose -f compose.yaml logs --tail=100 --timestamps") {
		t.Fatalf("startup diagnostics were not collected: %v", runner.calls)
	}
	firstEnv := readPrivateFile(t, filepath.Join(root, ".env"))
	runner.failOn = ""
	runner.calls = nil
	if err := run(context.Background(), root, strings.NewReader("\n\n\n\n"), &output, runner); err != nil {
		t.Fatal(err)
	}
	if got := readPrivateFile(t, filepath.Join(root, ".env")); got != firstEnv {
		t.Fatal("retry after Compose failure replaced the master key")
	}
}

func TestDoctorFailurePreservesStartedStackAndShowsRetryCommand(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{failOn: "exec -T control-plane xray-easy doctor"}
	var output bytes.Buffer
	err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "docker compose -f compose.yaml exec -T control-plane xray-easy doctor") {
		t.Fatalf("expected doctor failure with retry command, got %v", err)
	}
	if len(runner.calls) != 6 || !strings.Contains(runner.calls[4], "up -d --remove-orphans --wait") || !strings.Contains(runner.calls[5], "doctor") {
		t.Fatalf("doctor was not the final install step: %v", runner.calls)
	}
	if strings.Contains(strings.Join(runner.calls, "\n"), " down") {
		t.Fatalf("doctor failure unexpectedly stopped the stack: %v", runner.calls)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".env")); statErr != nil {
		t.Fatalf("doctor failure removed the generated configuration: %v", statErr)
	}
	if !strings.Contains(output.String(), "services and configuration are preserved") {
		t.Fatalf("doctor failure message did not describe preserved state: %s", output.String())
	}
}

func TestReadEnvironmentFileDoesNotEchoMalformedSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	secret := "XRAY_EASY_MASTER_KEY with private material"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readEnvironmentFile(path)
	if err == nil || strings.Contains(fmt.Sprint(err), secret) {
		t.Fatalf("malformed line leaked: %v", err)
	}
}

func TestDockerRunnerUsesLocalConfigurationAndReportsFailures(t *testing.T) {
	root := t.TempDir()
	docker := filepath.Join(root, "docker")
	logPath := filepath.Join(root, "docker.log")
	script := "#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$*\" \"${XRAY_PUBLIC_PORT-unset}\" \"${COMPOSE_PROJECT_NAME-unset}\" \"${XRAY_EASY_BUILD_VERSION-unset}\" >> \"$FAKE_DOCKER_LOG\"\nif [ \"$1\" = fail ]; then echo 'simulated compose error' >&2; exit 17; fi\necho 'docker output'\n"
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_LOG", logPath)
	t.Setenv("XRAY_PUBLIC_PORT", "9999")
	t.Setenv("COMPOSE_PROJECT_NAME", "wrong-project")
	t.Setenv("XRAY_EASY_BUILD_VERSION", "build-test")
	var output bytes.Buffer
	runner := dockerRunner{output: &output}
	if err := runner.run(context.Background(), root, false, "compose", "version"); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("quiet Docker command printed output")
	}
	if err := runner.run(context.Background(), root, true, "compose", "up"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "docker output") {
		t.Fatal("visible Docker output was hidden")
	}
	if err := runner.run(context.Background(), root, false, "fail"); err == nil || !strings.Contains(err.Error(), "simulated compose error") {
		t.Fatalf("quiet Docker error lost details: %v", err)
	}
	if err := runner.run(context.Background(), root, true, "fail"); err == nil || !strings.Contains(err.Error(), "exit status 17") {
		t.Fatalf("visible Docker error was lost: %v", err)
	}
	log := readFile(t, logPath)
	if strings.Contains(log, "9999") || strings.Contains(log, "wrong-project") || !strings.Contains(log, "unset|unset|build-test") {
		t.Fatalf("shell environment overrode .env: %s", log)
	}
}

func TestDockerFailureAndClosedInputStopBeforeWriting(t *testing.T) {
	for _, failedCommand := range []string{"compose version", "info --format"} {
		t.Run(failedCommand, func(t *testing.T) {
			root := t.TempDir()
			runner := &fakeRunner{failOn: failedCommand}
			var output bytes.Buffer
			if err := run(context.Background(), root, strings.NewReader(""), &output, runner); err == nil {
				t.Fatal("expected Docker preflight failure")
			}
			if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight wrote .env: %v", err)
			}
		})
	}
	root := t.TempDir()
	var output bytes.Buffer
	if err := run(context.Background(), root, strings.NewReader(""), &output, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "input ended") {
		t.Fatalf("expected closed terminal error, got %v", err)
	}
	for _, input := range []string{"\n", "\n\n"} {
		if err := run(context.Background(), root, strings.NewReader(input), &output, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "input ended") {
			t.Fatalf("expected closed terminal error after %q, got %v", input, err)
		}
	}
}

func TestInstallerRequiresDockerVersionsWithIPv6GatewayPrioritySupport(t *testing.T) {
	for _, test := range []struct {
		name          string
		engineVersion string
		composeVer    string
		wantError     string
	}{
		{name: "old engine", engineVersion: "27.5.1", composeVer: "v2.33.1", wantError: "Docker Engine 28.0.0 or newer"},
		{name: "old compose", engineVersion: "28.0.0", composeVer: "v2.33.0", wantError: "Docker Compose 2.33.1 or newer"},
		{name: "version suffix", engineVersion: "29.0.0", composeVer: "v5.5.1-desktop.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			runner := &fakeRunner{engineVersion: test.engineVersion, composeVersion: test.composeVer}
			var output bytes.Buffer
			err := run(context.Background(), root, strings.NewReader(""), &output, runner)
			if test.wantError == "" {
				if err == nil || strings.Contains(err.Error(), "Docker Engine 28.0.0 or newer") || strings.Contains(err.Error(), "Docker Compose 2.33.1 or newer") {
					t.Fatalf("expected versioned Docker installation to pass preflight, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected %q, got %v", test.wantError, err)
			}
			if _, statErr := os.Stat(filepath.Join(root, ".env")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("old Docker version created configuration: %v", statErr)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, test := range []struct {
		version string
		minimum string
		want    bool
	}{
		{"v2.33.1", "2.33.1", true},
		{"v5.5.1-desktop.1", "2.33.1", true},
		{"27.10.0", "28.0.0", false},
		{"invalid", "2.33.1", false},
	} {
		if got := versionAtLeast(test.version, test.minimum); got != test.want {
			t.Errorf("versionAtLeast(%q, %q) = %t, want %t", test.version, test.minimum, got, test.want)
		}
	}
}

func TestComposeValidationFailureKeepsSecrets(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{failOn: "config --quiet"}
	var output bytes.Buffer
	err := run(context.Background(), root, strings.NewReader("\n\n\n\n\nmaybe\ny\n"), &output, runner)
	if err == nil || !strings.Contains(err.Error(), "Compose configuration is invalid") {
		t.Fatalf("expected config error, got %v", err)
	}
	if !strings.Contains(output.String(), "Enter y or n") {
		t.Fatal("invalid confirmation was not handled")
	}
	readPrivateFile(t, filepath.Join(root, ".env"))
	if _, err := os.Stat(filepath.Join(root, "secrets", "xray_supervisor_token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("installer created a legacy supervisor token: %v", err)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("invalid Compose config proceeded to up: %v", runner.calls)
	}
}

func TestConfigurationDoesNotCreateSupervisorTokenOrReplaceEnv(t *testing.T) {
	root := t.TempDir()
	secretPath := filepath.Join(root, "secrets", "xray_supervisor_token")
	if err := createConfiguration(root, configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secretPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration created a legacy supervisor token: %v", err)
	}
	firstEnv := readPrivateFile(t, filepath.Join(root, ".env"))
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_EASY_IMAGE_NAMESPACE"] != "dasshit" || values["XRAY_EASY_IMAGE_TAG"] != "latest" {
		t.Fatalf("unexpected default image reference settings: namespace=%q tag=%q", values["XRAY_EASY_IMAGE_NAMESPACE"], values["XRAY_EASY_IMAGE_TAG"])
	}
	if err := createConfiguration(root, configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080}); err == nil {
		t.Fatal("second configuration write replaced .env")
	}
	if got := readPrivateFile(t, filepath.Join(root, ".env")); got != firstEnv {
		t.Fatal("second configuration write replaced .env")
	}
}

func TestConfigurationPersistsDockerImageNamespaceAndTag(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XRAY_EASY_IMAGE_NAMESPACE", "example-namespace")
	t.Setenv("XRAY_EASY_IMAGE_TAG", "v1.2.3")
	if err := createConfiguration(root, configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080}); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if values["XRAY_EASY_IMAGE_NAMESPACE"] != "example-namespace" || values["XRAY_EASY_IMAGE_TAG"] != "v1.2.3" {
		t.Fatalf("Docker image settings were not persisted: namespace=%q tag=%q", values["XRAY_EASY_IMAGE_NAMESPACE"], values["XRAY_EASY_IMAGE_TAG"])
	}
}

func TestInvalidEnvironmentIsRejected(t *testing.T) {
	root := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	for _, line := range []string{
		"XRAY_PUBLIC_PORT=65536",
		"XRAY_EASY_UI_PORT=0",
		"XRAY_PUBLIC_PORT=8080\nXRAY_EASY_UI_PORT=8080",
		"XRAY_PUBLIC_PORT=443\nXRAY_VMESS_PORT=443",
	} {
		env := "XRAY_EASY_MASTER_KEY=" + key + "\n" + line + "\n"
		if err := os.WriteFile(filepath.Join(root, ".env"), []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfiguration(root); err == nil {
			t.Fatalf("invalid configuration accepted: %s", line)
		}
	}
}

func TestPrivateFileWriteAndEnvReaderBoundaries(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "secret")
	if err := writeNewPrivateFile(path, "first"); err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivateFile(path, "second"); err == nil {
		t.Fatal("private file was overwritten")
	}
	if got := readPrivateFile(t, path); got != "first" {
		t.Fatal("private file contents changed")
	}
	if err := writeNewPrivateFile(filepath.Join(root, "missing", "secret"), "value"); err == nil {
		t.Fatal("write to missing directory succeeded")
	}
	if _, err := readEnvironmentFile(filepath.Join(root, "missing.env")); err == nil {
		t.Fatal("missing .env was accepted")
	}
	envPath := filepath.Join(root, ".env")
	if err := os.WriteFile(envPath, []byte("# comment\n  KEY = 'quoted' \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := readEnvironmentFile(envPath)
	if err != nil || values["KEY"] != "quoted" {
		t.Fatalf("quoted .env value rejected: %#v, %v", values, err)
	}
}

func TestSetupRejectsUnusableSecretsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "secrets"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run(context.Background(), root, strings.NewReader("\n\n\n\n\n\n"), &output, &fakeRunner{})
	if err == nil || !strings.Contains(err.Error(), "Hysteria TLS directory") {
		t.Fatalf("expected TLS directory error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed setup wrote .env: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func readPrivateFile(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s has permissions %o, want 0600", path, info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
