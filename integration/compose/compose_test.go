//go:build composeintegration

// Package compose contains Docker-backed integration tests for the assembled
// Xray-easy Compose application.
package compose

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	composeStartupTimeout = 10 * time.Minute
	composeTestTimeout    = 35 * time.Minute

	integrationResponse = "xray-easy-integration-ok"
)

// TestComposeFreshInstallSmoke builds and starts a disposable fresh Compose
// installation, runs doctor and connectivity checks, then removes only the
// test project's containers, networks, volumes, and uniquely tagged images.
func TestComposeFreshInstallSmoke(t *testing.T) {
	root := repositoryRoot(t)
	runID := randomRunID(t)
	projectName := os.Getenv("XRAY_EASY_RUNTIME_PROJECT_NAME")
	if projectName == "" {
		projectName = "xray-easy-smoke-" + runID
	}
	if !validProjectName(projectName) {
		t.Fatalf("invalid Compose project name %q", projectName)
	}

	masterKey := randomMasterKey(t)
	values := composeEnvironment(t, runID, masterKey)
	envFile := writeComposeEnvironment(t, values)

	images := []string{
		integrationImage(values["XRAY_EASY_IMAGE_NAMESPACE"], "control-plane", values["XRAY_EASY_IMAGE_TAG"]),
		integrationImage(values["XRAY_EASY_IMAGE_NAMESPACE"], "controller", values["XRAY_EASY_IMAGE_TAG"]),
		integrationImage(values["XRAY_EASY_IMAGE_NAMESPACE"], "xray-core-service", values["XRAY_EASY_IMAGE_TAG"]),
		integrationImage(values["XRAY_EASY_IMAGE_NAMESPACE"], "hysteria-tls-init", values["XRAY_EASY_IMAGE_TAG"]),
	}
	project := &composeProject{
		t:         t,
		root:      root,
		project:   projectName,
		envFile:   envFile,
		masterKey: masterKey,
		images:    images,
		artifact:  os.Getenv("XRAY_EASY_RUNTIME_ARTIFACT_DIR"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), composeTestTimeout)
	defer cancel()
	t.Cleanup(project.cleanup)

	project.assertUnused(ctx)
	t.Log("validating isolated Compose configuration")
	if output, err := project.compose(ctx, "config", "--quiet"); err != nil {
		t.Fatalf("docker compose config failed: %v\n%s", err, output)
	}

	t.Log("building and starting the fresh Compose stack")
	project.started = true // Startup can fail after creating some resources.
	if output, err := project.compose(
		ctx,
		"up", "--detach", "--build", "--wait", "--wait-timeout",
		strconv.Itoa(int(composeStartupTimeout/time.Second)),
	); err != nil {
		t.Fatalf("docker compose up failed: %v\n%s", err, output)
	}
	if output, err := project.compose(ctx, "ps", "--all"); err != nil {
		t.Fatalf("docker compose ps failed: %v\n%s", err, output)
	}

	uiAddress := project.assertLoopbackUI(ctx)
	project.assertUnpublished(ctx, "controller", "10088/tcp")
	project.assertUnpublished(ctx, "xray-core-service", "10086/tcp")
	project.assertUnpublished(ctx, "integration-echo", "8081/tcp")
	project.assertUIHealth(ctx, uiAddress)
	project.assertFreshInstallDoctor(ctx)
	project.assertXrayEgress(ctx)

	t.Logf("Compose smoke passed; Web UI is published at %s", uiAddress)
}

type composeProject struct {
	t         *testing.T
	root      string
	project   string
	envFile   string
	masterKey string
	images    []string
	artifact  string
	started   bool
}

func (p *composeProject) baseArgs() []string {
	return []string{
		"compose",
		"--project-directory", p.root,
		"--env-file", p.envFile,
		"--project-name", p.project,
		"-f", filepath.Join(p.root, "compose.yaml"),
		"-f", filepath.Join(p.root, "scripts", "compose-integration-smoke.override.yaml"),
	}
}

func (p *composeProject) compose(ctx context.Context, args ...string) (string, error) {
	return p.command(ctx, append(p.baseArgs(), args...)...)
}

func (p *composeProject) composeQuiet(ctx context.Context, args ...string) (string, error) {
	return p.commandQuiet(ctx, append(p.baseArgs(), args...)...)
}

func (p *composeProject) command(ctx context.Context, args ...string) (string, error) {
	return p.runCommand(ctx, true, args...)
}

func (p *composeProject) commandQuiet(ctx context.Context, args ...string) (string, error) {
	return p.runCommand(ctx, false, args...)
}

func (p *composeProject) runCommand(ctx context.Context, streamOutput bool, args ...string) (string, error) {
	p.t.Helper()
	command := exec.CommandContext(ctx, "docker", args...)
	command.Dir = p.root
	command.Env = isolatedProcessEnvironment(os.Environ())

	var output bytes.Buffer
	if streamOutput {
		command.Stdout = io.MultiWriter(&output, os.Stdout)
		command.Stderr = io.MultiWriter(&output, os.Stderr)
	} else {
		command.Stdout = &output
		command.Stderr = &output
	}
	err := command.Run()
	return redact(output.String(), p.masterKey), err
}

func (p *composeProject) assertUnused(ctx context.Context) {
	p.t.Helper()
	label := "label=com.docker.compose.project=" + p.project
	resources := []struct {
		name string
		args []string
	}{
		{name: "containers", args: []string{"ps", "--all", "--quiet", "--filter", label}},
		{name: "volumes", args: []string{"volume", "ls", "--quiet", "--filter", label}},
		{name: "networks", args: []string{"network", "ls", "--quiet", "--filter", label}},
	}
	for _, resource := range resources {
		output, err := p.commandQuiet(ctx, resource.args...)
		if err != nil {
			p.t.Fatalf("check existing Docker %s for project %s: %v\n%s", resource.name, p.project, err, output)
		}
		if strings.TrimSpace(output) != "" {
			p.t.Fatalf("refusing to reuse Compose project %q; existing Docker %s use that project name", p.project, resource.name)
		}
	}
}

func (p *composeProject) assertLoopbackUI(ctx context.Context) string {
	p.t.Helper()
	output, err := p.composeQuiet(ctx, "port", "control-plane", "8080")
	if err != nil {
		p.t.Fatalf("read Web UI host binding: %v\n%s", err, output)
	}
	address := strings.TrimSpace(output)
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		p.t.Fatalf("invalid Web UI host binding %q: %v", address, err)
	}
	if host != "127.0.0.1" {
		p.t.Fatalf("Web UI must be published on loopback only; got %s", address)
	}
	return address
}

func (p *composeProject) assertUnpublished(ctx context.Context, service, port string) {
	p.t.Helper()
	output, err := p.composeQuiet(ctx, "ps", "--quiet", service)
	if err != nil {
		p.t.Fatalf("find Compose container for %s: %v\n%s", service, err, output)
	}
	containerID := strings.TrimSpace(output)
	if containerID == "" {
		p.t.Fatalf("expected Compose service %s to be running", service)
	}

	output, err = p.commandQuiet(ctx, "inspect", "--format", "{{json .HostConfig.PortBindings}}", containerID)
	if err != nil {
		p.t.Fatalf("inspect host port bindings for %s: %v\n%s", service, err, output)
	}
	var bindings map[string][]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &bindings); err != nil {
		p.t.Fatalf("decode Docker port bindings for %s: %v; output=%q", service, err, output)
	}
	if len(bindings[port]) != 0 {
		p.t.Fatalf("private service %s port %s must not be published on the host", service, port)
	}
}

func (p *composeProject) assertUIHealth(ctx context.Context, address string) {
	p.t.Helper()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: nil},
	}
	url := "http://" + address + "/api/healthz"
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			p.t.Fatalf("create Web UI health request: %v", err)
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
				return
			}
			lastErr = fmt.Errorf("health endpoint returned HTTP %s", response.Status)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	p.t.Fatalf("Web UI health endpoint is unreachable at %s: %v", url, lastErr)
}

func (p *composeProject) assertFreshInstallDoctor(ctx context.Context) {
	p.t.Helper()
	output, err := p.composeQuiet(ctx, "exec", "--no-TTY", "control-plane", "xray-easy", "doctor")
	p.t.Logf("fresh-install doctor report:\n%s", output)
	if err != nil {
		p.t.Fatalf("fresh-install doctor command failed: %v", err)
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "FAIL  ") {
			p.t.Fatal("doctor reported a failing check")
		}
	}
	if !strings.Contains(output, "Result: PASS (") {
		p.t.Fatal("doctor did not report a passing result")
	}
	if !strings.Contains(output, "WARN  Application setup: initial Web UI setup is still pending") {
		p.t.Fatal("fresh-install doctor output did not include the expected pending-setup warning")
	}
}

func (p *composeProject) assertXrayEgress(ctx context.Context) {
	p.t.Helper()
	output, err := p.composeQuiet(
		ctx,
		"exec", "--no-TTY", "xray-core-service",
		"/bin/busybox", "wget", "-q", "-O", "-", "http://integration-echo:8081/health",
	)
	if err != nil {
		p.t.Fatalf("Xray container could not reach the private integration target: %v\n%s", err, output)
	}
	if strings.TrimSpace(output) != integrationResponse {
		p.t.Fatalf("unexpected local egress response %q", strings.TrimSpace(output))
	}
}

func (p *composeProject) cleanup() {
	p.t.Helper()
	if p.started {
		if p.t.Failed() {
			p.collectFailureDiagnostics()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if output, err := p.composeQuiet(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
			p.t.Errorf("remove test Compose project %s: %v\n%s", p.project, err, output)
		}
	}

	for _, image := range p.images {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		output, err := p.commandQuiet(ctx, "image", "inspect", image)
		cancel()
		if err != nil {
			continue // A failed build may not have created every image.
		}
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		output, err = p.commandQuiet(ctx, "image", "rm", image)
		cancel()
		if err != nil {
			p.t.Errorf("remove test image %s: %v\n%s", image, err, output)
		}
	}
}

func (p *composeProject) collectFailureDiagnostics() {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, diagnostic := range []struct {
		name string
		args []string
	}{
		{name: "compose-ps.txt", args: []string{"ps", "--all"}},
		{name: "compose-logs.txt", args: []string{"logs", "--no-color", "--tail", "300"}},
	} {
		output, err := p.composeQuiet(ctx, diagnostic.args...)
		if err != nil {
			output += "\ncollect diagnostic: " + err.Error()
		}
		p.t.Logf("Compose diagnostic %s:\n%s", diagnostic.name, output)
		if p.artifact == "" {
			continue
		}
		if err := os.MkdirAll(p.artifact, 0700); err != nil {
			p.t.Logf("create diagnostic directory: %v", err)
			continue
		}
		if err := os.Chmod(p.artifact, 0700); err != nil {
			p.t.Logf("secure diagnostic directory: %v", err)
			continue
		}
		path := filepath.Join(p.artifact, diagnostic.name)
		if err := os.WriteFile(path, []byte(output), 0600); err != nil {
			p.t.Logf("write diagnostic file %s: %v", path, err)
		}
	}
}

func composeEnvironment(t *testing.T, runID, masterKey string) map[string]string {
	t.Helper()
	values := map[string]string{
		"XRAY_EASY_MASTER_KEY":            masterKey,
		"XRAY_VERSION":                    "26.7.28",
		"XRAY_EASY_BUILD_VERSION":         "integration-test",
		"XRAY_EASY_IMAGE_NAMESPACE":       "xray-easy-integration",
		"XRAY_EASY_IMAGE_TAG":             "smoke-" + runID,
		"XRAY_EASY_CONTROL_SUBNET":        runtimeSetting("XRAY_EASY_RUNTIME_CONTROL_SUBNET", "172.31.243.0/24"),
		"XRAY_EASY_BACKEND_SUBNET":        runtimeSetting("XRAY_EASY_RUNTIME_BACKEND_SUBNET", "172.31.244.0/24"),
		"XRAY_EASY_XRAY_IP":               runtimeSetting("XRAY_EASY_RUNTIME_XRAY_IP", "172.31.243.2"),
		"XRAY_EASY_AWG_IP":                runtimeSetting("XRAY_EASY_RUNTIME_AWG_IP", "172.31.243.4"),
		"XRAY_EASY_CONTROLLER_CONTROL_IP": runtimeSetting("XRAY_EASY_RUNTIME_CONTROLLER_CONTROL_IP", "172.31.243.5"),
		"XRAY_EASY_CONTROLLER_BACKEND_IP": runtimeSetting("XRAY_EASY_RUNTIME_CONTROLLER_BACKEND_IP", "172.31.244.2"),
		"XRAY_EASY_BACKEND_IP":            runtimeSetting("XRAY_EASY_RUNTIME_BACKEND_IP", "172.31.244.3"),
		"XRAY_EASY_LEASE_CONTROL_IP":      runtimeSetting("XRAY_EASY_RUNTIME_LEASE_CONTROL_IP", "172.31.243.6"),
		"XRAY_EASY_LEASE_BACKEND_IP":      runtimeSetting("XRAY_EASY_RUNTIME_LEASE_BACKEND_IP", "172.31.244.4"),
		"AWG_PUBLIC_HOST":                 runtimeSetting("XRAY_EASY_RUNTIME_AWG_PUBLIC_HOST", ""),
		"AWG_PUBLIC_PORT":                 runtimeSetting("XRAY_EASY_RUNTIME_AWG_PORT", "11234"),
		"COMPOSE_PROFILES":                "",
	}

	portSettings := []struct {
		runtimeKey string
		composeKey string
	}{
		{runtimeKey: "XRAY_EASY_RUNTIME_PUBLIC_PORT", composeKey: "XRAY_PUBLIC_PORT"},
		{runtimeKey: "XRAY_EASY_RUNTIME_VMESS_PORT", composeKey: "XRAY_VMESS_PORT"},
		{runtimeKey: "XRAY_EASY_RUNTIME_SHADOWSOCKS_PORT", composeKey: "XRAY_SHADOWSOCKS_PORT"},
		{runtimeKey: "XRAY_EASY_RUNTIME_TROJAN_PORT", composeKey: "XRAY_TROJAN_PORT"},
		{runtimeKey: "XRAY_EASY_RUNTIME_UI_PORT", composeKey: "XRAY_EASY_UI_PORT"},
	}
	usedPorts := make(map[string]string, len(portSettings))
	for _, setting := range portSettings {
		port := os.Getenv(setting.runtimeKey)
		if port == "" {
			port = freeHostPort(t, usedPorts)
		}
		parsed, err := strconv.Atoi(port)
		if err != nil || parsed < 1 || parsed > 65535 {
			t.Fatalf("%s must be a TCP/UDP port from 1 to 65535; got %q", setting.runtimeKey, port)
		}
		if previous, exists := usedPorts[port]; exists {
			t.Fatalf("host port %s is assigned to both %s and %s", port, previous, setting.runtimeKey)
		}
		usedPorts[port] = setting.runtimeKey
		values[setting.composeKey] = port
	}

	return values
}

func freeHostPort(t *testing.T, used map[string]string) string {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve temporary host port: %v", err)
		}
		port := strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port)
		udpListener, udpErr := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", port))
		_ = tcpListener.Close()
		if udpErr != nil {
			continue
		}
		_ = udpListener.Close()
		if _, exists := used[port]; !exists {
			return port
		}
	}
	t.Fatal("could not allocate a distinct temporary host port")
	return ""
}

func writeComposeEnvironment(t *testing.T, values map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "compose.env")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var content strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&content, "%s=%s\n", key, values[key])
	}
	if err := os.WriteFile(path, []byte(content.String()), 0600); err != nil {
		t.Fatalf("write isolated Compose environment: %v", err)
	}
	return path
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate integration test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}

func randomRunID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 8)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate unique test identifier: %v", err)
	}
	return hex.EncodeToString(value)
}

func randomMasterKey(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate temporary master key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(value)
}

func validProjectName(value string) bool {
	if value == "" {
		return false
	}
	firstIsLowercase := value[0] >= 'a' && value[0] <= 'z'
	firstIsDigit := value[0] >= '0' && value[0] <= '9'
	if !firstIsLowercase && !firstIsDigit {
		return false
	}
	for _, char := range value {
		if char < 'a' || char > 'z' {
			if char < '0' || char > '9' {
				if char != '-' && char != '_' {
					return false
				}
			}
		}
	}
	return true
}

func integrationImage(namespace, service, tag string) string {
	return fmt.Sprintf("ghcr.io/%s/xray-easy/%s:%s", namespace, service, tag)
}

func runtimeSetting(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func isolatedProcessEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, value := range environment {
		key, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(key, "XRAY_") || strings.HasPrefix(key, "AWG_") || strings.HasPrefix(key, "COMPOSE_") {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func redact(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[REDACTED]")
}
