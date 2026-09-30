// Command xray-supervisor owns the Xray child process and exposes a small,
// private control API to the xray-easy control plane.
//
// The supervisor deliberately does not write Xray configuration files. The
// control plane creates an immutable candidate and asks the supervisor to
// validate or apply that candidate.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"xray-easy/internal/diagnostics"
	supervisorapi "xray-easy/internal/supervisor"
)

const protocolVersion = "v1"

type config struct {
	configDir     string
	xrayBinary    string
	xrayAPI       string
	tokenFile     string
	listen        string
	grace         time.Duration
	logSize       int
	listenFunc    func(string, string) (net.Listener, error)
	probeTargetFn func(context.Context, string, string) error
}

type logBuffer struct {
	mu    sync.Mutex
	lines []string
	limit int
}

func newLogBuffer(limit int) *logBuffer {
	if limit < 1 {
		limit = 100
	}
	return &logBuffer{limit: limit}
}

func (b *logBuffer) add(line string) {
	line = redact(line)
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.lines) >= b.limit {
		copy(b.lines, b.lines[1:])
		b.lines = b.lines[:b.limit-1]
	}
	b.lines = append(b.lines, line)
}

func (b *logBuffer) all() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...)
}

type supervisor struct {
	cfg         *config
	log         *logBuffer
	xrayVersion string

	applyMu      sync.Mutex
	mu           sync.Mutex
	child        *exec.Cmd
	childDone    chan error
	configPath   string
	state        string
	lastError    string
	lastExit     string
	restartCount int
	startedAt    time.Time
	usedNoncesMu sync.Mutex
	usedNonces   map[string]time.Time
	ipv6ProbeFn  func(context.Context) error
}

func newSupervisor(cfg *config) *supervisor {
	version := "unknown"
	if output, err := exec.Command(cfg.xrayBinary, "version").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
			version = strings.TrimSpace(lines[0])
		}
	}
	return &supervisor{
		cfg:         cfg,
		log:         newLogBuffer(cfg.logSize),
		xrayVersion: version,
		state:       "starting",
		usedNonces:  make(map[string]time.Time),
	}
}

func (s *supervisor) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	s.log.add(line)
	fmt.Fprintln(os.Stderr, redact(line))
}

func (s *supervisor) startInitial() error {
	active := filepath.Join(s.cfg.configDir, "active.json")
	if _, err := os.Stat(active); errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		s.state = "no-config"
		s.mu.Unlock()
		s.logf("no active.json; supervisor is ready for the first apply")
		return nil
	}
	if err := s.startChild(active); err != nil {
		return err
	}
	return nil
}

func (s *supervisor) startChild(path string) error {
	path, err := s.safePath(path)
	if err != nil {
		return err
	}
	cmd := exec.Command(s.cfg.xrayBinary, "run", "-config", path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}

	s.mu.Lock()
	s.child = cmd
	s.childDone = make(chan error, 1)
	s.configPath = path
	s.state = "running"
	s.lastError = ""
	s.lastExit = ""
	s.restartCount++
	s.startedAt = time.Now().UTC()
	done := s.childDone
	s.mu.Unlock()

	go s.capture(stdout)
	go s.capture(stderr)
	go func() {
		err := cmd.Wait()
		done <- err
		s.mu.Lock()
		if s.child == cmd {
			s.child = nil
			s.state = "stopped"
			s.lastExit = formatExit(err)
			if err != nil {
				s.lastError = err.Error()
			}
		}
		s.mu.Unlock()
		s.logf("xray exited: %s", formatExit(err))
	}()
	s.logf("started xray with %s", filepath.Base(path))
	return nil
}

func (s *supervisor) capture(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := redact(scanner.Text())
		s.log.add(line)
		fmt.Fprintln(os.Stderr, line)
	}
}

func (s *supervisor) stopChild() {
	s.mu.Lock()
	cmd := s.child
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-time.After(s.cfg.grace):
		_ = cmd.Process.Kill()
	case <-func() <-chan error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.childDone
	}():
	}
}

func (s *supervisor) apply(path string) error {
	return s.applyContext(context.Background(), path)
}

func (s *supervisor) applyContext(ctx context.Context, path string) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if err := s.validateContext(ctx, path); err != nil {
		return err
	}
	// The control plane only promotes a candidate to active.json after this
	// call succeeds. Keep that stable path as the rollback target while the
	// candidate is being started.
	previous := filepath.Join(s.cfg.configDir, "active.json")
	s.stopChild()
	if err := s.startChild(path); err != nil {
		s.rollback(previous, err)
		return err
	}
	startupTimer := time.NewTimer(500 * time.Millisecond)
	defer startupTimer.Stop()
	select {
	case <-ctx.Done():
		s.stopChild()
		s.rollback(previous, ctx.Err())
		return ctx.Err()
	case <-startupTimer.C:
	}
	s.mu.Lock()
	state := s.state
	lastError := s.lastError
	lastExit := s.lastExit
	s.mu.Unlock()
	if state != "running" {
		if lastError == "" {
			lastError = lastExit
		}
		if lastError == "" {
			lastError = "Xray exited during startup"
		}
		err := errors.New(lastError)
		s.rollback(previous, err)
		return err
	}
	return nil
}

func (s *supervisor) rollback(previous string, cause error) {
	if _, err := os.Stat(previous); err != nil {
		s.mu.Lock()
		s.state = "degraded"
		s.lastError = cause.Error()
		s.mu.Unlock()
		return
	}
	if err := s.startChild(previous); err != nil {
		s.mu.Lock()
		s.state = "degraded"
		s.lastError = fmt.Sprintf("%v; rollback failed: %v", cause, err)
		s.mu.Unlock()
		return
	}
	s.logf("candidate rejected; restored active.json")
}

func (s *supervisor) validate(path string) error {
	return s.validateContext(context.Background(), path)
}

func (s *supervisor) validateContext(parent context.Context, path string) error {
	path, err := s.safePath(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.xrayBinary, "run", "-test", "-config", path)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("xray config validation timed out: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("xray config validation failed: %s", redact(strings.TrimSpace(string(out))))
	}
	return nil
}

func (s *supervisor) safePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("config path is required")
	}
	base, err := filepath.Abs(s.cfg.configDir)
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	full, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	full, err = filepath.EvalSymlinks(full)
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("config path must be inside config directory")
	}
	return full, nil
}

type replaceInboundRequest struct {
	CandidatePath string `json:"candidate_path"`
	PreviousPath  string `json:"previous_path"`
	Tag           string `json:"tag"`
	OperationID   string `json:"operation_id"`
}

// replaceInbound performs Xray's native RemoveInbound/AddInbound sequence.
// It briefly interrupts connections on the selected tag, but leaves the Xray
// process and every other inbound running.
func (s *supervisor) replaceInbound(req replaceInboundRequest) error {
	return s.replaceInboundContext(context.Background(), req)
}

func (s *supervisor) replaceInboundContext(parent context.Context, req replaceInboundRequest) error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.cfg.xrayAPI == "" {
		return errors.New("Xray API address is not configured in supervisor")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(req.Tag) {
		return errors.New("invalid inbound tag")
	}
	s.mu.Lock()
	running := s.state == "running" && s.child != nil && s.child.Process != nil
	s.mu.Unlock()
	if !running {
		return errors.New("Xray is not running")
	}
	candidatePath, err := s.safePath(req.CandidatePath)
	if err != nil {
		return err
	}
	previousPath, err := s.safePath(req.PreviousPath)
	if err != nil {
		return err
	}
	candidateInbound, candidateFound, err := optionalInboundFile(candidatePath, req.Tag)
	if err != nil {
		return fmt.Errorf("read candidate inbound: %w", err)
	}
	if candidateFound {
		defer os.Remove(candidateInbound)
	}
	previousInbound, previousFound, err := optionalInboundFile(previousPath, req.Tag)
	if err != nil {
		return fmt.Errorf("read previous inbound for rollback: %w", err)
	}
	if previousFound {
		defer os.Remove(previousInbound)
	}
	if !candidateFound && !previousFound {
		return errors.New("inbound is absent from both candidate and active configurations")
	}

	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	if previousFound {
		if err := s.runXrayAPI(ctx, "rmi", "--server="+s.cfg.xrayAPI, "--timeout=20", req.Tag); err != nil {
			return errors.New("Xray rejected RemoveInbound")
		}
	}
	if candidateFound {
		if err := s.runXrayAPI(ctx, "adi", "--server="+s.cfg.xrayAPI, "--timeout=20", candidateInbound); err != nil {
			if !previousFound {
				return errors.New("Xray rejected AddInbound")
			}
			rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 30*time.Second)
			rollbackErr := s.runXrayAPI(rollbackCtx, "adi", "--server="+s.cfg.xrayAPI, "--timeout=20", previousInbound)
			rollbackCancel()
			if rollbackErr != nil {
				s.logf("inbound replacement failed; rollback also failed for tag %s", req.Tag)
				return errors.New("Xray rejected AddInbound and the previous inbound could not be restored")
			}
			s.logf("inbound replacement failed; restored tag %s", req.Tag)
			return errors.New("Xray rejected AddInbound; previous inbound restored")
		}
		s.logf("replaced inbound %s without restarting the Xray process", req.Tag)
		return nil
	}
	s.logf("removed inbound %s without restarting the Xray process", req.Tag)
	return nil
}

func (s *supervisor) runXrayAPI(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, s.cfg.xrayBinary, append([]string{"api"}, args...)...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Xray CLI output can contain fragments of the submitted configuration;
		// keep it out of the API response and persistent logs.
		_ = output
		return errors.New("Xray API command failed")
	}
	return nil
}

func inboundOnlyFile(configPath, tag string) (string, error) {
	path, found, err := optionalInboundFile(configPath, tag)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("inbound %q was not found", tag)
	}
	return path, nil
}

func optionalInboundFile(configPath, tag string) (string, bool, error) {
	return optionalInboundFileWith(configPath, tag, func() (inboundTempFile, error) {
		return os.CreateTemp("", "xray-inbound-*.json")
	})
}

type inboundTempFile interface {
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Name() string
	Close() error
}

func optionalInboundFileWith(configPath, tag string, createTemp func() (inboundTempFile, error)) (string, bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", false, err
	}
	var config struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return "", false, errors.New("invalid Xray config")
	}
	for _, raw := range config.Inbounds {
		var inbound struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &inbound); err != nil {
			return "", false, errors.New("invalid Xray inbound")
		}
		if inbound.Tag == tag {
			content, err := json.Marshal(struct {
				Inbounds []json.RawMessage `json:"inbounds"`
			}{Inbounds: []json.RawMessage{raw}})
			if err != nil {
				return "", false, err
			}
			file, err := createTemp()
			if err != nil {
				return "", false, err
			}
			if _, err := file.Write(content); err != nil {
				_ = file.Close()
				_ = os.Remove(file.Name())
				return "", false, err
			}
			if err := file.Chmod(0o600); err != nil {
				_ = file.Close()
				_ = os.Remove(file.Name())
				return "", false, err
			}
			if err := file.Close(); err != nil {
				_ = os.Remove(file.Name())
				return "", false, err
			}
			return file.Name(), true, nil
		}
	}
	return "", false, nil
}

func formatExit(err error) string {
	if err == nil {
		return "clean exit"
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Error()
	}
	return err.Error()
}

func redact(value string) string {
	return diagnostics.Redact(value)
}

func runHealthcheck(address, tokenFile string) error {
	client, err := supervisorapi.DialWithOperation(address, tokenFile, "healthcheck")
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.Health(ctx)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
		address := fs.String("addr", "127.0.0.1:10086", "supervisor gRPC address")
		tokenFile := fs.String("token-file", "/run/secrets/xray_supervisor_token", "HMAC token file")
		_ = fs.Parse(os.Args[2:])
		if err := runHealthcheck(*address, *tokenFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	fs := flag.NewFlagSet("xray-supervisor", flag.ExitOnError)
	cfg := &config{}
	fs.StringVar(&cfg.configDir, "config-dir", "/etc/xray", "directory containing active and candidate configs")
	fs.StringVar(&cfg.xrayBinary, "xray-bin", "/usr/local/bin/xray", "Xray binary")
	fs.StringVar(&cfg.xrayAPI, "xray-api", "127.0.0.1:10085", "private Xray gRPC API address")
	fs.StringVar(&cfg.tokenFile, "token-file", "/run/secrets/xray_supervisor_token", "HMAC token file")
	fs.StringVar(&cfg.listen, "listen", "127.0.0.1:10086", "private supervisor gRPC address")
	fs.DurationVar(&cfg.grace, "grace-period", 10*time.Second, "grace period for Xray shutdown")
	fs.IntVar(&cfg.logSize, "log-capacity", 200, "number of recent log lines to retain")
	_ = fs.Parse(os.Args[1:])

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	if err := runSupervisor(cfg, signals); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
