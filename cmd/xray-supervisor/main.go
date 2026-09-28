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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"xray-easy/internal/diagnostics"
)

const protocolVersion = "v1"

type config struct {
	configDir  string
	xrayBinary string
	tokenFile  string
	listen     string
	grace      time.Duration
	logSize    int
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
	cfg *config
	log *logBuffer

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
}

func newSupervisor(cfg *config) *supervisor {
	return &supervisor{
		cfg:        cfg,
		log:        newLogBuffer(cfg.logSize),
		state:      "starting",
		usedNonces: make(map[string]time.Time),
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
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if err := s.validate(path); err != nil {
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
	time.Sleep(500 * time.Millisecond)
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
	path, err := s.safePath(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.xrayBinary, "run", "-test", "-config", path)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("xray config validation timed out")
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

type applyRequest struct {
	Path        string `json:"path"`
	OperationID string `json:"operation_id"`
}

type probeRequest struct {
	Target string `json:"target"`
	SNI    string `json:"sni"`
}

func (s *supervisor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/logs", s.handleLogs)
	mux.HandleFunc("/validate", s.handleValidate)
	mux.HandleFunc("/apply", s.handleApply)
	mux.HandleFunc("/probe-target", s.handleProbe)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.authenticate(r, body); err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		mux.ServeHTTP(w, r)
	})
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("request body is too large")
	}
	return body, nil
}

func (s *supervisor) authenticate(r *http.Request, body []byte) error {
	secret, err := os.ReadFile(s.cfg.tokenFile)
	if err != nil || len(secret) == 0 {
		return errors.New("supervisor token is unavailable")
	}
	operation := r.Header.Get("X-Xray-Operation")
	nonce := r.Header.Get("X-Xray-Nonce")
	signature := r.Header.Get("X-Xray-Signature")
	if operation == "" || nonce == "" || signature == "" {
		return errors.New("missing request authentication headers")
	}
	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{r.Method, r.URL.Path, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, bytesTrimSpace(secret))
	_, _ = mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.ToLower(signature))) != 1 {
		return errors.New("invalid request signature")
	}
	if len(nonce) < 16 || len(nonce) > 128 {
		return errors.New("invalid request nonce")
	}
	now := time.Now()
	s.usedNoncesMu.Lock()
	defer s.usedNoncesMu.Unlock()
	for key, seen := range s.usedNonces {
		if now.Sub(seen) > 2*time.Minute {
			delete(s.usedNonces, key)
		}
	}
	if _, exists := s.usedNonces[nonce]; exists {
		return errors.New("request nonce was already used")
	}
	s.usedNonces[nonce] = now
	return nil
}

func bytesTrimSpace(value []byte) []byte { return []byte(strings.TrimSpace(string(value))) }

func (s *supervisor) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state != "running" && state != "no-config" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "state": state, "protocol": protocolVersion})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": state, "protocol": protocolVersion})
}

func (s *supervisor) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid := 0
	if s.child != nil && s.child.Process != nil {
		pid = s.child.Process.Pid
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":      protocolVersion,
		"state":         s.state,
		"pid":           pid,
		"config_path":   s.configPath,
		"last_error":    redact(s.lastError),
		"last_exit":     redact(s.lastExit),
		"restart_count": s.restartCount,
		"started_at":    s.startedAt,
	})
}

func (s *supervisor) handleLogs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"protocol": protocolVersion, "lines": s.log.all()})
}

func (s *supervisor) handleValidate(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.validate(req.Path); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "operation_id": req.OperationID, "protocol": protocolVersion})
}

func (s *supervisor) handleApply(w http.ResponseWriter, r *http.Request) {
	var req applyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.OperationID == "" {
		writeError(w, http.StatusBadRequest, errors.New("operation_id is required"))
		return
	}
	if err := s.apply(req.Path); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "operation_id": req.OperationID, "protocol": protocolVersion})
}

func (s *supervisor) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := probeTarget(req.Target, req.SNI); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "target": req.Target, "protocol": protocolVersion})
}

func probeTarget(target, sni string) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return probeTargetWith(target, sni, net.DefaultResolver.LookupIP, func(address string, config *tls.Config) (net.Conn, error) {
		return tls.DialWithDialer(dialer, "tcp", address, config)
	})
}

func probeTargetWith(target, sni string, lookupIP func(context.Context, string, string) ([]net.IP, error), dialTLS func(string, *tls.Config) (net.Conn, error)) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return errors.New("target must be host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("target port must be between 1 and 65535")
	}
	if sni == "" {
		sni = host
	}
	addresses := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		addresses = append(addresses, ip)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addresses, err = lookupIP(ctx, "ip", host)
		cancel()
		if err != nil {
			return fmt.Errorf("resolve target: %w", err)
		}
	}
	if len(addresses) == 0 {
		return errors.New("target has no addresses")
	}
	for _, address := range addresses {
		if forbiddenProbeIP(address) {
			return errors.New("target resolves to a private or local address")
		}
	}
	// Dial the address returned by the same DNS lookup that passed the SSRF
	// checks. Using the hostname here would allow a DNS rebinding between the
	// check and the TLS connection.
	var lastErr error
	for _, address := range addresses {
		conn, dialErr := dialTLS(net.JoinHostPort(address.String(), port), &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
		if dialErr == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = dialErr
	}
	return fmt.Errorf("TLS probe failed: %w", lastErr)
}

func forbiddenProbeIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"ok": false, "error": redact(err.Error()), "protocol": protocolVersion})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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

func runHealthcheck(url, tokenFile string) error {
	return runHealthcheckWithClient(url, tokenFile, &http.Client{Timeout: 5 * time.Second})
}

func runHealthcheckWithClient(url, tokenFile string, client *http.Client) error {
	body := []byte{}
	nonce := fmt.Sprintf("health-%d", time.Now().UnixNano())
	secret, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	hash := sha256.Sum256(body)
	message := strings.Join([]string{"GET", "/health", "healthcheck", nonce, hex.EncodeToString(hash[:])}, "\n")
	mac := hmac.New(sha256.New, bytesTrimSpace(secret))
	_, _ = mac.Write([]byte(message))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Xray-Operation", "healthcheck")
	req.Header.Set("X-Xray-Nonce", nonce)
	req.Header.Set("X-Xray-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
		url := fs.String("url", "http://127.0.0.1:10086/health", "health endpoint")
		tokenFile := fs.String("token-file", "/run/secrets/xray_supervisor_token", "HMAC token file")
		_ = fs.Parse(os.Args[2:])
		if err := runHealthcheck(*url, *tokenFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	fs := flag.NewFlagSet("xray-supervisor", flag.ExitOnError)
	cfg := &config{}
	fs.StringVar(&cfg.configDir, "config-dir", "/etc/xray", "directory containing active and candidate configs")
	fs.StringVar(&cfg.xrayBinary, "xray-bin", "/usr/local/bin/xray", "Xray binary")
	fs.StringVar(&cfg.tokenFile, "token-file", "/run/secrets/xray_supervisor_token", "HMAC token file")
	fs.StringVar(&cfg.listen, "listen", "0.0.0.0:10086", "private supervisor API address")
	fs.DurationVar(&cfg.grace, "grace-period", 10*time.Second, "grace period for Xray shutdown")
	fs.IntVar(&cfg.logSize, "log-capacity", 200, "number of recent log lines to retain")
	_ = fs.Parse(os.Args[1:])

	s := newSupervisor(cfg)
	if err := s.startInitial(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := &http.Server{Addr: cfg.listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		s.logf("supervisor API listening on %s", cfg.listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logf("supervisor API stopped: %v", err)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	ctx, cancel := context.WithTimeout(context.Background(), cfg.grace)
	defer cancel()
	_ = server.Shutdown(ctx)
	s.stopChild()
}
