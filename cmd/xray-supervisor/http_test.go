package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const supervisorTestToken = "test-token"

func signedRequest(method, path, operation, nonce string, body []byte, token string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	request.Header.Set("X-Xray-Operation", operation)
	request.Header.Set("X-Xray-Nonce", nonce)
	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{method, path, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write([]byte(message))
	request.Header.Set("X-Xray-Signature", hex.EncodeToString(mac.Sum(nil)))
	return request
}

func nextNonce() string {
	return fmt.Sprintf("nonce-%012d", time.Now().UnixNano())
}

func performSupervisorRequest(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	request := signedRequest(method, path, "control-plane", nextNonce(), body, supervisorTestToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSupervisorHTTPAuthAndHealthStatus(t *testing.T) {
	s, _ := newProcessTestSupervisor(t)
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	handler := s.handler()

	response := performSupervisorRequest(handler, http.MethodGet, "/health", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"no-config"`) {
		t.Fatalf("no-config health = %d %s", response.Code, response.Body.String())
	}

	s.mu.Lock()
	s.state = "degraded"
	s.lastError = `failed password="hidden"`
	s.mu.Unlock()
	response = performSupervisorRequest(handler, http.MethodGet, "/health", nil)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "hidden") {
		t.Fatalf("degraded health = %d %s", response.Code, response.Body.String())
	}

	response = performSupervisorRequest(handler, http.MethodGet, "/status", nil)
	var status map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || status["protocol"] != protocolVersion || status["state"] != "degraded" || !strings.Contains(status["last_error"].(string), "[REDACTED]") {
		t.Fatalf("status response = %d %+v", response.Code, status)
	}

	s.log.add(`token="secret"`)
	response = performSupervisorRequest(handler, http.MethodGet, "/logs", nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret") || !strings.Contains(response.Body.String(), "[REDACTED]") {
		t.Fatalf("logs response = %d %s", response.Code, response.Body.String())
	}
	response = performSupervisorRequest(handler, http.MethodGet, "/missing", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", response.Code)
	}
}

func TestSupervisorHTTPRejectsInvalidAuthenticationAndLargeBodies(t *testing.T) {
	s, _ := newProcessTestSupervisor(t)
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	handler := s.handler()

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "missing request authentication") {
		t.Fatalf("unauthenticated response = %d %s", response.Code, response.Body.String())
	}

	for name, mutate := range map[string]func(*http.Request){
		"signature":   func(request *http.Request) { request.Header.Set("X-Xray-Signature", "00") },
		"short nonce": func(request *http.Request) { request.Header.Set("X-Xray-Nonce", "short") },
	} {
		t.Run(name, func(t *testing.T) {
			request := signedRequest(http.MethodGet, "/health", "control-plane", nextNonce(), nil, supervisorTestToken)
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("invalid auth status = %d, body=%s", response.Code, response.Body.String())
			}
		})
	}

	nonce := nextNonce()
	request = signedRequest(http.MethodGet, "/health", "control-plane", nonce, nil, supervisorTestToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("first signed request status = %d", response.Code)
	}
	request = signedRequest(http.MethodGet, "/health", "control-plane", nonce, nil, supervisorTestToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "already used") {
		t.Fatalf("replay response = %d %s", response.Code, response.Body.String())
	}

	// Old nonces expire from the replay cache as the next valid request arrives.
	oldNonce := "an-old-request-nonce"
	s.usedNoncesMu.Lock()
	s.usedNonces[oldNonce] = time.Now().Add(-3 * time.Minute)
	s.usedNoncesMu.Unlock()
	request = signedRequest(http.MethodGet, "/health", "control-plane", nextNonce(), nil, supervisorTestToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("request after nonce expiration = %d", response.Code)
	}
	s.usedNoncesMu.Lock()
	_, oldNonceRetained := s.usedNonces[oldNonce]
	s.usedNoncesMu.Unlock()
	if oldNonceRetained {
		t.Fatal("expired nonce remained in replay cache")
	}

	tooLarge := make([]byte, (1<<20)+1)
	request = signedRequest(http.MethodPost, "/validate", "control-plane", nextNonce(), tooLarge, supervisorTestToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "too large") {
		t.Fatalf("oversized request response = %d %s", response.Code, response.Body.String())
	}
}

func TestSupervisorHTTPTokenUnavailableAndHandlerValidation(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	if err := os.WriteFile(s.cfg.tokenFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	request := signedRequest(http.MethodGet, "/health", "control-plane", nextNonce(), nil, supervisorTestToken)
	response := httptest.NewRecorder()
	s.handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "token is unavailable") {
		t.Fatalf("empty token response = %d %s", response.Code, response.Body.String())
	}
	if err := os.WriteFile(s.cfg.tokenFile, []byte(supervisorTestToken), 0o600); err != nil {
		t.Fatal(err)
	}

	handler := s.handler()
	for name, body := range map[string][]byte{
		"malformed validate": []byte("{"),
		"malformed apply":    []byte("{"),
		"malformed probe":    []byte("{"),
	} {
		t.Run(name, func(t *testing.T) {
			path := "/validate"
			if strings.Contains(name, "apply") {
				path = "/apply"
			} else if strings.Contains(name, "probe") {
				path = "/probe-target"
			}
			response := performSupervisorRequest(handler, http.MethodPost, path, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("malformed request response = %d %s", response.Code, response.Body.String())
			}
		})
	}

	missingOperation, _ := json.Marshal(applyRequest{Path: filepath.Join(configDir, "active.json")})
	response = performSupervisorRequest(handler, http.MethodPost, "/apply", missingOperation)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "operation_id is required") {
		t.Fatalf("missing operation id response = %d %s", response.Code, response.Body.String())
	}

	validPath := writeTestConfig(t, configDir, "candidates/valid.json", "valid")
	validateBody, _ := json.Marshal(applyRequest{Path: validPath, OperationID: "validate-1"})
	response = performSupervisorRequest(handler, http.MethodPost, "/validate", validateBody)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "validate-1") {
		t.Fatalf("valid config response = %d %s", response.Code, response.Body.String())
	}
	invalidBody, _ := json.Marshal(applyRequest{Path: filepath.Join(configDir, "missing.json"), OperationID: "validate-2"})
	response = performSupervisorRequest(handler, http.MethodPost, "/validate", invalidBody)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid config response = %d %s", response.Code, response.Body.String())
	}

	badTarget, _ := json.Marshal(probeRequest{Target: "not-a-host-port", SNI: "test"})
	response = performSupervisorRequest(handler, http.MethodPost, "/probe-target", badTarget)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "host:port") {
		t.Fatalf("invalid probe response = %d %s", response.Code, response.Body.String())
	}
}

func TestSupervisorHTTPApplyStartsChildAndReportsRunningStatus(t *testing.T) {
	s, configDir := newProcessTestSupervisor(t)
	if err := s.startInitial(); err != nil {
		t.Fatal(err)
	}
	candidate := writeTestConfig(t, configDir, "candidates/http-apply.json", "valid")
	body, err := json.Marshal(applyRequest{Path: candidate, OperationID: "http-apply-operation"})
	if err != nil {
		t.Fatal(err)
	}
	response := performSupervisorRequest(s.handler(), http.MethodPost, "/apply", body)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "http-apply-operation") {
		t.Fatalf("HTTP apply response = %d %s", response.Code, response.Body.String())
	}
	waitForSupervisorState(t, s, "running")
	status := httptest.NewRecorder()
	request := signedRequest(http.MethodGet, "/status", "control-plane", nextNonce(), nil, supervisorTestToken)
	s.handler().ServeHTTP(status, request)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"pid":`) || !strings.Contains(status.Body.String(), canonicalTestPath(t, candidate)) {
		t.Fatalf("running status response = %d %s", status.Code, status.Body.String())
	}
	s.stopChild()
	waitForSupervisorState(t, s, "stopped")
}

type failedRequestBody struct{}

func (failedRequestBody) Read([]byte) (int, error) { return 0, errors.New("request read failed") }
func (failedRequestBody) Close() error             { return nil }

func TestSupervisorReadBodyAndAuthenticationBoundaryErrors(t *testing.T) {
	s, _ := newProcessTestSupervisor(t)
	request := httptest.NewRequest(http.MethodPost, "/health", nil)
	request.Body = failedRequestBody{}
	if _, err := readBody(request); err == nil || !strings.Contains(err.Error(), "request read failed") {
		t.Fatalf("readBody error = %v", err)
	}
	tooLong := strings.Repeat("a", 129)
	request = signedRequest(http.MethodGet, "/health", "control-plane", tooLong, nil, supervisorTestToken)
	if err := s.authenticate(request, nil); err == nil || !strings.Contains(err.Error(), "invalid request nonce") {
		t.Fatalf("long nonce error = %v", err)
	}
	if err := os.Remove(s.cfg.tokenFile); err != nil {
		t.Fatal(err)
	}
	request = signedRequest(http.MethodGet, "/health", "control-plane", nextNonce(), nil, supervisorTestToken)
	if err := s.authenticate(request, nil); err == nil || !strings.Contains(err.Error(), "token is unavailable") {
		t.Fatalf("missing token file error = %v", err)
	}
	if err := probeTarget("not-a-host-port", ""); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("invalid direct probe target = %v", err)
	}
	if err := probeTarget("127.0.0.1:443", "localhost"); err == nil || !strings.Contains(err.Error(), "private or local") {
		t.Fatalf("private direct probe target = %v", err)
	}
}

func TestProbeTargetWithInjectedResolverAndDialer(t *testing.T) {
	publicIP := net.ParseIP("93.184.216.34")
	var lookedUp, dialed string
	var dialConfig *tls.Config
	var receivedDeadline bool
	peer, remote := net.Pipe()
	defer remote.Close()
	err := probeTargetWith("example.test:443", "front.example", func(ctx context.Context, network, host string) ([]net.IP, error) {
		lookedUp = network + ":" + host
		_, receivedDeadline = ctx.Deadline()
		return []net.IP{publicIP}, nil
	}, func(address string, config *tls.Config) (net.Conn, error) {
		dialed, dialConfig = address, config
		return peer, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "ip:example.test" || !receivedDeadline || dialed != "93.184.216.34:443" {
		t.Fatalf("lookup/dial = %q, deadline=%v, %q", lookedUp, receivedDeadline, dialed)
	}
	if dialConfig.ServerName != "front.example" || dialConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config = %+v", dialConfig)
	}

	if err := probeTargetWith("93.184.216.34:8443", "", func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("literal IP should not use DNS")
		return nil, nil
	}, func(address string, config *tls.Config) (net.Conn, error) {
		if address != "93.184.216.34:8443" || config.ServerName != "93.184.216.34" {
			t.Fatalf("literal IP dial config = %q %+v", address, config)
		}
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}); err != nil {
		t.Fatalf("public IP probe failed: %v", err)
	}
}

func TestProbeTargetWithRejectsUnsafeAndUnresolvableTargets(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]net.IP, error) {
		switch host {
		case "private.test":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}, nil
		case "empty.test":
			return nil, nil
		case "broken.test":
			return nil, errors.New("DNS unavailable")
		default:
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
	}
	neverDial := func(string, *tls.Config) (net.Conn, error) {
		t.Fatal("unsafe target reached TLS dial")
		return nil, nil
	}
	for _, target := range []string{"", "example.test", "example.test:0", "example.test:65536", "example.test:https"} {
		if err := probeTargetWith(target, "", lookup, neverDial); err == nil {
			t.Errorf("invalid target %q accepted", target)
		}
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "169.254.10.1", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::"} {
		if err := probeTargetWith(net.JoinHostPort(host, "443"), "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), "private or local") {
			t.Errorf("unsafe literal %q error = %v", host, err)
		}
	}
	if err := probeTargetWith("private.test:443", "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), "private or local") {
		t.Fatalf("mixed public/private DNS result error = %v", err)
	}
	if err := probeTargetWith("empty.test:443", "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("empty DNS result error = %v", err)
	}
	if err := probeTargetWith("broken.test:443", "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), "DNS unavailable") {
		t.Fatalf("DNS error = %v", err)
	}
	if err := probeTargetWith("example.test:443", "", lookup, func(string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("handshake failed")
	}); err == nil || !strings.Contains(err.Error(), "TLS probe failed") || !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("TLS dial failure = %v", err)
	}
}

func TestProbeTargetWithRetriesAddressesAndReturnsFinalDialError(t *testing.T) {
	addresses := []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("1.1.1.1")}
	calls := 0
	err := probeTargetWith("multi.example.test:443", "front.example.test", func(context.Context, string, string) ([]net.IP, error) {
		return addresses, nil
	}, func(address string, _ *tls.Config) (net.Conn, error) {
		calls++
		if calls == 1 {
			if address != "93.184.216.34:443" {
				t.Fatalf("first candidate address = %q", address)
			}
			return nil, errors.New("first address timed out")
		}
		if address != "1.1.1.1:443" {
			t.Fatalf("second candidate address = %q", address)
		}
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("probe did not retry the next public address: calls=%d err=%v", calls, err)
	}

	err = probeTargetWith("multi.example.test:443", "", func(context.Context, string, string) ([]net.IP, error) {
		return addresses, nil
	}, func(string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("all addresses timed out")
	})
	if err == nil || !strings.Contains(err.Error(), "all addresses timed out") {
		t.Fatalf("final probe dial error = %v", err)
	}
}

func TestForbiddenProbeIP(t *testing.T) {
	for _, test := range []struct {
		name string
		ip   net.IP
		want bool
	}{
		{name: "public", ip: net.ParseIP("93.184.216.34")},
		{name: "loopback", ip: net.ParseIP("127.0.0.1"), want: true},
		{name: "private", ip: net.ParseIP("192.168.1.1"), want: true},
		{name: "link local", ip: net.ParseIP("169.254.1.1"), want: true},
		{name: "unspecified", ip: net.ParseIP("::"), want: true},
		{name: "multicast", ip: net.ParseIP("ff02::1"), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := forbiddenProbeIP(test.ip); got != test.want {
				t.Fatalf("forbiddenProbeIP(%s) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}

type healthRoundTripFunc func(*http.Request) (*http.Response, error)

func (f healthRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRunHealthcheckSignsRequestAndReportsFailures(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(" test-token \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: healthRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/health" || request.Header.Get("X-Xray-Operation") != "healthcheck" || !strings.HasPrefix(request.Header.Get("X-Xray-Nonce"), "health-") {
			t.Fatalf("healthcheck request = %s %s %+v", request.Method, request.URL, request.Header)
		}
		var body []byte
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
		}
		bodyHash := sha256.Sum256(body)
		message := strings.Join([]string{http.MethodGet, "/health", "healthcheck", request.Header.Get("X-Xray-Nonce"), hex.EncodeToString(bodyHash[:])}, "\n")
		mac := hmac.New(sha256.New, []byte("test-token"))
		_, _ = mac.Write([]byte(message))
		if !hmac.Equal([]byte(request.Header.Get("X-Xray-Signature")), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			t.Fatal("healthcheck signature is invalid")
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header), Request: request}, nil
	})}
	if err := runHealthcheckWithClient("http://supervisor.local/health", tokenFile, client); err != nil {
		t.Fatalf("successful healthcheck: %v", err)
	}
	if err := runHealthcheckWithClient("://bad-url", tokenFile, client); err == nil {
		t.Fatal("malformed healthcheck URL accepted")
	}
	if err := runHealthcheckWithClient("http://supervisor.local/health", filepath.Join(t.TempDir(), "missing"), client); err == nil || !strings.Contains(err.Error(), "read token") {
		t.Fatalf("missing token healthcheck error = %v", err)
	}
	client.Transport = healthRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: request}, nil
	})
	if err := runHealthcheckWithClient("http://supervisor.local/health", tokenFile, client); err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("unhealthy status error = %v", err)
	}
	client.Transport = healthRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })
	if err := runHealthcheckWithClient("http://supervisor.local/health", tokenFile, client); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestRunHealthcheckBuildsDefaultHTTPClient(t *testing.T) {
	err := runHealthcheck("http://127.0.0.1:10086/health", filepath.Join(t.TempDir(), "missing-token"))
	if err == nil || !strings.Contains(err.Error(), "read token") {
		t.Fatalf("healthcheck missing-token error = %v", err)
	}
}
