package supervisor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func responseFor(request *http.Request, statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func TestClientMethodsSignRequestsAndDecodeResponses(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("  shared-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests []*http.Request
	client := Client{
		BaseURL:   "http://supervisor.local/",
		TokenFile: tokenFile,
		HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests = append(requests, request)
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			if err := verifyControlSignature(request, body, []byte("shared-token")); err != nil {
				return nil, err
			}
			switch request.URL.Path {
			case "/replace-inbound":
				var payload replaceInboundRequest
				if err := json.Unmarshal(body, &payload); err != nil {
					return nil, err
				}
				if payload.CandidatePath != "/etc/xray/candidate.json" || payload.PreviousPath != "/etc/xray/active.json" || payload.Tag != "vless-reality" || payload.OperationID != "op-3" {
					return nil, fmt.Errorf("unexpected replace-inbound payload: %+v", payload)
				}
				return responseFor(request, http.StatusOK, `{"ok":true}`), nil
			case "/status":
				return responseFor(request, http.StatusOK, `{"protocol":"v1","state":"running","pid":123,"restart_count":4,"last_error":""}`), nil
			case "/logs":
				return responseFor(request, http.StatusOK, `{"lines":["one","two"]}`), nil
			default:
				return responseFor(request, http.StatusOK, `{"ok":true}`), nil
			}
		})},
	}
	ctx := context.Background()
	if err := client.Validate(ctx, "/etc/xray/candidate.json", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := client.Apply(ctx, "/etc/xray/candidate.json", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := client.ReplaceInbound(ctx, "/etc/xray/candidate.json", "/etc/xray/active.json", "vless-reality", "op-3"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeTarget(ctx, "example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := client.ProbeIPv6(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Health(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(ctx)
	if err != nil || status.Protocol != "v1" || status.State != "running" || status.PID != 123 || status.RestartCount != 4 {
		t.Fatalf("Status() = %+v, %v", status, err)
	}
	logs, err := client.Logs(ctx)
	if err != nil || len(logs) != 2 || logs[0] != "one" || logs[1] != "two" {
		t.Fatalf("Logs() = %v, %v", logs, err)
	}
	if len(requests) != 8 {
		t.Fatalf("requests = %d, want 8", len(requests))
	}
	wantPaths := []string{"/validate", "/apply", "/replace-inbound", "/probe-target", "/probe-ipv6", "/health", "/status", "/logs"}
	for i, request := range requests {
		if request.URL.Path != wantPaths[i] || request.Header.Get("X-Xray-Operation") != "control-plane" || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %d headers/path = %s %+v", i, request.URL.Path, request.Header)
		}
	}
}

func verifyControlSignature(request *http.Request, body, key []byte) error {
	operation := request.Header.Get("X-Xray-Operation")
	nonce := request.Header.Get("X-Xray-Nonce")
	signature := request.Header.Get("X-Xray-Signature")
	if operation != "control-plane" || len(nonce) != 32 {
		return fmt.Errorf("invalid authentication headers: operation=%q nonce=%q", operation, nonce)
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return fmt.Errorf("nonce is not hex: %w", err)
	}
	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{request.Method, request.URL.Path, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	if !hmac.Equal([]byte(signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return errors.New("invalid HMAC signature")
	}
	return nil
}

func TestClientReportsTokenAndRequestErrors(t *testing.T) {
	client := Client{BaseURL: "http://supervisor.local", TokenFile: filepath.Join(t.TempDir(), "missing"), HTTP: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected request"); return nil, nil })}}
	if err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "read supervisor token") {
		t.Fatalf("missing token error = %v", err)
	}
	token := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(token, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client.TokenFile = token
	if err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "token is empty") {
		t.Fatalf("empty token error = %v", err)
	}
	if err := os.WriteFile(token, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	client.TokenFile = token
	client.BaseURL = "://bad"
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("invalid URL accepted")
	}
	client.BaseURL = "http://supervisor.local"
	client.HTTP = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport down") })}
	if err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "transport down") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestClientReportsHTTPStatusAndDecodeFailures(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{BaseURL: "http://supervisor.local", TokenFile: token}
	client.HTTP = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return responseFor(request, http.StatusUnprocessableEntity, `{"error":"bad candidate"}`), nil
	})}
	if err := client.Validate(context.Background(), "candidate", "op"); err == nil || !strings.Contains(err.Error(), "returned 422") || !strings.Contains(err.Error(), "bad candidate") {
		t.Fatalf("HTTP status error = %v", err)
	}
	client.HTTP = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/status" {
			return responseFor(request, http.StatusOK, "not-json"), nil
		}
		return responseFor(request, http.StatusOK, "{}"), nil
	})}
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "decode supervisor status") {
		t.Fatalf("invalid status JSON error = %v", err)
	}
	if _, err := client.Logs(context.Background()); err != nil {
		t.Fatalf("empty logs JSON object should decode: %v", err)
	}
	client.HTTP = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return responseFor(request, http.StatusOK, "not-json"), nil
	})}
	if _, err := client.Logs(context.Background()); err == nil || !strings.Contains(err.Error(), "decode supervisor logs") {
		t.Fatalf("invalid logs JSON error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read response failed") }
func (errorReader) Close() error             { return nil }

func TestClientReportsResponseReadError(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{BaseURL: "http://supervisor.local", TokenFile: token, HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: errorReader{}, Request: request}, nil
	})}}
	if err := client.Health(context.Background()); err == nil || err.Error() != "read response failed" {
		t.Fatalf("response read error = %v", err)
	}
}

func TestClientStatusStartedAtDecode(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	startedAt := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]any{"started_at": startedAt.Format(time.RFC3339Nano)})
	client := Client{BaseURL: "http://supervisor.local", TokenFile: token, HTTP: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return responseFor(request, http.StatusOK, string(body)), nil
	})}}
	status, err := client.Status(context.Background())
	if err != nil || !status.StartedAt.Equal(startedAt) {
		t.Fatalf("decoded StartedAt = %v, %v", status.StartedAt, err)
	}
}
