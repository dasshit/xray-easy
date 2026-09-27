package supervisor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL   string
	TokenFile string
	HTTP      *http.Client
}

type operationRequest struct {
	Path        string `json:"path"`
	OperationID string `json:"operation_id"`
}

type probeRequest struct {
	Target string `json:"target"`
	SNI    string `json:"sni"`
}

func (c Client) Validate(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, http.MethodPost, "/validate", operationRequest{Path: path, OperationID: operationID})
	return err
}

func (c Client) Apply(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, http.MethodPost, "/apply", operationRequest{Path: path, OperationID: operationID})
	return err
}

func (c Client) ProbeTarget(ctx context.Context, target, sni string) error {
	_, err := c.call(ctx, http.MethodPost, "/probe-target", probeRequest{Target: target, SNI: sni})
	return err
}

func (c Client) Health(ctx context.Context) error {
	_, err := c.call(ctx, http.MethodGet, "/health", nil)
	return err
}

func (c Client) call(ctx context.Context, method, path string, payload any) ([]byte, error) {
	body := []byte{}
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = encoded
	}
	secret, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read supervisor token: %w", err)
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) == 0 {
		return nil, errors.New("supervisor token is empty")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	operation := "control-plane"
	bodyHash := sha256.Sum256(body)
	message := strings.Join([]string{method, path, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(message))
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Xray-Operation", operation)
	req.Header.Set("X-Xray-Nonce", nonce)
	req.Header.Set("X-Xray-Signature", hex.EncodeToString(mac.Sum(nil)))
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("supervisor %s returned %s: %s", path, response.Status, strings.TrimSpace(string(responseBody)))
	}
	return responseBody, nil
}
