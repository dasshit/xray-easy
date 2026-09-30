package interaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogRPCRecordsSafeStructuredFields(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	secret := "private-key-must-not-be-logged"
	LogRPC(logger, "controller", "/controller.v1.Controller/GetStatus", "trace-1", "xray", time.Now(), errors.New(secret), Trace{OperationID: "operation-1", Attempt: 3, StateRevision: 42})
	var fields map[string]any
	if err := json.Unmarshal(output.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"service": "controller", "method": "/controller.v1.Controller/GetStatus",
		"request_id": "trace-1", "controller_operation_id": "operation-1", "protocol": "xray", "result": "failure", "grpc_code": "Unknown",
	} {
		if fields[key] != want {
			t.Errorf("field %q = %v, want %q", key, fields[key], want)
		}
	}
	if fields["retry_attempt"] != float64(3) {
		t.Errorf("retry_attempt = %v, want 3", fields["retry_attempt"])
	}
	if fields["state_revision"] != float64(42) {
		t.Errorf("state_revision = %v, want 42", fields["state_revision"])
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("log contains raw error: %s", output.String())
	}
}

func TestLogRPCHandlesNilLoggerAndSuccess(t *testing.T) {
	LogRPC(nil, "service", "method", "request", "none", time.Now(), nil)
}
