package runtime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validValidatorConfig = `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`

func TestValidateConfigIsolatedRunsAndMapsChildResults(t *testing.T) {
	success := writeValidatorFixture(t, "#!/bin/sh\n[ \"$1\" = validate-candidate ] || exit 7\ncat >/dev/null\nexit 0\n")
	previousExecutable := runtimeExecutable
	t.Cleanup(func() { runtimeExecutable = previousExecutable })
	runtimeExecutable = func() (string, error) { return success, nil }
	if err := ValidateConfigIsolated([]byte(validValidatorConfig)); err != nil {
		t.Fatalf("isolated config validation: %v", err)
	}
	if err := ValidateConfigIsolatedContext(nil, []byte(validValidatorConfig)); err != nil {
		t.Fatalf("nil-context isolated validation: %v", err)
	}

	runtimeExecutable = func() (string, error) { return "", errors.New("executable unavailable") }
	if err := ValidateConfigIsolatedContext(context.Background(), []byte(validValidatorConfig)); err == nil || !strings.Contains(err.Error(), "locate runtime executable") {
		t.Fatalf("executable lookup error = %v", err)
	}

	failure := writeValidatorFixture(t, "#!/bin/sh\ncat >/dev/null\nexit 9\n")
	runtimeExecutable = func() (string, error) { return failure, nil }
	if err := ValidateConfigIsolatedContext(context.Background(), []byte(validValidatorConfig)); err == nil || !strings.Contains(err.Error(), "isolated Xray runtime validation failed") {
		t.Fatalf("child failure = %v", err)
	}
	if err := ValidateConfigIsolatedContext(context.Background(), []byte(`{"inbounds":[`)); err == nil || !strings.Contains(err.Error(), "parse Xray configuration") {
		t.Fatalf("builder validation error = %v", err)
	}

	sleep := writeValidatorFixture(t, "#!/bin/sh\nexec sleep 5\n")
	runtimeExecutable = func() (string, error) { return sleep, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := ValidateConfigIsolatedContext(ctx, []byte(validValidatorConfig)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline validation error = %v", err)
	}
	canceled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	if err := ValidateConfigIsolatedContext(canceled, []byte(validValidatorConfig)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled validation error = %v", err)
	}
}

func TestEngineStatsAvailabilityAndUninitializedLifecycle(t *testing.T) {
	var nilEngine *Engine
	if nilEngine.StatsAvailable() {
		t.Fatal("nil engine advertised stats")
	}
	if err := nilEngine.Start(); err == nil {
		t.Fatal("nil engine started")
	}
	if err := nilEngine.Close(); err != nil {
		t.Fatalf("close nil engine: %v", err)
	}
	if (&Engine{}).StatsAvailable() {
		t.Fatal("engine without a core instance advertised stats")
	}
	if err := (&Engine{}).Start(); err == nil {
		t.Fatal("engine without a core instance started")
	}

	withoutStats, err := LoadEngine([]byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer withoutStats.Close()
	if withoutStats.StatsAvailable() {
		t.Fatal("default Xray no-op stats manager was reported as available")
	}
	if _, err := withoutStats.GetTelemetry(context.Background(), nil); err == nil {
		t.Fatal("telemetry unexpectedly worked with Xray no-op stats manager")
	}

	withStats, err := LoadEngine([]byte(`{"stats":{},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer withStats.Close()
	if !withStats.StatsAvailable() {
		t.Fatal("configured Xray stats manager was not reported as available")
	}
}

func TestEngineStartReturnsListenerBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	engine, err := LoadEngine(vlessTestConfiguration(port))
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	defer engine.Close()
	if err := engine.Start(); err == nil {
		t.Fatal("Xray listener started on an occupied port")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeValidatorFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "validator")
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
