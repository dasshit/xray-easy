package runtime

import (
	"strconv"
	"testing"
	"time"
)

func TestRuntimeGenerationIsStableAndEmptyBeforeStart(t *testing.T) {
	if got := runtimeGeneration(time.Time{}); got != "" {
		t.Fatalf("runtimeGeneration(zero) = %q, want empty", got)
	}
	startedAt := time.Unix(123, 456).UTC()
	want := strconv.FormatInt(startedAt.UnixNano(), 10)
	if got := runtimeGeneration(startedAt); got != want {
		t.Fatalf("runtimeGeneration() = %q, want %q", got, want)
	}
}

func TestConfiguredLogLevelUsesConfiguredValueOrWarningDefault(t *testing.T) {
	for _, test := range []struct {
		name          string
		configuration []byte
		want          string
	}{
		{name: "configured and normalized", configuration: []byte(`{"log":{"loglevel":" DEBUG "}}`), want: "debug"},
		{name: "empty value", configuration: []byte(`{"log":{"loglevel":"  "}}`), want: "warning"},
		{name: "malformed config", configuration: []byte(`{`), want: "warning"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := configuredLogLevel(test.configuration); got != test.want {
				t.Fatalf("configuredLogLevel() = %q, want %q", got, test.want)
			}
		})
	}
}
