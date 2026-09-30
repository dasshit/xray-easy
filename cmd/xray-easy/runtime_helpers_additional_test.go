package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"xray-easy/internal/domain"
)

func TestRuntimeConfigurationComparisonHelpers(t *testing.T) {
	if _, err := newHysteriaAuth(); err != nil {
		t.Fatalf("newHysteriaAuth() error = %v", err)
	}
	settings := rendererSettings(domain.Settings{
		PublicHost: "vpn.example.test", PublicPort: 443, RealityTarget: "www.example.test:443",
		RealitySNI: "www.example.test", ClientFingerprint: "chrome", LogLevel: "warning",
	}, "private-key")
	if settings.PublicHost != "vpn.example.test" || settings.RealityPrivateKey != "private-key" || settings.VMessPublicPort != 9443 {
		t.Fatalf("renderer settings were not mapped: %+v", settings)
	}

	expected := map[string]struct{}{"one": {}, "two": {}}
	if !stringSliceMatchesSet([]string{"two", "one"}, expected) {
		t.Fatal("matching set was rejected")
	}
	if stringSliceMatchesSet([]string{"one"}, expected) || stringSliceMatchesSet([]string{"one", "other"}, expected) || stringSliceMatchesSet([]string{"one", "one"}, expected) {
		t.Fatal("mismatched or duplicate values were accepted")
	}
	if !sameStringSet(expected, map[string]struct{}{"two": {}, "one": {}}) || sameStringSet(expected, map[string]struct{}{"one": {}, "three": {}}) || sameStringSet(expected, map[string]struct{}{"one": {}}) {
		t.Fatal("set equality did not distinguish identical and different key sets")
	}
	if vmessInboundExpected([]domain.Client{{Protocol: domain.ProtocolVMess, VMessRevoked: true}}) || !vmessInboundExpected([]domain.Client{{Protocol: domain.ProtocolVMess, VMessRevoked: false}}) {
		t.Fatal("VMess topology expectation did not account for revocation")
	}
}

func TestActiveRealityShortIDReaderValidatesFileAndFindsTaggedInbound(t *testing.T) {
	if _, err := activeRealityShortIDs(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing active config was accepted")
	}
	path := filepath.Join(t.TempDir(), "active.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := activeRealityShortIDs(path); err == nil {
		t.Fatal("malformed active config was accepted")
	}
	data, err := json.Marshal(map[string]any{"inbounds": []any{
		map[string]any{"tag": "other"},
		map[string]any{"tag": "vless-reality", "streamSettings": map[string]any{"realitySettings": map[string]any{"shortIds": []string{"a", "b"}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := activeRealityShortIDs(path)
	if err != nil || len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("active REALITY short IDs = %v, %v", ids, err)
	}
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"tag":"other"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ids, err := activeRealityShortIDs(path); err != nil || len(ids) != 0 {
		t.Fatalf("config without REALITY inbound = %v, %v", ids, err)
	}
}

func TestReadTerminalLineClearsPartialPasswordAtEOF(t *testing.T) {
	original := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("partial-secret")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = original
		_ = reader.Close()
	})
	value, err := readTerminalLine()
	if !errors.Is(err, io.EOF) || value != nil {
		t.Fatalf("readTerminalLine() = %q, %v; want no value on EOF", value, err)
	}
}
