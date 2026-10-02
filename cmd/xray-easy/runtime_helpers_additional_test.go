package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestNormalizeShadowsocks2022UserKeyPreservesLegacyBytes(t *testing.T) {
	original := bytes.Repeat([]byte{0xff}, 32)
	legacy := base64.RawURLEncoding.EncodeToString(original)
	want := base64.StdEncoding.EncodeToString(original)
	for _, value := range []string{legacy, want} {
		got, err := normalizeShadowsocks2022UserKey(value)
		if err != nil || got != want {
			t.Errorf("normalizeShadowsocks2022UserKey(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	for _, value := range []string{"bad", base64.StdEncoding.EncodeToString([]byte("short")), strings.Repeat("A", 44), want + "\n"} {
		if got, err := normalizeShadowsocks2022UserKey(value); err == nil || got != "" {
			t.Errorf("invalid key %q normalized to %q, %v", value, got, err)
		}
	}
}

func TestRendererSettingsDeriveStableShadowsocks2022ServerKey(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	masterKey := bytes.Repeat([]byte("k"), 32)
	settings := domain.Settings{}
	first, err := rendererSettingsWithMasterKey(settings, "", domain.HysteriaSettings{}, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rendererSettingsWithMasterKey(settings, "", domain.HysteriaSettings{}, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(first.ShadowsocksServerKey)
	bootstrap, bootstrapErr := base64.StdEncoding.DecodeString(first.ShadowsocksBootstrapUserKey)
	if decodeErr != nil || len(decoded) != 32 || bootstrapErr != nil || len(bootstrap) != 32 || first.ShadowsocksServerKey == first.ShadowsocksBootstrapUserKey || first.ShadowsocksServerKey != second.ShadowsocksServerKey || first.ShadowsocksBootstrapUserKey != second.ShadowsocksBootstrapUserKey || !first.ShadowsocksEnabled || first.ShadowsocksMethod != domain.ShadowsocksMethod2022AES256GCM {
		t.Fatalf("derived Shadowsocks settings = %+v, decoded key length=%d decode error=%v", first, len(decoded), decodeErr)
	}
	if _, err := rendererSettingsWithMasterKey(settings, "", domain.HysteriaSettings{}, []byte("short")); err == nil {
		t.Fatal("short master key was accepted when deriving the Shadowsocks key")
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
