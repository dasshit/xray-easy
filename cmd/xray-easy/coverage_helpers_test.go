package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/secret"
)

func TestUpdateActiveLogLevelRewritesOnlyTheLogSection(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "active.json")
	for name, content := range map[string]string{
		"existing":       "{\"log\":{\"loglevel\":\"warning\",\"access\":\"none\"},\"inbounds\":[{\"tag\":\"vless-reality\"}]}",
		"missing":        "{\"inbounds\":[{\"tag\":\"vless-reality\"}]}",
		"wrong log type": "{\"log\":\"legacy\",\"inbounds\":[{\"tag\":\"vless-reality\"}]}",
		"invalid":        "not-json",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			err := updateActiveLogLevel(path, "debug")
			if name == "invalid" {
				if err == nil {
					t.Fatal("invalid JSON was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			if !strings.Contains(text, "\"loglevel\": \"debug\"") || !strings.Contains(text, "\"vless-reality\"") {
				t.Fatalf("active config was not updated or lost other settings: %s", text)
			}
			if name == "existing" && !strings.Contains(text, "\"access\": \"none\"") {
				t.Fatalf("existing log option was discarded: %s", text)
			}
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("active config permissions = %v, %v", info, err)
			}
		})
	}
	if err := updateActiveLogLevel(filepath.Join(root, "missing.json"), "debug"); err == nil {
		t.Fatal("missing active config was accepted")
	}
}

func TestTrojanPasswordDecryptionAndRendererFailures(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if got := mustDecryptTrojanPassword(key, domain.Client{}); got != "" {
		t.Fatalf("empty Trojan credential decrypted to %q", got)
	}
	encrypted, err := secret.Seal(key, "trojan-password", "trojan_password")
	if err != nil {
		t.Fatal(err)
	}
	client := domain.Client{ID: "trojan-device", TrojanPasswordEnc: encrypted}
	if got := mustDecryptTrojanPassword(key, client); got != "trojan-password" {
		t.Fatalf("decrypted Trojan credential = %q", got)
	}
	client.TrojanPasswordEnc = "invalid-envelope"
	if got := mustDecryptTrojanPassword(key, client); got != "" {
		t.Fatalf("malformed Trojan credential decrypted to %q", got)
	}
	if _, err := rendererClientsWithSecrets(key, []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "decrypt Trojan password") {
		t.Fatalf("renderer accepted malformed Trojan credential: %v", err)
	}
}

func TestShadowsocksPasswordDecryptionHandlesEmptyInvalidAndLegacyEncodings(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if got := mustDecryptShadowsocksPassword(key, domain.Client{}); got != "" {
		t.Fatalf("empty Shadowsocks credential decrypted to %q", got)
	}
	if got := mustDecryptShadowsocksPassword(key, domain.Client{ShadowsocksPasswordEnc: "not-an-envelope"}); got != "" {
		t.Fatalf("invalid Shadowsocks envelope decrypted to %q", got)
	}
	invalidKey, err := secret.Seal(key, "short", "shadowsocks_password")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustDecryptShadowsocksPassword(key, domain.Client{ShadowsocksPasswordEnc: invalidKey}); got != "" {
		t.Fatalf("wrong-length Shadowsocks key decrypted to %q", got)
	}
	legacyValue := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	legacyEnvelope, err := secret.Seal(key, legacyValue, "shadowsocks_password")
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if got := mustDecryptShadowsocksPassword(key, domain.Client{ShadowsocksPasswordEnc: legacyEnvelope}); got != want {
		t.Fatalf("legacy Shadowsocks password normalized to %q, want %q", got, want)
	}
	if _, err := rendererClientsWithSecrets(key, []domain.Client{{ID: "bad-ss", ShadowsocksPasswordEnc: invalidKey}}); err == nil || !strings.Contains(err.Error(), "normalize Shadowsocks password") {
		t.Fatalf("renderer accepted a malformed decrypted SS2022 key: %v", err)
	}
}

func TestPrepareCandidateHelpersReportStorageAndSecretFailures(t *testing.T) {
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.server.prepareCandidateWithHysteriaLocked(context.Background(), settings, privateKey, []domain.Client{{ID: "broken-ss", ShadowsocksPasswordEnc: "invalid"}}, nil, domain.HysteriaSettings{}); err == nil || !strings.Contains(err.Error(), "decrypt Shadowsocks password") {
		t.Fatalf("candidate with invalid encrypted protocol secret error = %v", err)
	}
	if err := app.server.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.server.prepareCandidateLocked(context.Background(), settings, privateKey, nil); err == nil {
		t.Fatal("candidate preparation succeeded with a closed store")
	}
	if _, _, err := app.server.prepareCandidateWithReservedLocked(context.Background(), settings, privateKey, nil, nil); err == nil {
		t.Fatal("candidate preparation with a reserved pool succeeded with a closed store")
	}
}

func TestPrepareCandidateWithReservedShortIDsBuildsCandidate(t *testing.T) {
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}
	path, operationID, err := app.server.prepareCandidateWithReservedLocked(context.Background(), settings, privateKey, nil, nil)
	if err != nil {
		t.Fatalf("prepareCandidateWithReservedLocked() failed: %v", err)
	}
	if operationID == "" {
		t.Fatal("candidate preparation returned an empty operation ID")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("candidate file %q was not created: %v", path, err)
	}
}
