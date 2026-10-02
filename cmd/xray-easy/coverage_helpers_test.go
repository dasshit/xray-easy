package main

import (
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
		"existing": "{\"log\":{\"loglevel\":\"warning\",\"access\":\"none\"},\"inbounds\":[{\"tag\":\"vless-reality\"}]}",
		"missing":  "{\"inbounds\":[{\"tag\":\"vless-reality\"}]}",
		"invalid":  "not-json",
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
