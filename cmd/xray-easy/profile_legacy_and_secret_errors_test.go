package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestLegacyProfileDeliveryKeepsCombinedFormat(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "legacy-phone")
	response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy profile response = %d %s", response.Code, response.Body.String())
	}
	for _, field := range []string{`"protocol":"legacy_dual"`, `"uri":"vless://`, `"json":`, `"hysteria_uri":"hysteria2://`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Errorf("legacy profile omitted %s: %s", field, response.Body.String())
		}
	}
}

func TestProfileRejectsUndecryptableProtocolSecrets(t *testing.T) {
	t.Run("REALITY private key", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "bad-reality-key")
		settings, err := app.server.store.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityPrivateKeyEnc = "invalid-envelope"
		if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not decrypt REALITY private key") {
			t.Fatalf("profile with invalid REALITY key = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("Trojan password", func(t *testing.T) {
		t.Setenv("XRAY_TROJAN_ENABLED", "true")
		app := newTestApp(t, true)
		client, err := domain.NewProtocolClient("broken-trojan", "phone", domain.ProtocolTrojan, "", "")
		if err != nil {
			t.Fatal(err)
		}
		client.Email = "broken-trojan@xray-easy"
		client.TrojanPasswordEnc = "invalid-envelope"
		if err := app.server.store.CreateClient(context.Background(), client, "", client.Email, ""); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not decrypt Trojan password") {
			t.Fatalf("profile with invalid Trojan password = %d %s", response.Code, response.Body.String())
		}
	})
}
