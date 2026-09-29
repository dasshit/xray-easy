package xray

import (
	"encoding/json"
	"testing"

	"xray-easy/internal/domain"
)

func TestRenderServerConfigSeparatesProtocolUsersAndShortIDs(t *testing.T) {
	settings := validTestSettings()
	settings.Hysteria2Enabled = true
	settings.ReservedShortIDs = []string{"reserved-id"}
	clients := []Client{
		{
			ID: "vless", Protocol: domain.ProtocolVLESS, UUID: "vless-uuid", Email: "vless@xray-easy",
			ShortID: "vless-short", Enabled: true, VLESSEnabled: true,
		},
		{
			ID: "hysteria", Protocol: domain.ProtocolHysteria2, Email: "hysteria@xray-easy",
			HysteriaAuth: "hysteria-secret", Enabled: true, HysteriaEnabled: true,
		},
		{
			ID: "legacy", Protocol: domain.ProtocolLegacyDual, UUID: "legacy-uuid", Email: "legacy@xray-easy",
			ShortID: "legacy-short", HysteriaAuth: "legacy-auth", Enabled: true,
			VLESSEnabled: true, HysteriaEnabled: true,
		},
		{
			ID: "legacy-hysteria-only", Protocol: domain.ProtocolLegacyDual, UUID: "old-uuid", Email: "legacy-active@xray-easy",
			ShortID: "old-short", HysteriaAuth: "old-auth", Enabled: true,
			VLESSEnabled: false, VLESSRevoked: true, HysteriaEnabled: true,
		},
	}
	data, err := RenderServerConfig(settings, clients)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
			Settings struct {
				Clients []struct {
					ID string `json:"id"`
				} `json:"clients"`
				Users []struct {
					Email string `json:"email"`
					Auth  string `json:"auth"`
				} `json:"users"`
			} `json:"settings"`
			StreamSettings struct {
				Reality struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var vless, hysteria *struct {
		Tag string `json:"tag"`
		Settings struct {
			Clients []struct {
				ID string `json:"id"`
			} `json:"clients"`
			Users []struct {
				Email string `json:"email"`
				Auth  string `json:"auth"`
			} `json:"users"`
		} `json:"settings"`
		StreamSettings struct {
			Reality struct {
				ShortIDs []string `json:"shortIds"`
			} `json:"realitySettings"`
		} `json:"streamSettings"`
	}
	for index := range config.Inbounds {
		inbound := &config.Inbounds[index]
		if inbound.Tag == "vless-reality" {
			vless = inbound
		}
		if inbound.Tag == HysteriaInboundTag {
			hysteria = inbound
		}
	}
	if vless == nil || hysteria == nil {
		t.Fatalf("missing protocol inbounds: %+v", config.Inbounds)
	}
	if got := []string{vless.Settings.Clients[0].ID, vless.Settings.Clients[1].ID}; got[0] != "legacy-uuid" || got[1] != "vless-uuid" {
		t.Fatalf("VLESS inbound users = %v", got)
	}
	if len(hysteria.Settings.Users) != 3 {
		t.Fatalf("Hysteria 2 inbound users = %+v", hysteria.Settings.Users)
	}
	for _, expected := range []struct{ email, auth string }{
		{"hysteria@xray-easy", "hysteria-secret"},
		{"legacy@xray-easy", "legacy-auth"},
		{"legacy-active@xray-easy", "old-auth"},
	} {
		found := false
		for _, user := range hysteria.Settings.Users {
			if user.Email == expected.email && user.Auth == expected.auth {
				found = true
			}
		}
		if !found {
			t.Errorf("Hysteria 2 inbound missing user %s with its own auth", expected.email)
		}
	}
	shortIDs := vless.StreamSettings.Reality.ShortIDs
	for _, want := range []string{"vless-short", "legacy-short", "reserved-id"} {
		found := false
		for _, id := range shortIDs {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Errorf("REALITY short ID %q missing from %v", want, shortIDs)
		}
	}
	for _, id := range shortIDs {
		if id == "old-short" {
			t.Fatalf("revoked VLESS short ID remained in inbound: %v", shortIDs)
		}
	}
}
