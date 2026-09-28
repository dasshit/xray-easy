package xray

import (
	"encoding/json"
	"testing"
)

func TestRenderServerConfigKeepsRealityShortIDsInSyncWithActiveClients(t *testing.T) {
	config, err := RenderServerConfig(Settings{
		PublicHost: "198.51.100.10", PublicPort: 443,
		XrayAPIListen: "172.31.241.2:10085", InternalInboundPort: 8443,
		RealityTarget: "example.com:443", RealitySNI: "example.com",
		RealityPrivateKey: "private", RealityPublicKey: "public", ClientFingerprint: "chrome",
	}, []Client{
		{ID: "active", UUID: "uuid-active", Email: "active@example", ShortID: "0123456789abcdef", Enabled: true},
		{ID: "disabled", UUID: "uuid-disabled", Email: "disabled@example", ShortID: "fedcba9876543210", Enabled: false},
	})
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var decoded struct {
		Inbounds []struct {
			Settings struct {
				Clients []struct {
					ID string `json:"id"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				RealitySettings struct {
					MinClientVer string   `json:"minClientVer"`
					ShortIDs     []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if len(decoded.Inbounds) != 1 {
		t.Fatalf("got %d inbounds, want 1", len(decoded.Inbounds))
	}
	inbound := decoded.Inbounds[0]
	if len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != "uuid-active" {
		t.Fatalf("unexpected active clients: %+v", inbound.Settings.Clients)
	}
	if got := inbound.StreamSettings.RealitySettings.ShortIDs; len(got) != 1 || got[0] != "0123456789abcdef" {
		t.Fatalf("unexpected REALITY shortIds: %v", got)
	}
	if got := inbound.StreamSettings.RealitySettings.MinClientVer; got != "1.0.0" {
		t.Fatalf("REALITY minClientVer contract changed: %q", got)
	}
}
