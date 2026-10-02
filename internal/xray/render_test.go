package xray

import (
	"encoding/json"
	"testing"

	"xray-easy/internal/domain"
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
	if got := inbound.StreamSettings.RealitySettings.ShortIDs; len(got) != 2 || got[0] != "0123456789abcdef" || got[1] != "fedcba9876543210" {
		t.Fatalf("unexpected REALITY shortIds: %v", got)
	}
	if got := inbound.StreamSettings.RealitySettings.MinClientVer; got != "1.0.0" {
		t.Fatalf("REALITY minClientVer contract changed: %q", got)
	}
}

func TestRenderServerConfigUsesConfiguredLogLevel(t *testing.T) {
	settings := validTestSettings()
	settings.LogLevel = "debug"
	config, err := RenderServerConfig(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Log struct {
			Level string `json:"loglevel"`
		} `json:"log"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Log.Level != "debug" {
		t.Fatalf("rendered log level = %q, want debug", decoded.Log.Level)
	}
	settings.LogLevel = "trace"
	if _, err := RenderServerConfig(settings, nil); err == nil {
		t.Fatal("unsupported Xray log level was accepted")
	}
}

func TestClientAccessHelpersPreserveLegacyZeroProtocolBehavior(t *testing.T) {
	client := Client{Enabled: true, Revoked: false}
	if !client.VLESSCanConnect() || !client.Hysteria2CanConnect() || !client.VMessCanConnect() {
		t.Fatal("zero-value protocol should retain legacy VLESS, Hysteria 2, and VMess access")
	}
	if client.ShadowsocksCanConnect() || client.TrojanCanConnect() {
		t.Fatal("zero-value protocol must not grant Shadowsocks or Trojan access")
	}
	if !client.VMESSEnabled() || client.VLESSIsRevoked() || client.HysteriaIsRevoked() || client.VMessIsRevoked() || client.ShadowsocksIsRevoked() || client.TrojanIsRevoked() {
		t.Fatal("legacy enabled/unrevoked flags were not interpreted consistently")
	}

	client.Revoked = true
	if client.VLESSCanConnect() || client.Hysteria2CanConnect() || client.VMessCanConnect() || !client.VLESSIsRevoked() || !client.HysteriaIsRevoked() || !client.VMessIsRevoked() {
		t.Fatal("legacy revoked state was not applied to the supported legacy protocols")
	}
	if client.ShadowsocksIsRevoked() || client.TrojanIsRevoked() {
		t.Fatal("legacy revoked state must not fabricate protocol-specific revocation")
	}

	vmess := Client{Protocol: domain.ProtocolVMess, VMessEnabled: true, VMessRevoked: true}
	if !vmess.VMESSEnabled() || !vmess.VMessIsRevoked() || vmess.VMessCanConnect() {
		t.Fatal("explicit VMess lifecycle state was not preserved")
	}
}
