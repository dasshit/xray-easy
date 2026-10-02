package xray

import (
	"encoding/json"
	"net/url"
	"strings"
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
			Tag      string `json:"tag"`
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
		Tag      string `json:"tag"`
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

func TestRenderAndBuildShadowsocksProfile(t *testing.T) {
	settings := validTestSettings()
	settings.ShadowsocksEnabled = true
	settings.ShadowsocksPublicPort = 8388
	settings.ShadowsocksMethod = domain.ShadowsocksMethodChaCha20Poly1305
	settings.ShadowsocksNetwork = domain.ShadowsocksNetworkTCPUDP
	client := Client{ID: "ss", Name: "MacBook Pro", Protocol: domain.ProtocolShadowsocks, Email: "ss@xray-easy", ShadowsocksPassword: "secret-password", ShadowsocksEnabled: true}
	config, err := RenderServerConfig(settings, []Client{client})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Network string                                     `json:"network"`
				Clients []struct{ Method, Password, Email string } `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	var inbound *struct {
		Tag      string `json:"tag"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Settings struct {
			Network string                                     `json:"network"`
			Clients []struct{ Method, Password, Email string } `json:"clients"`
		} `json:"settings"`
	}
	for i := range decoded.Inbounds {
		if decoded.Inbounds[i].Tag == ShadowsocksInboundTag {
			inbound = &decoded.Inbounds[i]
		}
	}
	if inbound == nil || inbound.Port != ShadowsocksInternalPort || inbound.Protocol != "shadowsocks" || inbound.Settings.Network != domain.ShadowsocksNetworkTCPUDP || len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].Password != client.ShadowsocksPassword {
		t.Fatalf("unexpected Shadowsocks inbound: %+v", decoded.Inbounds)
	}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.ShadowsocksURI)
	if err != nil || parsed.Scheme != "ss" || parsed.Host != "vpn.example.com:8388" || parsed.Fragment != client.Name {
		t.Fatalf("unexpected Shadowsocks URI: %s (%v)", profile.ShadowsocksURI, err)
	}
	if !strings.Contains(profile.ShadowsocksURI, "Y2hhY2hhMjAtcG9seTEzMDU6c2VjcmV0LX") {
		t.Fatalf("URI does not contain encoded method/password: %s", profile.ShadowsocksURI)
	}
	if len(profile.ShadowsocksJSON) == 0 || !strings.Contains(string(profile.ShadowsocksJSON), client.ShadowsocksPassword) {
		t.Fatal("Shadowsocks JSON profile missing password")
	}
}

func TestRenderAndBuildTrojanProfile(t *testing.T) {
	settings := validTestSettings()
	settings.TrojanEnabled = true
	settings.TrojanPublicPort = 10443
	settings.HysteriaTLSMode = HysteriaTLSCustom
	settings.HysteriaTLSServerName = "vpn.example.com"
	settings.HysteriaTLSCertPath = "/certs/fullchain.pem"
	settings.HysteriaTLSKeyPath = "/certs/privkey.pem"
	client := Client{ID: "trojan", Name: "iPhone", Protocol: domain.ProtocolTrojan, Email: "trojan@xray-easy", TrojanPassword: "secret-password", Enabled: true, TrojanEnabled: true}
	config, err := RenderServerConfig(settings, []Client{client})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []struct{ Password, Email string } `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, inbound := range decoded.Inbounds {
		if inbound.Tag == TrojanInboundTag {
			found = true
			if inbound.Port != TrojanInternalPort || inbound.Protocol != "trojan" || len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].Password != client.TrojanPassword {
				t.Fatalf("unexpected Trojan inbound: %+v", inbound)
			}
		}
	}
	if !found {
		t.Fatalf("Trojan inbound missing: %+v", decoded.Inbounds)
	}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.TrojanURI)
	if err != nil || parsed.Scheme != "trojan" || parsed.Host != "vpn.example.com:10443" || parsed.User.Username() != client.TrojanPassword || parsed.Query().Get("security") != "tls" || parsed.Query().Has("allowInsecure") {
		t.Fatalf("unexpected Trojan URI: %s (%v)", profile.TrojanURI, err)
	}
	if len(profile.TrojanJSON) == 0 || !strings.Contains(string(profile.TrojanJSON), client.TrojanPassword) {
		t.Fatal("Trojan JSON profile missing password")
	}
}

func TestTrojanSelfSignedProfilesPinTLSCertificate(t *testing.T) {
	settings := validTestSettings()
	settings.TrojanEnabled = true
	settings.TrojanPublicPort = 10443
	settings.HysteriaTLSMode = HysteriaTLSSelfSigned
	settings.HysteriaTLSFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	client := Client{ID: "trojan", Name: "phone", Protocol: domain.ProtocolTrojan, TrojanEnabled: true, TrojanPassword: "secret"}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.TrojanURI)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("pcs"); got != strings.ToUpper(settings.HysteriaTLSFingerprint) {
		t.Fatalf("Trojan URI certificate pin = %q", got)
	}
	if parsed.Query().Has("allowInsecure") {
		t.Fatal("Trojan URI still disables certificate validation")
	}
	var config struct {
		Outbounds []struct {
			StreamSettings struct {
				TLSSettings struct {
					PinnedPeerCertSHA256 string `json:"pinnedPeerCertSha256"`
					AllowInsecure        *bool  `json:"allowInsecure"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(profile.TrojanJSON, &config); err != nil {
		t.Fatal(err)
	}
	tls := config.Outbounds[0].StreamSettings.TLSSettings
	if tls.PinnedPeerCertSHA256 != strings.ToUpper(settings.HysteriaTLSFingerprint) || tls.AllowInsecure != nil {
		t.Fatalf("Trojan JSON TLS settings = %+v", tls)
	}
}

func TestTrojanSelfSignedProfileRequiresValidFingerprint(t *testing.T) {
	settings := validTestSettings()
	settings.TrojanEnabled = true
	settings.TrojanPublicPort = 10443
	settings.HysteriaTLSMode = HysteriaTLSSelfSigned
	client := Client{ID: "trojan", Name: "phone", Protocol: domain.ProtocolTrojan, TrojanEnabled: true, TrojanPassword: "secret"}
	if _, err := BuildProfile(settings, client); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("self-signed Trojan profile error = %v", err)
	}
}

func TestRenderVMessInboundUsesTLSAndRetainsDisabledProfiles(t *testing.T) {
	settings := validTestSettings()
	settings.VMessPublicPort = 9443
	settings.HysteriaTLSMode = HysteriaTLSCustom
	settings.HysteriaTLSServerName = "vpn.example.com"
	settings.HysteriaTLSCertPath = "/certs/fullchain.pem"
	settings.HysteriaTLSKeyPath = "/certs/privkey.pem"
	clients := []Client{
		{ID: "active", Name: "Mac", Protocol: domain.ProtocolVMess, UUID: "active-uuid", Email: "active@xray-easy", Enabled: true, VMessEnabled: true},
		{ID: "disabled", Name: "iPad", Protocol: domain.ProtocolVMess, UUID: "disabled-uuid", Email: "disabled@xray-easy", Enabled: false, VMessEnabled: false},
	}
	data, err := RenderServerConfig(settings, clients)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
			Settings struct {
				Clients []struct {
					ID      string `json:"id"`
					AlterID int    `json:"alterId"`
					Email   string `json:"email"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Network     string `json:"network"`
				Security    string `json:"security"`
				TLSSettings struct {
					Certificates []struct {
						CertificateFile string `json:"certificateFile"`
						KeyFile         string `json:"keyFile"`
					} `json:"certificates"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 2 {
		t.Fatalf("VMess config contains %d inbounds, want 2", len(config.Inbounds))
	}
	inbound := config.Inbounds[1]
	if inbound.Tag != VMessInboundTag || inbound.Protocol != "vmess" || inbound.Port != VMessInternalPort || inbound.StreamSettings.Network != "tcp" || inbound.StreamSettings.Security != "tls" {
		t.Fatalf("unexpected VMess inbound: %+v", inbound)
	}
	if len(inbound.Settings.Clients) != 1 || inbound.Settings.Clients[0].ID != "active-uuid" || inbound.Settings.Clients[0].AlterID != 0 || inbound.Settings.Clients[0].Email != "active@xray-easy" {
		t.Fatalf("VMess inbound users = %+v", inbound.Settings.Clients)
	}
	certificates := inbound.StreamSettings.TLSSettings.Certificates
	if len(certificates) != 1 || certificates[0].CertificateFile != "/certs/fullchain.pem" || certificates[0].KeyFile != "/certs/privkey.pem" {
		t.Fatalf("VMess certificate files = %+v", certificates)
	}
}

func TestRenderServerConfigRejectsInvalidOptionalProtocolClients(t *testing.T) {
	base := validTestSettings()
	cases := []struct {
		name   string
		change func(*Settings, *[]Client)
		want   string
	}{
		{"Hysteria credentials", func(settings *Settings, clients *[]Client) {
			settings.Hysteria2Enabled = true
			*clients = []Client{{ID: "h", Protocol: domain.ProtocolHysteria2, Email: "h@example.test", HysteriaEnabled: true}}
		}, "missing Hysteria 2 credentials"},
		{"VMess public port", func(settings *Settings, clients *[]Client) {
			settings.VMessPublicPort = 0
			*clients = []Client{{ID: "v", Protocol: domain.ProtocolVMess, UUID: "uuid", Email: "v@example.test", VMessEnabled: true}}
		}, "VMess public port"},
		{"VMess credentials", func(settings *Settings, clients *[]Client) {
			settings.VMessPublicPort = 9443
			*clients = []Client{{ID: "v", Protocol: domain.ProtocolVMess, Email: "v@example.test", VMessEnabled: true}}
		}, "missing VMess credentials"},
		{"Shadowsocks method", func(settings *Settings, clients *[]Client) {
			settings.ShadowsocksEnabled, settings.ShadowsocksPublicPort, settings.ShadowsocksMethod, settings.ShadowsocksNetwork = true, 8388, "unsupported", domain.ShadowsocksNetworkTCPUDP
		}, "unsupported Shadowsocks method"},
		{"Shadowsocks network", func(settings *Settings, clients *[]Client) {
			settings.ShadowsocksEnabled, settings.ShadowsocksPublicPort, settings.ShadowsocksMethod, settings.ShadowsocksNetwork = true, 8388, domain.ShadowsocksMethodChaCha20Poly1305, "sctp"
		}, "unsupported Shadowsocks network"},
		{"Shadowsocks credentials", func(settings *Settings, clients *[]Client) {
			settings.ShadowsocksEnabled, settings.ShadowsocksPublicPort, settings.ShadowsocksMethod, settings.ShadowsocksNetwork = true, 8388, domain.ShadowsocksMethodChaCha20Poly1305, domain.ShadowsocksNetworkTCPUDP
			*clients = []Client{{ID: "s", Protocol: domain.ProtocolShadowsocks, Email: "s@example.test", ShadowsocksEnabled: true}}
		}, "missing Shadowsocks credentials"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			settings := base
			clients := []Client{}
			test.change(&settings, &clients)
			if _, err := RenderServerConfig(settings, clients); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("RenderServerConfig() error = %v, want %q", err, test.want)
			}
		})
	}
}
