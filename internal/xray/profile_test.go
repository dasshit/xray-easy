package xray

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func validTestSettings() Settings {
	return Settings{
		PublicHost: "vpn.example.com", PublicPort: 443,
		XrayAPIListen: "127.0.0.1:10085", InternalInboundPort: 8443,
		RealityTarget: "target.example.com:443", RealitySNI: "target.example.com",
		RealityPrivateKey: "private-key", RealityPublicKey: "public-key",
		ClientFingerprint: "chrome",
		LogLevel:          "warning",
	}
}

func TestBuildProfileKeepsURIAndJSONCredentialsInSync(t *testing.T) {
	settings := validTestSettings()
	client := Client{ID: "device", Name: "iOS phone / 1", UUID: "123e4567-e89b-42d3-a456-426614174000", ShortID: "0123456789abcdef"}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.URI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "vless" || parsed.User.Username() != client.UUID || parsed.Host != "vpn.example.com:443" || parsed.Fragment != client.Name {
		t.Fatalf("unexpected VLESS URI: %+v", parsed)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"encryption": "none", "flow": Flow, "fp": "chrome", "pbk": settings.RealityPublicKey,
		"security": Security, "sid": client.ShortID, "sni": settings.RealitySNI, "type": Network,
	} {
		if got := query.Get(key); got != want {
			t.Errorf("VLESS query %s=%q, want %q", key, got, want)
		}
	}
	var config struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				VNext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID         string `json:"id"`
						Encryption string `json:"encryption"`
						Flow       string `json:"flow"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				RealitySettings map[string]any `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(profile.JSON, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || config.Inbounds[0].Protocol != "socks" || config.Inbounds[0].Listen != "127.0.0.1" || config.Inbounds[0].Port != 10808 {
		t.Fatalf("unexpected client inbound: %+v", config.Inbounds)
	}
	if len(config.Outbounds) != 1 || config.Outbounds[0].Protocol != Protocol || len(config.Outbounds[0].Settings.VNext) != 1 {
		t.Fatalf("unexpected client outbound: %+v", config.Outbounds)
	}
	server := config.Outbounds[0].Settings.VNext[0]
	if server.Address != settings.PublicHost || server.Port != settings.PublicPort || len(server.Users) != 1 || server.Users[0].ID != client.UUID || server.Users[0].Flow != Flow || server.Users[0].Encryption != "none" {
		t.Fatalf("client endpoint and credentials do not match URI: %+v", server)
	}
	reality := config.Outbounds[0].StreamSettings.RealitySettings
	for key, want := range map[string]any{
		"serverName": settings.RealitySNI, "fingerprint": settings.ClientFingerprint,
		"password": settings.RealityPublicKey, "publicKey": settings.RealityPublicKey,
		"shortId": client.ShortID, "spiderX": "/",
	} {
		if got := reality[key]; got != want {
			t.Errorf("client REALITY field %s = %v, want %v", key, got, want)
		}
	}
	if profile.Name != client.Name || profile.UUID != client.UUID || profile.ShortID != client.ShortID {
		t.Fatalf("profile metadata = %+v", profile)
	}
}

func TestHysteria2InboundAndProfileUseDedicatedTLSUDPSettings(t *testing.T) {
	settings := validTestSettings()
	settings.Hysteria2Enabled = true
	client := Client{ID: "device", Name: "iPhone 15", UUID: "123e4567-e89b-42d3-a456-426614174000", Email: "device@example.test", ShortID: "0123456789abcdef", Enabled: true}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.HysteriaURI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "hysteria2" || parsed.User.Username() != client.UUID || parsed.Host != "vpn.example.com:443" || parsed.Query().Get("sni") != settings.PublicHost || parsed.Query().Has("insecure") {
		t.Fatalf("unexpected Hysteria 2 URI: %s", profile.HysteriaURI)
	}
	if parsed.Fragment != client.Name {
		t.Fatalf("Hysteria 2 URI name = %q, want %q", parsed.Fragment, client.Name)
	}

	config, err := RenderServerConfig(settings, []Client{client})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Port     int    `json:"port"`
			Settings struct {
				Version int `json:"version"`
				Users   []struct {
					Auth  string `json:"auth"`
					Email string `json:"email"`
				} `json:"users"`
			} `json:"settings"`
			StreamSettings struct {
				Network          string `json:"network"`
				Security         string `json:"security"`
				HysteriaSettings struct {
					Version int `json:"version"`
				} `json:"hysteriaSettings"`
				TLSSettings struct {
					Certificates []struct {
						CertificateFile string `json:"certificateFile"`
						KeyFile         string `json:"keyFile"`
					} `json:"certificates"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Inbounds) != 2 {
		t.Fatalf("Hysteria 2 enabled config has %d inbounds, want 2", len(decoded.Inbounds))
	}
	inbound := decoded.Inbounds[1]
	if inbound.Tag != HysteriaInboundTag || inbound.Protocol != "hysteria" || inbound.Port != settings.InternalInboundPort || inbound.Settings.Version != 2 || len(inbound.Settings.Users) != 1 || inbound.Settings.Users[0].Auth != client.UUID || inbound.Settings.Users[0].Email != client.Email {
		t.Fatalf("unexpected Hysteria inbound: %+v", inbound)
	}
	if inbound.StreamSettings.Network != "hysteria" || inbound.StreamSettings.Security != "tls" || inbound.StreamSettings.HysteriaSettings.Version != 2 {
		t.Fatalf("unexpected Hysteria transport: %+v", inbound.StreamSettings)
	}
	certificates := inbound.StreamSettings.TLSSettings.Certificates
	if len(certificates) != 1 || certificates[0].CertificateFile != HysteriaTLSCertPath || certificates[0].KeyFile != HysteriaTLSKeyPath {
		t.Fatalf("unexpected Hysteria TLS files: %+v", certificates)
	}
}

func TestProtocolSpecificProfilesDeliverOnlyTheirOwnCredentials(t *testing.T) {
	settings := validTestSettings()
	settings.Hysteria2Enabled = true
	settings.HysteriaTLSMode = HysteriaTLSCustom
	settings.HysteriaTLSServerName = "vpn.example.com"
	hysteriaClient := Client{
		ID: "hysteria-device", Name: "iPhone", Protocol: domain.ProtocolHysteria2,
		Email: "hysteria-device@xray-easy", HysteriaAuth: "auth with spaces",
		Enabled: true, HysteriaEnabled: true,
	}
	hysteriaProfile, err := BuildProfile(settings, hysteriaClient)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(hysteriaProfile.HysteriaURI)
	if err != nil || parsed.Scheme != "hysteria2" || parsed.User.Username() != hysteriaClient.HysteriaAuth {
		t.Fatalf("Hysteria-only URI = %q, %v", hysteriaProfile.HysteriaURI, err)
	}
	if hysteriaProfile.URI != "" || hysteriaProfile.JSON != nil || hysteriaProfile.Protocol != domain.ProtocolHysteria2 {
		t.Fatalf("Hysteria-only profile leaked a VLESS delivery: %+v", hysteriaProfile)
	}

	vlessClient := Client{
		ID: "vless-device", Name: "Mac", Protocol: domain.ProtocolVLESS,
		UUID: "vless-uuid", Email: "vless-device@xray-easy", ShortID: "0123456789abcdef",
		ClientFingerprint: "safari", Enabled: true, VLESSEnabled: true,
	}
	vlessProfile, err := BuildProfile(settings, vlessClient)
	if err != nil {
		t.Fatal(err)
	}
	if vlessProfile.URI == "" || vlessProfile.HysteriaURI != "" || len(vlessProfile.JSON) == 0 {
		t.Fatalf("VLESS-only profile included another protocol: %+v", vlessProfile)
	}
}

func TestVMessTLSProfileProducesStandardShareLinkAndClientJSON(t *testing.T) {
	settings := validTestSettings()
	settings.VMessPublicPort = 9443
	settings.HysteriaTLSMode = HysteriaTLSCustom
	settings.HysteriaTLSServerName = "vpn.example.com"
	settings.HysteriaTLSCertPath = "/etc/xray/hysteria-tls/test/fullchain.pem"
	settings.HysteriaTLSKeyPath = "/etc/xray/hysteria-tls/test/privkey.pem"
	client := Client{
		ID: "vmess-device", Name: "MacBook", Protocol: domain.ProtocolVMess,
		UUID: "123e4567-e89b-42d3-a456-426614174000", Email: "vmess-device@xray-easy",
		Enabled: true, VMessEnabled: true,
	}

	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	if profile.URI != "" || profile.HysteriaURI != "" || profile.VMessURI == "" || len(profile.JSON) == 0 {
		t.Fatalf("unexpected VMess-only delivery: %+v", profile)
	}
	encoded := strings.TrimPrefix(profile.VMessURI, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var share struct {
		Version  string `json:"v"`
		Name     string `json:"ps"`
		Address  string `json:"add"`
		Port     string `json:"port"`
		UUID     string `json:"id"`
		AlterID  string `json:"aid"`
		Network  string `json:"net"`
		TLS      string `json:"tls"`
		SNI      string `json:"sni"`
		Insecure string `json:"insecure"`
		CertPin  string `json:"pcs"`
	}
	if err := json.Unmarshal(decoded, &share); err != nil {
		t.Fatal(err)
	}
	if share.Version != "2" || share.Name != client.Name || share.Address != settings.PublicHost || share.Port != "9443" || share.UUID != client.UUID || share.AlterID != "0" || share.Network != "tcp" || share.TLS != "tls" || share.SNI != "vpn.example.com" || share.Insecure != "0" || share.CertPin != "" {
		t.Fatalf("VMess share JSON = %+v", share)
	}
	var clientConfig struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				VNext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID      string `json:"id"`
						AlterID int    `json:"alterId"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				Security    string `json:"security"`
				TLSSettings struct {
					ServerName           string `json:"serverName"`
					PinnedPeerCertSHA256 string `json:"pinnedPeerCertSha256"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(profile.JSON, &clientConfig); err != nil {
		t.Fatal(err)
	}
	server := clientConfig.Outbounds[0]
	endpoint := server.Settings.VNext[0]
	user := endpoint.Users[0]
	if server.Protocol != "vmess" || endpoint.Address != settings.PublicHost || endpoint.Port != 9443 || user.ID != client.UUID || user.AlterID != 0 || server.StreamSettings.Security != "tls" || server.StreamSettings.TLSSettings.ServerName != "vpn.example.com" || server.StreamSettings.TLSSettings.PinnedPeerCertSHA256 != "" {
		t.Fatalf("VMess client config does not match profile: %+v", server)
	}

	settings.HysteriaTLSMode = HysteriaTLSSelfSigned
	settings.HysteriaTLSFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	profile, err = BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = base64.StdEncoding.DecodeString(strings.TrimPrefix(profile.VMessURI, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(decoded, &share); err != nil || share.Insecure != "0" || share.CertPin != strings.ToUpper(settings.HysteriaTLSFingerprint) {
		t.Fatalf("self-signed VMess link does not pin the certificate: %+v, %v", share, err)
	}
	if err := json.Unmarshal(profile.JSON, &clientConfig); err != nil {
		t.Fatal(err)
	}
	if got := clientConfig.Outbounds[0].StreamSettings.TLSSettings.PinnedPeerCertSHA256; got != strings.ToUpper(settings.HysteriaTLSFingerprint) {
		t.Fatalf("VMess client JSON pin = %q, want %q", got, strings.ToUpper(settings.HysteriaTLSFingerprint))
	}
}

func TestVMessSelfSignedProfileRequiresCertificateFingerprint(t *testing.T) {
	settings := validTestSettings()
	settings.VMessPublicPort = 9443
	settings.HysteriaTLSMode = HysteriaTLSSelfSigned
	client := Client{ID: "vmess-device", Name: "MacBook", Protocol: domain.ProtocolVMess, UUID: "123e4567-e89b-42d3-a456-426614174000"}
	if _, err := BuildProfile(settings, client); err == nil {
		t.Fatal("VMess profile accepted an untrusted TLS certificate without a pin")
	}
}

func TestHysteria2URIUsesCertificateMode(t *testing.T) {
	client := Client{ID: "device", Name: "phone", UUID: "123e4567-e89b-42d3-a456-426614174000", ShortID: "0123456789abcdef"}
	for _, test := range []struct {
		name, host, mode, certIP, serverName, wantSNI, wantInsecure string
	}{
		{"mkcert IPv4", "89.169.13.234", HysteriaTLSSelfSigned, "89.169.13.234", "", "89.169.13.234", "1"},
		{"legacy unverified", "89.169.13.234", HysteriaTLSLegacy, "", "", "89.169.13.234", "1"},
		{"custom DNS", "vpn.example.com", HysteriaTLSCustom, "", "", "vpn.example.com", ""},
		{"custom DNS SNI with IP endpoint", "89.169.13.234", HysteriaTLSCustom, "", "vpn.example.com", "vpn.example.com", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := validTestSettings()
			settings.PublicHost = test.host
			settings.Hysteria2Enabled = true
			settings.HysteriaTLSMode = test.mode
			settings.HysteriaTLSCertIP = test.certIP
			settings.HysteriaTLSServerName = test.serverName
			profile, err := BuildProfile(settings, client)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(profile.HysteriaURI)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Query().Get("sni") != test.wantSNI || parsed.Query().Get("insecure") != test.wantInsecure {
				t.Fatalf("unexpected URI query: %s", profile.HysteriaURI)
			}
		})
	}
}

func TestHysteria2SelfSignedRejectsMismatchedPublicHost(t *testing.T) {
	settings := validTestSettings()
	settings.Hysteria2Enabled = true
	settings.HysteriaTLSMode = HysteriaTLSSelfSigned
	settings.HysteriaTLSCertIP = "89.169.13.234"
	client := Client{ID: "device", Name: "phone", UUID: "123e4567-e89b-42d3-a456-426614174000", ShortID: "0123456789abcdef"}
	if _, err := BuildProfile(settings, client); err == nil {
		t.Fatal("expected a public host/certificate IP mismatch error")
	}
}

func TestBuildProfileFormatsIPv6EndpointForURIAndJSON(t *testing.T) {
	settings := validTestSettings()
	settings.PublicHost = "2001:0db8:0:0:0:0:0:1"
	client := Client{ID: "device", Name: "phone", UUID: "123e4567-e89b-42d3-a456-426614174000", ShortID: "0123456789abcdef"}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.URI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "[2001:db8::1]:443" || parsed.Hostname() != "2001:db8::1" || parsed.Port() != "443" {
		t.Fatalf("IPv6 VLESS authority = %q (hostname %q, port %q)", parsed.Host, parsed.Hostname(), parsed.Port())
	}
	var config struct {
		Outbounds []struct {
			Settings struct {
				VNext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
				} `json:"vnext"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(profile.JSON, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Outbounds) != 1 || len(config.Outbounds[0].Settings.VNext) != 1 {
		t.Fatalf("unexpected client JSON outbounds: %+v", config.Outbounds)
	}
	endpoint := config.Outbounds[0].Settings.VNext[0]
	if endpoint.Address != "2001:db8::1" || endpoint.Port != 443 {
		t.Fatalf("client JSON endpoint = %+v, want unbracketed IPv6 and port 443", endpoint)
	}
}

func TestBuildProfileUsesPerClientFingerprintOverride(t *testing.T) {
	settings := validTestSettings()
	client := Client{ID: "device", Name: "phone", UUID: "uuid", ShortID: "sid", ClientFingerprint: "safari"}
	profile, err := BuildProfile(settings, client)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(profile.URI)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("fp"); got != "safari" {
		t.Fatalf("URI fingerprint = %q, want client override", got)
	}
	var config struct {
		Outbounds []struct {
			StreamSettings struct {
				RealitySettings struct {
					Fingerprint string `json:"fingerprint"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(profile.JSON, &config); err != nil {
		t.Fatal(err)
	}
	if got := config.Outbounds[0].StreamSettings.RealitySettings.Fingerprint; got != "safari" {
		t.Fatalf("JSON fingerprint = %q, want client override", got)
	}
}

func TestBuildProfileRejectsUnavailableClientAndIncompleteSettings(t *testing.T) {
	settings := validTestSettings()
	client := Client{ID: "device", Name: "phone", UUID: "uuid", ShortID: "sid"}
	for _, test := range []struct {
		name     string
		client   Client
		settings Settings
	}{
		{"missing uuid", Client{ID: "device", Name: "phone", ShortID: "sid"}, settings},
		{"missing short ID", Client{ID: "device", Name: "phone", UUID: "uuid"}, settings},
		{"revoked", Client{ID: "device", Name: "phone", UUID: "uuid", ShortID: "sid", Revoked: true}, settings},
		{"missing default fingerprint", client, func() Settings { s := settings; s.ClientFingerprint = ""; return s }()},
		{"invalid host", client, func() Settings { s := settings; s.PublicHost = "https://vpn.example.com"; return s }()},
		{"invalid public port", client, func() Settings { s := settings; s.PublicPort = 65536; return s }()},
		{"missing Xray API", client, func() Settings { s := settings; s.XrayAPIListen = ""; return s }()},
		{"invalid internal port", client, func() Settings { s := settings; s.InternalInboundPort = 0; return s }()},
		{"invalid REALITY target", client, func() Settings { s := settings; s.RealityTarget = "127.0.0.1:443"; return s }()},
		{"missing private key", client, func() Settings { s := settings; s.RealityPrivateKey = ""; return s }()},
		{"missing public key", client, func() Settings { s := settings; s.RealityPublicKey = ""; return s }()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildProfile(test.settings, test.client); err == nil {
				t.Fatal("invalid profile input accepted")
			}
		})
	}
}

func TestRenderServerConfigPreservesDisabledAndReservedShortIDsWithoutActiveClients(t *testing.T) {
	settings := validTestSettings()
	settings.ReservedShortIDs = []string{"1111111111111111"}
	config, err := RenderServerConfig(settings, []Client{
		{ID: "disabled", UUID: "uuid-disabled", Email: "disabled@example.test", ShortID: "0123456789abcdef", Enabled: false},
		{ID: "revoked", UUID: "uuid-revoked", Email: "revoked@example.test", ShortID: "fedcba9876543210", Enabled: true, Revoked: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Inbounds []struct {
			Settings struct {
				Clients []any `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Reality struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Inbounds) != 1 || len(decoded.Inbounds[0].Settings.Clients) != 0 {
		t.Fatalf("disabled or revoked client was rendered: %+v", decoded.Inbounds)
	}
	if got := decoded.Inbounds[0].StreamSettings.Reality.ShortIDs; len(got) != 2 || got[0] != "0123456789abcdef" || got[1] != "1111111111111111" {
		t.Fatalf("REALITY short IDs for disabled profile and reserve = %v", got)
	}
}

func TestRenderServerConfigRejectsActiveClientMissingGeneratedFields(t *testing.T) {
	for _, client := range []Client{
		{ID: "missing-uuid", Email: "device@example.test", ShortID: "sid", Enabled: true},
		{ID: "missing-email", UUID: "uuid", ShortID: "sid", Enabled: true},
		{ID: "missing-short", UUID: "uuid", Email: "device@example.test", Enabled: true},
	} {
		if _, err := RenderServerConfig(validTestSettings(), []Client{client}); err == nil {
			t.Errorf("active client with missing fields accepted: %+v", client)
		}
	}
	// The same incomplete record is ignored when it is not connectable.
	if _, err := RenderServerConfig(validTestSettings(), []Client{{ID: "disabled", Enabled: false}}); err != nil {
		t.Fatalf("disabled incomplete client should be ignored: %v", err)
	}
}

func TestRenderServerConfigIsDeterministicAndIncludesControlServices(t *testing.T) {
	clients := []Client{
		{ID: "b", UUID: "uuid-b", Email: "b@example.test", ShortID: "bbbbbbbbbbbbbbbb", Enabled: true},
		{ID: "a", UUID: "uuid-a", Email: "a@example.test", ShortID: "aaaaaaaaaaaaaaaa", Enabled: true},
	}
	first, err := RenderServerConfig(validTestSettings(), clients)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderServerConfig(validTestSettings(), []Client{clients[1], clients[0]})
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("server config changed with input client ordering")
	}
	var decoded struct {
		API struct {
			Services []string `json:"services"`
		} `json:"api"`
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
			Settings struct {
				Decryption string `json:"decryption"`
				Clients    []struct {
					ID   string `json:"id"`
					Flow string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
			Stream struct {
				Network  string `json:"network"`
				Security string `json:"security"`
				Reality  struct {
					Target       string   `json:"target"`
					ServerNames  []string `json:"serverNames"`
					PrivateKey   string   `json:"privateKey"`
					MinClientVer string   `json:"minClientVer"`
					ShortIDs     []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
			Sniffing struct {
				Enabled      bool     `json:"enabled"`
				DestOverride []string `json:"destOverride"`
			} `json:"sniffing"`
		} `json:"inbounds"`
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.API.Services) != 3 || decoded.API.Services[0] != "HandlerService" || decoded.API.Services[1] != "StatsService" || decoded.API.Services[2] != "LoggerService" {
		t.Fatalf("Xray API services = %v", decoded.API.Services)
	}
	if len(decoded.Inbounds) != 1 {
		t.Fatalf("inbound count = %d", len(decoded.Inbounds))
	}
	inbound := decoded.Inbounds[0]
	if inbound.Protocol != Protocol || inbound.Tag != "vless-reality" || inbound.Settings.Decryption != "none" || len(inbound.Settings.Clients) != 2 || inbound.Settings.Clients[0].ID != "uuid-a" || inbound.Settings.Clients[0].Flow != Flow {
		t.Fatalf("VLESS inbound users/config = %+v", inbound)
	}
	if inbound.Stream.Network != Network || inbound.Stream.Security != Security || inbound.Stream.Reality.Target != "target.example.com:443" || len(inbound.Stream.Reality.ServerNames) != 1 || inbound.Stream.Reality.ServerNames[0] != "target.example.com" || inbound.Stream.Reality.PrivateKey != "private-key" || inbound.Stream.Reality.MinClientVer != "1.0.0" || len(inbound.Stream.Reality.ShortIDs) != 2 {
		t.Fatalf("REALITY stream config = %+v", inbound.Stream)
	}
	if !inbound.Sniffing.Enabled || len(inbound.Sniffing.DestOverride) != 3 || len(decoded.Outbounds) != 1 || decoded.Outbounds[0].Protocol != "freedom" || decoded.Outbounds[0].Tag != "direct" {
		t.Fatalf("sniffing/outbound config = %+v / %+v", inbound.Sniffing, decoded.Outbounds)
	}
}

func TestRenderServerConfigRejectsInvalidSettings(t *testing.T) {
	base := validTestSettings()
	for _, test := range []struct {
		name   string
		change func(*Settings)
	}{
		{"host", func(s *Settings) { s.PublicHost = "bad host" }},
		{"port low", func(s *Settings) { s.PublicPort = 0 }},
		{"port high", func(s *Settings) { s.PublicPort = 65536 }},
		{"api", func(s *Settings) { s.XrayAPIListen = "" }},
		{"inbound port low", func(s *Settings) { s.InternalInboundPort = 0 }},
		{"inbound port high", func(s *Settings) { s.InternalInboundPort = 65536 }},
		{"target", func(s *Settings) { s.RealityTarget = "example.com" }},
		{"private key", func(s *Settings) { s.RealityPrivateKey = "" }},
		{"public key", func(s *Settings) { s.RealityPublicKey = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := base
			test.change(&settings)
			if _, err := RenderServerConfig(settings, nil); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
}
