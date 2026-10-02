package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/hysteria"
	"xray-easy/internal/xray"
)

func TestVMessProfilePinsUntrustedCertificateInShareLinkAndJSON(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	ctx := context.Background()
	if err := app.server.store.InitializeHysteriaSettings(ctx, domain.HysteriaSettings{
		TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := domain.NewProtocolClient("vmess-pin-test", "iphone", domain.ProtocolVMess, "", "")
	if err != nil {
		t.Fatal(err)
	}
	client.UUID, err = xray.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	client.Email = "vmess-pin-test@xray-easy"
	if err := app.server.store.CreateVMessClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	certificate, err := hysteria.Inspect(app.server.hysteriaTLSDir(), "", "vpn.example.test", true)
	if err != nil {
		t.Fatal(err)
	}

	response := requestJSON(t, app, "GET", "/api/clients/"+client.ID+"/profile", nil, true)
	if response.Code != 200 {
		t.Fatalf("VMess profile response = %d %s", response.Code, response.Body.String())
	}
	var delivery struct {
		VMessURI string          `json:"vmess_uri"`
		JSON     json.RawMessage `json:"json"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(delivery.VMessURI, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var share struct {
		Insecure string `json:"insecure"`
		CertPin  string `json:"pcs"`
	}
	if err := json.Unmarshal(decoded, &share); err != nil {
		t.Fatal(err)
	}
	if share.Insecure != "0" || share.CertPin != certificate.Fingerprint {
		t.Fatalf("VMess share certificate policy = %+v, want a verified certificate pin %q", share, certificate.Fingerprint)
	}
	var clientConfig struct {
		Outbounds []struct {
			StreamSettings struct {
				TLSSettings struct {
					PinnedPeerCertSHA256 string `json:"pinnedPeerCertSha256"`
				} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(delivery.JSON, &clientConfig); err != nil {
		t.Fatal(err)
	}
	if len(clientConfig.Outbounds) != 1 || clientConfig.Outbounds[0].StreamSettings.TLSSettings.PinnedPeerCertSHA256 != certificate.Fingerprint {
		t.Fatalf("VMess client JSON did not pin the active certificate: %+v", clientConfig)
	}
}

func TestTrojanProfilePinsUntrustedCertificateInShareLinkAndJSON(t *testing.T) {
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "11443")
	app := newTestApp(t, true)
	app.server.trojanPort = 11443
	ctx := context.Background()
	if err := app.server.store.InitializeHysteriaSettings(ctx, domain.HysteriaSettings{
		TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}); err != nil {
		t.Fatal(err)
	}
	certificate, err := hysteria.Inspect(app.server.hysteriaTLSDir(), "", "vpn.example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	client := createRuntimeTrojanClient(t, app, "trojan-pin-test")
	response := requestJSON(t, app, "GET", "/api/clients/"+client.ID+"/profile", nil, true)
	if response.Code != 200 {
		t.Fatalf("Trojan profile response = %d %s", response.Code, response.Body.String())
	}
	var delivery struct {
		TrojanURI string          `json:"trojan_uri"`
		JSON      json.RawMessage `json:"json"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(delivery.TrojanURI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("pcs") != certificate.Fingerprint || parsed.Query().Has("allowInsecure") {
		t.Fatalf("Trojan share certificate policy = %v, want pinned certificate %q", parsed.Query(), certificate.Fingerprint)
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
	if err := json.Unmarshal(delivery.JSON, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Outbounds) != 1 || config.Outbounds[0].StreamSettings.TLSSettings.PinnedPeerCertSHA256 != certificate.Fingerprint || config.Outbounds[0].StreamSettings.TLSSettings.AllowInsecure != nil {
		t.Fatalf("Trojan JSON TLS policy = %+v", config.Outbounds)
	}
}
