package xray

import (
	"testing"

	"xray-easy/internal/domain"
)

func TestDomainAdaptersPreserveXrayCredentials(t *testing.T) {
	settings := SettingsFromDomain(domain.Settings{PublicHost: "vpn.example.com", RealityTarget: "example.com:443", RealitySNI: "example.com"}, "private")
	if settings.RealityPrivateKey != "private" || settings.PublicHost != "vpn.example.com" {
		t.Fatalf("unexpected settings mapping: %+v", settings)
	}
	client := ClientFromDomain(domain.Client{ID: "id", UUID: "uuid", Email: "email", ShortID: "short", Enabled: true})
	if client.ID != "id" || client.UUID != "uuid" || client.ShortID != "short" || !client.Enabled {
		t.Fatalf("unexpected client mapping: %+v", client)
	}
}

func TestClientsFromDomainPreservesOrderAndEmptyInput(t *testing.T) {
	if got := ClientsFromDomain(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil input conversion = %#v, want allocated empty slice", got)
	}
	values := []domain.Client{
		{ID: "one", Name: "phone", UUID: "uuid-one", Email: "one@example.test", ShortID: "sid-one", ClientFingerprint: "safari", Enabled: true},
		{ID: "two", Name: "tablet", UUID: "uuid-two", Email: "two@example.test", ShortID: "sid-two", ClientFingerprint: "ios", Revoked: true},
	}
	got := ClientsFromDomain(values)
	if len(got) != 2 || got[0].ID != values[0].ID || got[1].ID != values[1].ID || got[1].Revoked != values[1].Revoked || got[1].Enabled != values[1].Enabled {
		t.Fatalf("domain client conversion lost order/state: %+v", got)
	}
}

func TestApplyHysteriaSettingsUsesValidatedVersionAndSafeLegacyPaths(t *testing.T) {
	value := domain.HysteriaSettings{
		Enabled: true, TLSMode: domain.HysteriaTLSCustom, TLSCertIP: "203.0.113.10",
		TLSServerName: "vpn.example.test", Host: "vpn.example.test", CertificateID: "0123456789abcdef0123456789abcdef",
		UDPIdleTimeout: 90, MasqueradeType: domain.HysteriaMasqueradeText, MasqueradeString: "https://example.test",
	}
	settings := Settings{}
	ApplyHysteriaSettings(&settings, value)
	if !settings.Hysteria2Enabled || settings.HysteriaTLSMode != value.TLSMode || settings.HysteriaTLSCertIP != value.TLSCertIP ||
		settings.HysteriaTLSServerName != value.TLSServerName || settings.HysteriaHost != value.Host || settings.HysteriaUDPIdleTimeout != value.UDPIdleTimeout ||
		settings.HysteriaMasqueradeType != value.MasqueradeType || settings.HysteriaMasqueradeString != value.MasqueradeString {
		t.Fatalf("Hysteria settings fields were not copied: %+v", settings)
	}
	if settings.HysteriaTLSCertPath != "/etc/xray/hysteria-tls/0123456789abcdef0123456789abcdef/fullchain.pem" ||
		settings.HysteriaTLSKeyPath != "/etc/xray/hysteria-tls/0123456789abcdef0123456789abcdef/privkey.pem" {
		t.Fatalf("versioned TLS paths = %q, %q", settings.HysteriaTLSCertPath, settings.HysteriaTLSKeyPath)
	}
	for _, invalid := range []string{"", "../0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789ABCDEF", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "short"} {
		value.CertificateID = invalid
		ApplyHysteriaSettings(&settings, value)
		if settings.HysteriaTLSCertPath != HysteriaTLSCertPath || settings.HysteriaTLSKeyPath != HysteriaTLSKeyPath {
			t.Errorf("invalid certificate ID %q selected versioned paths: %+v", invalid, settings)
		}
	}
}

func TestApplyShadowsocksSettingsCopiesNodeConfiguration(t *testing.T) {
	settings := Settings{}
	value := domain.ShadowsocksSettings{Enabled: true, PublicPort: 8388, Method: domain.ShadowsocksMethodAES128GCM, Network: domain.ShadowsocksNetworkTCPUDP}
	ApplyShadowsocksSettings(&settings, value)
	if !settings.ShadowsocksEnabled || settings.ShadowsocksPublicPort != value.PublicPort || settings.ShadowsocksMethod != value.Method || settings.ShadowsocksNetwork != value.Network {
		t.Fatalf("Shadowsocks settings were not copied: %+v", settings)
	}
}
