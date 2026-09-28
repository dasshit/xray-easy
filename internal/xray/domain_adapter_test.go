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
