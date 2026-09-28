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
