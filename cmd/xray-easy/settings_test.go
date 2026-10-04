package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestClientsFingerprintDetectsRosterAndStateChanges(t *testing.T) {
	base := []domain.Client{{ID: "a", UUID: "uuid-a", Enabled: true}, {ID: "b", UUID: "uuid-b", Enabled: true}}
	baseFingerprint := clientsFingerprint(base)
	if clientsFingerprint([]domain.Client{base[1], base[0]}) != baseFingerprint {
		t.Fatal("fingerprint should not depend on database row order")
	}
	if got := clientsFingerprint(append(base, domain.Client{ID: "c", UUID: "uuid-c", Enabled: true})); got == baseFingerprint {
		t.Fatal("fingerprint did not change after a device was added")
	}
	changed := append([]domain.Client(nil), base...)
	changed[0].Revoked = true
	if got := clientsFingerprint(changed); got == baseFingerprint {
		t.Fatal("fingerprint did not change after device state changed")
	}
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	withExpiry := append([]domain.Client(nil), base...)
	withExpiry[0].ExpiresAt = &expires
	if got := clientsFingerprint(withExpiry); got == baseFingerprint {
		t.Fatal("fingerprint did not include profile expiry")
	}
}

func TestActiveConfigUsersMatchRejectsMissingOptionalInbounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	config := `{"inbounds":[{"tag":"vless-reality","settings":{"clients":[]}}]}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		env      string
		includeH bool
		clients  []domain.Client
	}{
		{name: "Hysteria 2", includeH: true},
		{name: "VMess", clients: []domain.Client{{Protocol: domain.ProtocolVMess, VMessEnabled: true}}},
		{name: "Shadowsocks", env: "XRAY_SHADOWSOCKS_ENABLED"},
		{name: "Trojan", env: "XRAY_TROJAN_ENABLED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.env != "" {
				t.Setenv(test.env, "true")
			}
			if activeConfigUsersMatch(path, test.clients, test.includeH) {
				t.Fatal("active config without the optional inbound matched")
			}
		})
	}
}
