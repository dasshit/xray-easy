package main

import (
	"testing"

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
}
