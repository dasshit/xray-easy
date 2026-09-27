package main

import (
	"testing"

	"xray-easy/internal/store"
)

func TestClientsFingerprintDetectsRosterAndStateChanges(t *testing.T) {
	base := []store.Client{{ID: "a", UUID: "uuid-a", Enabled: true}, {ID: "b", UUID: "uuid-b", Enabled: true}}
	baseFingerprint := clientsFingerprint(base)
	if clientsFingerprint([]store.Client{base[1], base[0]}) != baseFingerprint {
		t.Fatal("fingerprint should not depend on database row order")
	}
	if got := clientsFingerprint(append(base, store.Client{ID: "c", UUID: "uuid-c", Enabled: true})); got == baseFingerprint {
		t.Fatal("fingerprint did not change after a device was added")
	}
	changed := append([]store.Client(nil), base...)
	changed[0].Revoked = true
	if got := clientsFingerprint(changed); got == baseFingerprint {
		t.Fatal("fingerprint did not change after device state changed")
	}
}
