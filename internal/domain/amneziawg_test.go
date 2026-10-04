package domain

import (
	"testing"
	"time"
)

func TestValidateAmneziaWGPeerName(t *testing.T) {
	for _, name := range []string{"a", "Phone-1", "12345678901234567890123456789012"} {
		if err := ValidateAmneziaWGPeerName(name); err != nil {
			t.Errorf("ValidateAmneziaWGPeerName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "with_underscore", "with space", "../profile", "123456789012345678901234567890123"} {
		if err := ValidateAmneziaWGPeerName(name); err == nil {
			t.Errorf("ValidateAmneziaWGPeerName(%q) accepted invalid name", name)
		}
	}
}

func TestAmneziaWGPeerExpiration(t *testing.T) {
	now := time.Date(2026, time.October, 3, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)
	for _, test := range []struct {
		name string
		peer AmneziaWGPeer
		want bool
	}{
		{name: "no deadline", peer: AmneziaWGPeer{}, want: false},
		{name: "deadline in future", peer: AmneziaWGPeer{ExpiresAt: &future}, want: false},
		{name: "deadline reached", peer: AmneziaWGPeer{ExpiresAt: &now}, want: true},
		{name: "deadline passed", peer: AmneziaWGPeer{ExpiresAt: &past}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.peer.IsExpired(now); got != test.want {
				t.Fatalf("IsExpired(%s) = %v, want %v", now, got, test.want)
			}
		})
	}
}
