package domain

import "testing"

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
