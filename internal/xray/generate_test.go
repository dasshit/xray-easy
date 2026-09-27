package xray

import "testing"

func TestValidatePublicHost(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "198.51.100.10", "node-1.example"} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("expected %q to be accepted: %v", host, err)
		}
	}
	for _, host := range []string{"", "https://vpn.example.com", "2001:db8::1", "bad host", "-invalid.example"} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("expected %q to be rejected", host)
		}
	}
}
