package domain

import "testing"

func TestValidatePublicHost(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "89.169.13.234", "sub-domain.example.", "localhost"} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("ValidatePublicHost(%q): %v", host, err)
		}
	}
	for _, host := range []string{"", "::1", "host/path", "bad..name", "-bad.example"} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("ValidatePublicHost(%q) unexpectedly succeeded", host)
		}
	}
}

func TestValidateRealityTarget(t *testing.T) {
	if err := ValidateRealityTarget("example.com:443", "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ target, sni string }{
		{"127.0.0.1:443", "example.com"},
		{"example.com:0", "example.com"},
		{"example.com:443", ""},
	} {
		if err := ValidateRealityTarget(test.target, test.sni); err == nil {
			t.Errorf("ValidateRealityTarget(%q, %q) unexpectedly succeeded", test.target, test.sni)
		}
	}
}
