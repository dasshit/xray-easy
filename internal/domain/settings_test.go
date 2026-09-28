package domain

import (
	"strings"
	"testing"
)

func TestValidatePublicHost(t *testing.T) {
	for _, host := range []string{"vpn.example.com", "89.169.13.234", "sub-domain.example.", "localhost", "2001:db8::1", "2001:0db8:0:0::1"} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("ValidatePublicHost(%q): %v", host, err)
		}
	}
	for _, host := range []string{"", "::1", "[2001:db8::1]", "[2001:db8::1]:443", "fe80::1%eth0", "fd12::1", "::", "ff02::1", "::ffff:192.0.2.1", "host/path", "bad..name", "-bad.example"} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("ValidatePublicHost(%q) unexpectedly succeeded", host)
		}
	}
}

func TestNormalizePublicHost(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "  2001:0db8:0:0:0:0:0:1  ", want: "2001:db8::1"},
		{input: "89.169.13.234", want: "89.169.13.234"},
		{input: "vpn.example.com", want: "vpn.example.com"},
	} {
		got, err := NormalizePublicHost(test.input)
		if err != nil {
			t.Errorf("NormalizePublicHost(%q): %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("NormalizePublicHost(%q) = %q, want %q", test.input, got, test.want)
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

func TestValidateConnection(t *testing.T) {
	valid := Settings{
		PublicHost: "vpn.example.com", PublicPort: 443,
		RealityTarget: "example.com:443", RealitySNI: "example.com",
		ClientFingerprint: "safari",
	}
	if err := valid.ValidateConnection(); err != nil {
		t.Fatalf("valid connection rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*Settings)
	}{
		{"public host", func(s *Settings) { s.PublicHost = "bad host" }},
		{"public port below range", func(s *Settings) { s.PublicPort = 0 }},
		{"public port above range", func(s *Settings) { s.PublicPort = 65536 }},
		{"REALITY target", func(s *Settings) { s.RealityTarget = "127.0.0.1:443" }},
		{"fingerprint", func(s *Settings) { s.ClientFingerprint = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.change(&candidate)
			if err := candidate.ValidateConnection(); err == nil {
				t.Fatal("invalid connection settings accepted")
			}
		})
	}
}

func TestValidateRealityTargetRejectsLocalAddressesAndInvalidSNI(t *testing.T) {
	for _, target := range []string{
		"127.0.0.1:443", "10.0.0.1:443", "169.254.1.1:443", "0.0.0.0:443",
		"224.0.0.1:443", "[::1]:443", "example.com:65536", "example.com:https",
		"example.com", "example.com:443/path",
	} {
		if err := ValidateRealityTarget(target, "example.com"); err == nil {
			t.Errorf("ValidateRealityTarget accepted target %q", target)
		}
	}
	for _, sni := range []string{"", "example.com/path", "example.com?x", "example.com#x", "exam\nple.com"} {
		if err := ValidateRealityTarget("example.com:443", sni); err == nil {
			t.Errorf("ValidateRealityTarget accepted SNI %q", sni)
		}
	}
}

func TestValidatePublicHostBoundaryCases(t *testing.T) {
	for _, host := range []string{
		"a", "example.com.", "123.example", "192.0.2.1",
		"a" + strings.Repeat("b", 61) + ".example",
	} {
		if err := ValidatePublicHost(host); err != nil {
			t.Errorf("valid public host %q rejected: %v", host, err)
		}
	}
	for _, host := range []string{
		strings.Repeat("a", 254), "example..com", "example-.com", "-example.com",
		"a" + strings.Repeat("b", 63) + ".example", "[2001:db8::1]", "https://example.com",
	} {
		if err := ValidatePublicHost(host); err == nil {
			t.Errorf("invalid public host %q accepted", host)
		}
	}
}
