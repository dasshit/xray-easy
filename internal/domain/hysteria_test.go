package domain

import "testing"

func TestHysteriaSettingsValidate(t *testing.T) {
	valid := HysteriaSettings{
		TLSMode: HysteriaTLSSelfSigned, TLSCertIP: "89.169.13.234", TLSServerName: "89.169.13.234",
		UDPIdleTimeout: 60, MasqueradeType: HysteriaMasqueradeOff,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*HysteriaSettings)
	}{
		{"invalid TLS mode", func(value *HysteriaSettings) { value.TLSMode = "plain" }},
		{"private IPv4", func(value *HysteriaSettings) { value.TLSCertIP = "10.0.0.1" }},
		{"mismatched SNI", func(value *HysteriaSettings) { value.TLSServerName = "vpn.example.com" }},
		{"short certificate ID", func(value *HysteriaSettings) { value.CertificateID = "../private-key" }},
		{"short UDP timeout", func(value *HysteriaSettings) { value.UDPIdleTimeout = 9 }},
		{"empty masquerade text", func(value *HysteriaSettings) { value.MasqueradeType = HysteriaMasqueradeText }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := valid
			test.mutate(&settings)
			if err := settings.Validate(); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
}

func TestHysteriaSettingsEffectiveTLSServerName(t *testing.T) {
	tests := []struct {
		name     string
		settings HysteriaSettings
		public   string
		want     string
	}{
		{
			name:     "explicit server name",
			settings: HysteriaSettings{TLSServerName: "tls.example.net", Host: "proxy.example.net", TLSMode: HysteriaTLSSelfSigned, TLSCertIP: "203.0.113.4"},
			public:   "node.example.net",
			want:     "tls.example.net",
		},
		{
			name:     "self-signed certificate address",
			settings: HysteriaSettings{TLSMode: HysteriaTLSSelfSigned, TLSCertIP: "203.0.113.4", Host: "proxy.example.net"},
			public:   "node.example.net",
			want:     "203.0.113.4",
		},
		{
			name:     "configured host",
			settings: HysteriaSettings{Host: "proxy.example.net"},
			public:   "node.example.net",
			want:     "proxy.example.net",
		},
		{
			name:     "node public host fallback",
			settings: HysteriaSettings{},
			public:   "node.example.net",
			want:     "node.example.net",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.settings.EffectiveTLSServerName(test.public); got != test.want {
				t.Fatalf("EffectiveTLSServerName() = %q, want %q", got, test.want)
			}
		})
	}
}
