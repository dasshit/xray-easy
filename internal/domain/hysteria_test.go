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
