package domain

import "testing"

func TestShadowsocksSettingsValidate(t *testing.T) {
	valid := ShadowsocksSettings{Enabled: true, PublicPort: 8388, Method: ShadowsocksMethod2022AES256GCM, Network: ShadowsocksNetworkTCPUDP}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	for _, mutate := range []func(*ShadowsocksSettings){
		func(s *ShadowsocksSettings) { s.PublicPort = 0 },
		func(s *ShadowsocksSettings) { s.PublicPort = 65536 },
		func(s *ShadowsocksSettings) { s.Method = "aes-256-gcm" },
		func(s *ShadowsocksSettings) { s.Network = "tcp,udp,quic" },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid settings accepted: %+v", candidate)
		}
	}
	if err := (ShadowsocksSettings{}).Validate(); err != nil {
		t.Fatalf("disabled settings must not require an active listener: %v", err)
	}
}

func TestSupportsShadowsocksMethodAndNetwork(t *testing.T) {
	if !SupportsShadowsocksMethod(ShadowsocksMethod2022AES256GCM) {
		t.Errorf("method %q should be supported", ShadowsocksMethod2022AES256GCM)
	}
	for _, network := range []string{ShadowsocksNetworkTCP, ShadowsocksNetworkUDP, ShadowsocksNetworkTCPUDP} {
		if !SupportsShadowsocksNetwork(network) {
			t.Errorf("network %q should be supported", network)
		}
	}
	if SupportsShadowsocksMethod("chacha20-poly1305") || SupportsShadowsocksNetwork("tcp,udp,icmp") {
		t.Fatal("unsupported Shadowsocks method or network accepted")
	}
}

func TestShadowsocksSettingsString(t *testing.T) {
	settings := ShadowsocksSettings{PublicPort: 8388, Method: ShadowsocksMethod2022AES256GCM, Network: ShadowsocksNetworkTCPUDP}
	if got := settings.String(); got != "8388/2022-blake3-aes-256-gcm/tcp,udp" {
		t.Fatalf("Shadowsocks settings string = %q", got)
	}
}
