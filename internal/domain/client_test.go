package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClientLifecycle(t *testing.T) {
	client, err := NewClient("device-1", "my-phone", "safari")
	if err != nil {
		t.Fatal(err)
	}
	if !client.CanConnect() {
		t.Fatal("new profile must be connectable")
	}

	disabled := client.Disable()
	if disabled.CanConnect() || disabled.Revoked {
		t.Fatalf("unexpected disabled state: %+v", disabled)
	}
	revoked := disabled.Revoke()
	if revoked.CanConnect() || !revoked.Revoked || revoked.Enabled {
		t.Fatalf("unexpected revoked state: %+v", revoked)
	}
	if _, err := revoked.Enable(); !errors.Is(err, ErrClientRevoked) {
		t.Fatalf("enabling revoked profile error = %v", err)
	}
	if transitioned, err := client.Transition(ActionRevoke); err != nil || !transitioned.Revoked {
		t.Fatalf("revoke transition = %+v, %v", transitioned, err)
	}
}

func TestClientExpiryBlocksConnectionAndEnableUntilExtended(t *testing.T) {
	deadline := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("UTC+2", 2*60*60))
	client, err := NewProtocolClient("expiry-client", "phone", ProtocolVLESS, "", "")
	if err != nil {
		t.Fatal(err)
	}
	client.ExpiresAt = &deadline
	before := deadline.Add(-time.Nanosecond)
	at := deadline
	if client.IsExpired(before) || !client.IsExpired(at) {
		t.Fatalf("expiry boundary before=%v at=%v", client.IsExpired(before), client.IsExpired(at))
	}
	if err := client.CanEnableAt(at); !errors.Is(err, ErrClientExpired) {
		t.Fatalf("enable expired profile error = %v", err)
	}
	if client.VLESSCanConnect() || client.CanConnect() {
		t.Fatal("expired profile remained connectable")
	}
	client.Enabled, client.VLESSEnabled = false, false
	if _, err := client.Enable(); !errors.Is(err, ErrClientExpired) {
		t.Fatalf("Enable() for expired profile error = %v", err)
	}
	newDeadline := time.Now().UTC().Add(time.Hour)
	client.ExpiresAt = &newDeadline
	if _, err := client.Enable(); err != nil {
		t.Fatalf("Enable() after expiry extension error = %v", err)
	}
	client.Revoked = true
	if err := client.CanEnableAt(time.Now()); !errors.Is(err, ErrClientRevoked) {
		t.Fatalf("permanently revoked profile error = %v, want revoke precedence", err)
	}
}

func TestNewClientValidation(t *testing.T) {
	for _, input := range []struct{ id, name, fingerprint string }{
		{"", "phone", "chrome"},
		{"id", "phone name", "chrome"},
		{"id", "phone", "unknown"},
	} {
		if _, err := NewClient(input.id, input.name, input.fingerprint); err == nil {
			t.Errorf("NewClient(%q, %q, %q) unexpectedly succeeded", input.id, input.name, input.fingerprint)
		}
	}
}

func TestClientTransitionCoversActionsAndRevokedState(t *testing.T) {
	client, err := NewClient("device-1", "phone-1", "safari")
	if err != nil {
		t.Fatal(err)
	}
	disabled := client.Disable()
	enabled, err := disabled.Transition(ActionEnable)
	if err != nil || !enabled.Enabled || enabled.Revoked {
		t.Fatalf("enable transition = %+v, %v", enabled, err)
	}
	for _, action := range []ClientAction{ActionDisable, ActionRevoke} {
		got, err := client.Transition(action)
		if err != nil {
			t.Errorf("transition %q: %v", action, err)
		}
		if got.CanConnect() {
			t.Errorf("transition %q left profile connectable: %+v", action, got)
		}
		if (action == ActionRevoke) != got.Revoked {
			t.Errorf("transition %q revoked=%v", action, got.Revoked)
		}
	}
	if got, err := client.Transition("unknown"); err == nil || got.ID != "" {
		t.Fatalf("unknown transition = %+v, %v; want zero value and error", got, err)
	}
	if got, err := client.Revoke().Transition(ActionDisable); err != nil || got.Enabled || !got.Revoked {
		t.Fatalf("disabling revoked profile = %+v, %v", got, err)
	}
}

func TestSupportsFingerprint(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "firefox", "safari", "edge", "ios", "android", "random"} {
		if !SupportsFingerprint(fingerprint) {
			t.Errorf("supported fingerprint %q rejected", fingerprint)
		}
	}
	for _, fingerprint := range []string{"", "Chrome", "unknown"} {
		if SupportsFingerprint(fingerprint) {
			t.Errorf("unsupported fingerprint %q accepted", fingerprint)
		}
	}
}

func TestNewClientTrimsValuesAndAllowsOptionalFingerprint(t *testing.T) {
	client, err := NewClient("device", " phone-1 ", " safari ")
	if err != nil {
		t.Fatal(err)
	}
	if client.Name != "phone-1" || client.ClientFingerprint != "safari" {
		t.Fatalf("values were not normalized: %+v", client)
	}
	if _, err := NewClient("device", "phone", ""); err != nil {
		t.Fatalf("empty fingerprint should use node default: %v", err)
	}
}

func TestNewProtocolClientCreatesOneInboundAccess(t *testing.T) {
	vless, err := NewProtocolClient("vless-id", "phone", ProtocolVLESS, "safari", "")
	if err != nil || vless.Protocol != ProtocolVLESS || !vless.VLESSCanConnect() || vless.HasHysteria2() || vless.UUID != "" || vless.ShortID != "" {
		t.Fatalf("VLESS-only profile = %+v, %v", vless, err)
	}
	hysteria, err := NewProtocolClient("hysteria-id", "phone", ProtocolHysteria2, "", "device-secret")
	if err != nil || hysteria.Protocol != ProtocolHysteria2 || !hysteria.Hysteria2CanConnect() || hysteria.HasVLESS() || hysteria.HysteriaAuth != "device-secret" {
		t.Fatalf("Hysteria-only profile = %+v, %v", hysteria, err)
	}
	vmess, err := NewProtocolClient("vmess-id", "phone", ProtocolVMess, "", "")
	if err != nil || vmess.Protocol != ProtocolVMess || !vmess.HasVMess() || !vmess.VMessCanConnect() || vmess.HasVLESS() || vmess.HasHysteria2() {
		t.Fatalf("VMess-only profile = %+v, %v", vmess, err)
	}
	shadowsocks, err := NewShadowsocksClient("ss-id", "phone")
	if err != nil || shadowsocks.Protocol != ProtocolShadowsocks || !shadowsocks.HasShadowsocks() || !shadowsocks.ShadowsocksCanConnect() || shadowsocks.HasVLESS() {
		t.Fatalf("Shadowsocks profile = %+v, %v", shadowsocks, err)
	}
	if _, err := NewProtocolClient("dual-id", "phone", ProtocolLegacyDual, "", "secret"); err == nil {
		t.Fatal("new dual-protocol profile was accepted")
	}
	trojan, err := NewProtocolClient("trojan-id", "phone", ProtocolTrojan, "", "")
	if err != nil || trojan.Protocol != ProtocolTrojan || !trojan.HasTrojan() || !trojan.TrojanCanConnect() || trojan.HasVLESS() || trojan.HasVMess() {
		t.Fatalf("Trojan-only profile = %+v, %v", trojan, err)
	}
	for _, auth := range []string{"", "bad\nsecret", strings.Repeat("x", 257)} {
		if _, err := NewProtocolClient("h-id", "phone", ProtocolHysteria2, "", auth); err == nil {
			t.Errorf("Hysteria auth %q was accepted", auth)
		}
	}
}

func TestTrojanConnectivityRequiresActiveCredentialProtocol(t *testing.T) {
	client := Client{Protocol: ProtocolTrojan, TrojanEnabled: true}
	if !client.HasTrojan() || !client.TrojanCanConnect() {
		t.Fatalf("enabled Trojan profile should connect: %+v", client)
	}
	client.TrojanRevoked = true
	if client.TrojanCanConnect() {
		t.Fatal("revoked Trojan profile remained connectable")
	}
	client.Protocol = ProtocolVLESS
	client.TrojanRevoked = false
	if client.HasTrojan() || client.TrojanCanConnect() {
		t.Fatal("Trojan access leaked into another protocol")
	}
}

func TestClientAccessStateIsIndependentByProtocol(t *testing.T) {
	client, err := NewClient("dual-id", "phone", "safari")
	if err != nil {
		t.Fatal(err)
	}
	if !client.VLESSCanConnect() || !client.Hysteria2CanConnect() {
		t.Fatalf("legacy dual profile did not initialize both accesses: %+v", client)
	}
	state, err := client.AccessState(ProtocolHysteria2)
	if err != nil || !state.Enabled || state.Revoked {
		t.Fatalf("Hysteria access state = %+v, %v", state, err)
	}
	if _, err := client.AccessState(ProtocolVLESS); err != nil {
		t.Fatalf("legacy VLESS access was missing: %v", err)
	}
	if _, err := NewProtocolClient("id", "phone", ProtocolHysteria2, "", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AccessState("unsupported"); err == nil {
		t.Fatal("unsupported protocol state was returned")
	}
}

func TestProtocolAccessHelpersAndHysteriaCredentialFallback(t *testing.T) {
	legacy := Client{Protocol: ProtocolLegacyDual, UUID: "legacy-uuid", HysteriaAuth: "  explicit-auth  "}
	if !legacy.HasVLESS() || !legacy.HasHysteria2() || legacy.HasVMess() {
		t.Fatalf("legacy protocol membership is incorrect: %+v", legacy)
	}
	if got := legacy.HysteriaCredential(); got != "  explicit-auth  " {
		t.Fatalf("explicit Hysteria credential = %q", got)
	}
	legacy.HysteriaAuth = ""
	if got := legacy.HysteriaCredential(); got != "legacy-uuid" {
		t.Fatalf("legacy Hysteria credential fallback = %q", got)
	}
	if legacy.VLESSCanConnect() || legacy.Hysteria2CanConnect() || legacy.VMessCanConnect() {
		t.Fatal("disabled access unexpectedly connects")
	}

	vless := Client{Protocol: ProtocolVLESS, VLESSEnabled: true}
	if !vless.VLESSCanConnect() || vless.Hysteria2CanConnect() || vless.VMessCanConnect() {
		t.Fatal("VLESS connectivity leaked across protocols")
	}
	hysteria := Client{Protocol: ProtocolHysteria2, HysteriaEnabled: true, HysteriaRevoked: true}
	if hysteria.Hysteria2CanConnect() {
		t.Fatal("revoked Hysteria access is connectable")
	}
	vmess := Client{Protocol: ProtocolVMess, Enabled: true}
	if !vmess.HasVMess() || !vmess.VMessCanConnect() || vmess.HasVLESS() || vmess.HasHysteria2() {
		t.Fatal("VMess connectivity or membership is incorrect")
	}
}

func TestAccessStateRejectsMissingAndUnsupportedProtocols(t *testing.T) {
	client := Client{Protocol: ProtocolVLESS, VLESSEnabled: true}
	for _, protocol := range []ClientProtocol{ProtocolHysteria2, ProtocolVMess, ProtocolShadowsocks, ProtocolTrojan, ProtocolAmneziaWG, "unknown"} {
		if _, err := client.AccessState(protocol); err == nil {
			t.Errorf("AccessState(%q) unexpectedly succeeded", protocol)
		}
	}
	if _, err := (Client{Protocol: ProtocolHysteria2}).AccessState(ProtocolHysteria2); err != nil {
		t.Fatalf("Hysteria access state: %v", err)
	}
	if _, err := (Client{Protocol: ProtocolVMess}).AccessState(ProtocolVMess); err != nil {
		t.Fatalf("VMess access state: %v", err)
	}
}

func TestNewProtocolClientValidatesHysteriaCredentialsAndProtocolSpecificFields(t *testing.T) {
	for _, auth := range []string{"", " \t", strings.Repeat("x", 257), "bad\nvalue"} {
		if _, err := NewProtocolClient("id", "phone", ProtocolHysteria2, "", auth); err == nil {
			t.Errorf("invalid Hysteria credential %q was accepted", auth)
		}
	}
	client, err := NewProtocolClient("id", " phone ", ProtocolHysteria2, "ignored", "  password  ")
	if err != nil || client.Name != "phone" || client.HysteriaAuth != "password" || client.ClientFingerprint != "" || !client.HysteriaEnabled {
		t.Fatalf("Hysteria client = %+v, %v", client, err)
	}
	for _, protocol := range []ClientProtocol{ProtocolLegacyDual, ProtocolAmneziaWG, "unknown"} {
		if _, err := NewProtocolClient("id", "phone", protocol, "", "password"); err == nil {
			t.Errorf("unsupported new profile protocol %q was accepted", protocol)
		}
	}
}

func TestNewProtocolClientRejectsMissingIdentityAndInvalidNames(t *testing.T) {
	for _, test := range []struct{ id, name string }{{"", "phone"}, {"id", "two words"}} {
		if client, err := NewProtocolClient(test.id, test.name, ProtocolVMess, "", ""); err == nil || client.ID != "" {
			t.Errorf("NewProtocolClient(%q, %q) = %+v, %v; want validation error", test.id, test.name, client, err)
		}
	}
	client, err := NewProtocolClient("ss-id", " phone ", ProtocolShadowsocks, "ignored", "ignored")
	if err != nil || client.Name != "phone" || client.Protocol != ProtocolShadowsocks || !client.ShadowsocksEnabled {
		t.Fatalf("Shadowsocks profile = %+v, %v", client, err)
	}
}

func TestProtocolAccessStateAndShadowsocksConstructorValidation(t *testing.T) {
	for _, test := range []struct {
		name     string
		client   Client
		protocol ClientProtocol
		want     ClientState
	}{
		{"VLESS", Client{Protocol: ProtocolVLESS, VLESSEnabled: true, VLESSRevoked: true}, ProtocolVLESS, ClientState{Enabled: true, Revoked: true}},
		{"Hysteria 2", Client{Protocol: ProtocolHysteria2, HysteriaEnabled: true, HysteriaRevoked: true}, ProtocolHysteria2, ClientState{Enabled: true, Revoked: true}},
		{"VMess", Client{Protocol: ProtocolVMess, Enabled: true, Revoked: true}, ProtocolVMess, ClientState{Enabled: true, Revoked: true}},
		{"Shadowsocks", Client{Protocol: ProtocolShadowsocks, ShadowsocksEnabled: true, ShadowsocksRevoked: true}, ProtocolShadowsocks, ClientState{Enabled: true, Revoked: true}},
		{"Trojan", Client{Protocol: ProtocolTrojan, TrojanEnabled: true, TrojanRevoked: true}, ProtocolTrojan, ClientState{Enabled: true, Revoked: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.client.AccessState(test.protocol)
			if err != nil || got != test.want {
				t.Fatalf("AccessState(%q) = %+v, %v; want %+v", test.protocol, got, err, test.want)
			}
		})
	}
	if _, err := (Client{Protocol: ProtocolHysteria2}).AccessState(ProtocolVLESS); err == nil {
		t.Fatal("VLESS state was returned for a Hysteria-only profile")
	}
	for _, input := range []struct{ id, name string }{{"", "phone"}, {"id", "two words"}} {
		if client, err := NewShadowsocksClient(input.id, input.name); err == nil || client.ID != "" {
			t.Errorf("NewShadowsocksClient(%q, %q) = %+v, %v; want validation error", input.id, input.name, client, err)
		}
	}
	if _, err := NewProtocolClient("id", "phone", ProtocolVLESS, "unsupported", ""); err == nil {
		t.Fatal("unsupported VLESS fingerprint was accepted")
	}
}
