package domain

import (
	"errors"
	"strings"
	"testing"
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
	if _, err := NewProtocolClient("dual-id", "phone", ProtocolLegacyDual, "", "secret"); err == nil {
		t.Fatal("new dual-protocol profile was accepted")
	}
	for _, auth := range []string{"", "bad\nsecret", strings.Repeat("x", 257)} {
		if _, err := NewProtocolClient("h-id", "phone", ProtocolHysteria2, "", auth); err == nil {
			t.Errorf("Hysteria auth %q was accepted", auth)
		}
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
