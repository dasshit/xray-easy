package main

import (
	"testing"

	"xray-easy/internal/domain"
)

func TestClientProtocolStatesIncludesOnlyCredentialsPresentOnEachProfile(t *testing.T) {
	clients := []domain.Client{
		{ID: "legacy", Protocol: domain.ProtocolLegacyDual, VLESSEnabled: true, HysteriaEnabled: false, HysteriaRevoked: true},
		{ID: "vless", Protocol: domain.ProtocolVLESS, VLESSEnabled: false, VLESSRevoked: true},
		{ID: "hysteria", Protocol: domain.ProtocolHysteria2, HysteriaEnabled: true},
		{ID: "vmess", Protocol: domain.ProtocolVMess, VMessEnabled: true},
		{ID: "awg", Protocol: domain.ProtocolAmneziaWG},
	}
	got := clientProtocolStates(clients)
	if len(got) != 3 {
		t.Fatalf("protocol transition map has %d profiles: %+v", len(got), got)
	}
	if len(got["legacy"]) != 2 || got["legacy"][domain.ProtocolHysteria2] != (domain.ClientState{Revoked: true}) {
		t.Fatalf("legacy protocol states = %+v", got["legacy"])
	}
	if got["vless"][domain.ProtocolVLESS] != (domain.ClientState{Revoked: true}) || len(got["vless"]) != 1 {
		t.Fatalf("VLESS-only transition = %+v", got["vless"])
	}
	if got["hysteria"][domain.ProtocolHysteria2] != (domain.ClientState{Enabled: true}) || len(got["hysteria"]) != 1 {
		t.Fatalf("Hysteria-only transition = %+v", got["hysteria"])
	}
	if _, ok := got["vmess"]; ok {
		t.Fatalf("VMess profile should be preserved without a REALITY/Hysteria transition: %+v", got["vmess"])
	}
	if _, ok := got["awg"]; ok {
		t.Fatal("AWG profile should not be included in Xray transition map")
	}
}
