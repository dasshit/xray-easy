package runtime

import (
	"context"
	"fmt"
	"net"
	"testing"

	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

func TestEmbeddedEngineManagesUsersAndReplacesInboundLive(t *testing.T) {
	initialPort := freeEngineTCPPort(t)
	candidatePort := freeEngineTCPPort(t)
	initial := vlessTestConfiguration(initialPort)
	candidate := vlessTestConfiguration(candidatePort)
	engine, err := LoadEngine(initial)
	if err != nil {
		t.Fatalf("load embedded Xray engine: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close embedded Xray engine: %v", err)
		}
	}()
	if err := engine.Start(); err != nil {
		t.Fatalf("start embedded Xray engine: %v", err)
	}
	ctx := context.Background()
	protocol := xrayruntimev1.Protocol_PROTOCOL_VLESS
	credential := "12345678-1234-4234-8234-123456789012"
	added, err := engine.AddUser(ctx, protocol, "vless", "device-1", credential, "xtls-rprx-vision")
	if err != nil || added {
		t.Fatalf("add user already=%v error=%v", added, err)
	}
	added, err = engine.AddUser(ctx, protocol, "vless", "device-1", credential, "xtls-rprx-vision")
	if err != nil || !added {
		t.Fatalf("idempotent add already=%v error=%v", added, err)
	}
	if _, err := engine.AddUser(ctx, protocol, "vless", "device-1", "87654321-4321-4321-8321-210987654321", "xtls-rprx-vision"); err == nil {
		t.Fatal("conflicting credential for existing email was accepted")
	}
	users, err := engine.ListUsers(ctx, "vless")
	if err != nil || len(users) != 1 || users[0] != "device-1" {
		t.Fatalf("users=%v error=%v", users, err)
	}
	alreadyAbsent, err := engine.RemoveUser(ctx, "vless", "device-1")
	if err != nil || alreadyAbsent {
		t.Fatalf("remove existing user alreadyAbsent=%v error=%v", alreadyAbsent, err)
	}
	alreadyAbsent, err = engine.RemoveUser(ctx, "vless", "device-1")
	if err != nil || !alreadyAbsent {
		t.Fatalf("remove absent user alreadyAbsent=%v error=%v", alreadyAbsent, err)
	}
	if _, err := engine.ReplaceInbound(ctx, "vless", candidate); err != nil {
		t.Fatalf("replace active inbound: %v", err)
	}
	if alreadyCurrent, err := engine.ReplaceInbound(ctx, "vless", candidate); err != nil || !alreadyCurrent {
		t.Fatalf("idempotent inbound replace already=%v error=%v", alreadyCurrent, err)
	}
	if _, err := engine.ReplaceInbound(ctx, "vless", []byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`)); err != nil {
		t.Fatalf("remove inbound: %v", err)
	}
	if alreadyCurrent, err := engine.ReplaceInbound(ctx, "vless", []byte(`{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}`)); err != nil || !alreadyCurrent {
		t.Fatalf("idempotent inbound removal already=%v error=%v", alreadyCurrent, err)
	}
}

func TestAccountFactoryRejectsUnsupportedProtocolAndInvalidUUID(t *testing.T) {
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED, "credential", ""); err == nil {
		t.Fatal("unspecified protocol was accepted")
	}
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VLESS, "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", ""); err == nil {
		t.Fatal("invalid VLESS UUID was accepted")
	}
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VMESS, "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", ""); err == nil {
		t.Fatal("invalid VMess UUID was accepted")
	}
	credential := "12345678-1234-4234-8234-123456789012"
	vision, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VLESS, credential, "xtls-rprx-vision")
	if err != nil {
		t.Fatal(err)
	}
	withoutFlow, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VLESS, credential, "")
	if err != nil {
		t.Fatal(err)
	}
	if sameAccount(vision, withoutFlow) {
		t.Fatal("VLESS accounts with different flows were considered identical")
	}
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VLESS, credential, "unsupported-flow"); err == nil {
		t.Fatal("unsupported VLESS flow was accepted")
	}
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_VMESS, credential, "vision"); err == nil {
		t.Fatal("VMess flow was accepted")
	}
	if _, err := accountFor(xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, "auth-secret", "flow"); err == nil {
		t.Fatal("Hysteria flow was accepted")
	}
}

func TestInboundConfigurationLookupAndUninitializedEngine(t *testing.T) {
	configuration := vlessTestConfiguration(12345)
	if inbound, err := InboundConfiguration(configuration, "vless"); err != nil || inbound == nil || inbound.GetTag() != "vless" {
		t.Fatalf("inbound=%v error=%v", inbound, err)
	}
	if inbound, err := InboundConfiguration(configuration, "missing"); err != nil || inbound != nil {
		t.Fatalf("missing inbound=%v error=%v", inbound, err)
	}
	if _, err := InboundConfiguration([]byte("bad json"), "vless"); err == nil {
		t.Fatal("invalid config was accepted")
	}
	var engine *Engine
	if _, err := engine.ReplaceInbound(context.Background(), "vless", configuration); err == nil {
		t.Fatal("uninitialized engine replaced an inbound")
	}
	if _, err := engine.AddUser(context.Background(), xrayruntimev1.Protocol_PROTOCOL_VLESS, "vless", "email", "credential", ""); err == nil {
		t.Fatal("uninitialized engine added a user")
	}
	if _, err := engine.RemoveUser(context.Background(), "vless", "email"); err == nil {
		t.Fatal("uninitialized engine removed a user")
	}
	if _, err := engine.ListUsers(context.Background(), "vless"); err == nil {
		t.Fatal("uninitialized engine listed users")
	}
}

func vlessTestConfiguration(port int) []byte {
	return []byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","tag":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, port))
}

func freeEngineTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local test TCP port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
