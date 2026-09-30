package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	corestats "github.com/xtls/xray-core/features/stats"
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
	statsManager, ok := engine.instance.GetFeature(corestats.ManagerType()).(corestats.Manager)
	if !ok || statsManager == nil {
		t.Fatal("configured embedded Xray instance has no stats manager")
	}
	uplink, err := statsManager.GetOrRegisterCounter("user>>>device-1>>>traffic>>>uplink")
	if err != nil {
		t.Fatal(err)
	}
	uplink.Set(321)
	downlink, err := statsManager.GetOrRegisterCounter("user>>>device-1>>>traffic>>>downlink")
	if err != nil {
		t.Fatal(err)
	}
	downlink.Set(654)
	online, err := statsManager.GetOrRegisterOnlineMap("user>>>device-1>>>online")
	if err != nil {
		t.Fatal(err)
	}
	online.AddIP("::ffff:192.0.2.45")
	telemetry, err := engine.GetTelemetry(ctx, map[xrayruntimev1.Protocol]string{protocol: "vless"})
	if err != nil || len(telemetry) != 1 {
		t.Fatalf("read embedded telemetry=%+v error=%v", telemetry, err)
	}
	if telemetry[0].Email != "device-1" || telemetry[0].UploadBytes != 321 || telemetry[0].DownloadBytes != 654 || !telemetry[0].Online || len(telemetry[0].SourceIPs) != 1 || telemetry[0].SourceIPs[0].Address != "192.0.2.45" || telemetry[0].LastSeen.IsZero() {
		t.Fatalf("embedded telemetry=%+v", telemetry[0])
	}
	online.RemoveIP("::ffff:192.0.2.45")
	telemetry, err = engine.GetTelemetry(ctx, map[xrayruntimev1.Protocol]string{protocol: "vless"})
	if err != nil || len(telemetry) != 1 || telemetry[0].Online || len(telemetry[0].SourceIPs) != 0 || telemetry[0].UploadBytes != 321 {
		t.Fatalf("offline embedded telemetry=%+v error=%v", telemetry, err)
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

func TestEmbeddedEngineCollectsTelemetryForEachConfiguredProtocol(t *testing.T) {
	vlessPort := freeEngineTCPPort(t)
	vmessPort := freeEngineTCPPort(t)
	hysteriaPort := freeEngineUDPPort(t)
	certificateFile, keyFile := writeEngineTestCertificate(t)
	configuration := []byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}}},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","tag":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}},{"listen":"127.0.0.1","port":%d,"protocol":"vmess","tag":"vmess","settings":{"clients":[]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]}}},{"listen":"127.0.0.1","port":%d,"protocol":"hysteria","tag":"hysteria2","settings":{"version":2,"users":[]},"streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"certificates":[{"certificateFile":%q,"keyFile":%q}]},"hysteriaSettings":{"version":2,"udpIdleTimeout":60}}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, vlessPort, vmessPort, certificateFile, keyFile, hysteriaPort, certificateFile, keyFile))
	engine, err := LoadEngine(configuration)
	if err != nil {
		t.Fatalf("load multi-protocol Xray config: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			t.Errorf("close multi-protocol engine: %v", err)
		}
	}()
	if err := engine.Start(); err != nil {
		t.Fatalf("start multi-protocol Xray config: %v", err)
	}

	ctx := context.Background()
	users := []struct {
		protocol   xrayruntimev1.Protocol
		tag        string
		email      string
		credential string
		flow       string
	}{
		{xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, "hysteria2", "telemetry-hysteria", "hysteria-secret", ""},
		{xrayruntimev1.Protocol_PROTOCOL_VLESS, "vless", "telemetry-vless", "12345678-1234-4234-8234-123456789012", "xtls-rprx-vision"},
		{xrayruntimev1.Protocol_PROTOCOL_VMESS, "vmess", "telemetry-vmess", "12345678-1234-4234-8234-123456789013", ""},
	}
	tags := make(map[xrayruntimev1.Protocol]string, len(users))
	statsManager, ok := engine.instance.GetFeature(corestats.ManagerType()).(corestats.Manager)
	if !ok || statsManager == nil {
		t.Fatal("multi-protocol engine has no stats manager")
	}
	for i, user := range users {
		tags[user.protocol] = user.tag
		if _, err := engine.AddUser(ctx, user.protocol, user.tag, user.email, user.credential, user.flow); err != nil {
			t.Fatalf("add %s telemetry user: %v", user.protocol, err)
		}
		for direction, value := range map[string]int64{"uplink": int64(100 + i), "downlink": int64(200 + i)} {
			counter, err := statsManager.GetOrRegisterCounter("user>>>" + user.email + ">>>traffic>>>" + direction)
			if err != nil {
				t.Fatal(err)
			}
			counter.Set(value)
		}
		online, err := statsManager.GetOrRegisterOnlineMap("user>>>" + user.email + ">>>online")
		if err != nil {
			t.Fatal(err)
		}
		online.AddIP(fmt.Sprintf("192.0.2.%d", 40+i))
	}
	telemetry, err := engine.GetTelemetry(ctx, tags)
	if err != nil || len(telemetry) != len(users) {
		t.Fatalf("collect protocol telemetry=%+v error=%v", telemetry, err)
	}
	for i, user := range users {
		item := telemetry[i]
		if item.Email != user.email || item.UploadBytes != int64(100+i) || item.DownloadBytes != int64(200+i) || !item.Online || len(item.SourceIPs) != 1 || item.SourceIPs[0].Address != fmt.Sprintf("192.0.2.%d", 40+i) {
			t.Errorf("telemetry for %s = %+v", user.protocol, item)
		}
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
	return []byte(fmt.Sprintf(`{"log":{"loglevel":"none"},"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}}},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","tag":"vless","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`, port))
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

func freeEngineUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local test UDP port: %v", err)
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func writeEngineTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test TLS key: %v", err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "fullchain.pem")
	keyFile := filepath.Join(directory, "privkey.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatalf("write test TLS key: %v", err)
	}
	return certificateFile, keyFile
}
