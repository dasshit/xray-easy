package spike

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "xray-easy/xray-runtime/internal/xrayregistration"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/stats"
	xrayserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
)

func TestEmbeddedRealityRuntimeExposesLiveFeaturesAndUserManager(t *testing.T) {
	vlessPort := freeTCPPort(t)
	vmessPort := freeTCPPort(t)
	hysteriaPort := freeUDPPort(t)
	certificateFile, keyFile := writeSelfSignedCertificate(t)
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatalf("generate test REALITY key: %v", err)
	}

	configJSON, err := json.Marshal(map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"stats": map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
		}}},
		"inbounds": []any{
			map[string]any{
				"listen": "127.0.0.1", "port": vlessPort, "protocol": "vless", "tag": "vless-reality",
				"settings": map[string]any{"clients": []any{map[string]any{"id": "c94653da-cc9e-4431-866e-fc763509281a", "flow": "xtls-rprx-vision", "email": "spike-device"}}, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
					"target": "example.com:443", "serverNames": []string{"example.com"},
					"privateKey": base64.RawURLEncoding.EncodeToString(privateKey), "shortIds": []string{"0123abcd"},
				}},
			},
			map[string]any{
				"listen": "127.0.0.1", "port": vmessPort, "protocol": "vmess", "tag": "vmess-tls",
				"settings":       map[string]any{"clients": []any{map[string]any{"id": "9ad01091-a8d3-4650-9fb4-250982fd31a3", "alterId": 0, "email": "spike-vmess"}}},
				"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certificateFile, "keyFile": keyFile}}}},
			},
			map[string]any{
				"listen": "127.0.0.1", "port": hysteriaPort, "protocol": "hysteria", "tag": "hysteria2",
				"settings": map[string]any{"version": 2, "users": []any{map[string]any{"auth": "spike-secret", "email": "spike-hysteria", "level": 0}}},
				"streamSettings": map[string]any{
					"network": "hysteria", "security": "tls",
					"tlsSettings":      map[string]any{"certificates": []any{map[string]any{"certificateFile": certificateFile, "keyFile": keyFile}}},
					"hysteriaSettings": map[string]any{"version": 2, "udpIdleTimeout": 60},
				},
			},
		},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	})
	if err != nil {
		t.Fatalf("encode spike config: %v", err)
	}

	config, err := xrayserial.LoadJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		t.Fatalf("load rendered VLESS + REALITY config: %v", err)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatalf("construct embedded Xray instance: %v", err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Errorf("close embedded Xray instance: %v", err)
		}
	})
	if err := instance.Start(); err != nil {
		t.Fatalf("start embedded Xray instance: %v", err)
	}

	inboundFeature, ok := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if !ok {
		t.Fatal("Xray instance does not expose inbound.Manager")
	}
	statsFeature, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		t.Fatal("Xray instance does not expose stats.Manager")
	}
	managers := make(map[string]proxy.UserManager)
	for _, tag := range []string{"vless-reality", "vmess-tls", "hysteria2"} {
		handler, err := inboundFeature.GetHandler(context.Background(), tag)
		if err != nil {
			t.Fatalf("get %s inbound through inbound.Manager: %v", tag, err)
		}
		inboundProxy, ok := handler.(proxy.GetInbound)
		if !ok {
			t.Fatalf("Xray inbound handler %s does not expose proxy.GetInbound", tag)
		}
		userManager, ok := inboundProxy.GetInbound().(proxy.UserManager)
		if !ok {
			t.Fatalf("Xray inbound proxy %s does not implement proxy.UserManager", tag)
		}
		if got := userManager.GetUsersCount(context.Background()); got != 1 {
			t.Fatalf("initial user count for %s = %d, want 1", tag, got)
		}
		managers[tag] = userManager
	}

	vlessAccount, err := (&vless.Account{Id: "1c5d72ca-9f7c-4cf6-9cf3-a8b6ec688a01", Flow: "xtls-rprx-vision"}).AsAccount()
	if err != nil {
		t.Fatalf("build test VLESS account: %v", err)
	}
	vmessAccount, err := (&vmess.Account{Id: "d960dd23-f3d6-4c15-9d9d-75e9a7ac4a45", SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AUTO}}).AsAccount()
	if err != nil {
		t.Fatalf("build test VMess account: %v", err)
	}
	hysteriaUser, err := (&hysteriaaccount.Account{Auth: "new-spike-hysteria"}).AsAccount()
	if err != nil {
		t.Fatalf("build test Hysteria account: %v", err)
	}
	users := map[string]*protocol.MemoryUser{
		"vless-reality": {Email: "new-spike-vless", Account: vlessAccount},
		"vmess-tls":     {Email: "new-spike-vmess", Account: vmessAccount},
		"hysteria2":     {Email: "new-spike-hysteria", Account: hysteriaUser},
	}
	for tag, user := range users {
		manager := managers[tag]
		if err := manager.AddUser(context.Background(), user); err != nil {
			t.Fatalf("add %s user without HandlerService: %v", tag, err)
		}
		if got := manager.GetUsersCount(context.Background()); got != 2 {
			t.Fatalf("user count for %s after direct add = %d, want 2", tag, got)
		}
		if err := manager.RemoveUser(context.Background(), user.Email); err != nil {
			t.Fatalf("remove %s user without HandlerService: %v", tag, err)
		}
		if got := manager.GetUsersCount(context.Background()); got != 1 {
			t.Fatalf("user count for %s after direct remove = %d, want 1", tag, got)
		}
	}

	counter, err := statsFeature.GetOrRegisterCounter("user>>>new-spike-device>>>traffic>>>uplink")
	if err != nil || counter == nil {
		t.Fatalf("register in-process stats counter = %v, %v", counter, err)
	}
	counter.Add(42)
	if got := statsFeature.GetCounter("user>>>new-spike-device>>>traffic>>>uplink").Value(); got != 42 {
		t.Fatalf("in-process traffic counter = %d, want 42", got)
	}
	onlineMap, err := statsFeature.GetOrRegisterOnlineMap("user>>>new-spike-device>>>online")
	if err != nil || onlineMap == nil {
		t.Fatalf("register in-process online map = %v, %v", onlineMap, err)
	}
	onlineMap.AddIP("192.0.2.1")
	if got := onlineMap.Count(); got != 1 {
		t.Fatalf("in-process online map count = %d, want 1", got)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test TCP port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test UDP port: %v", err)
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func writeSelfSignedCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test TLS key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create test TLS certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal test TLS key: %v", err)
	}
	certificateFile := filepath.Join(t.TempDir(), "fullchain.pem")
	keyFile := filepath.Join(filepath.Dir(certificateFile), "privkey.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatalf("write test TLS key: %v", err)
	}
	return certificateFile, keyFile
}
