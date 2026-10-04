package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestProfileRouteReportsUnavailableProtocolFormats(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	hysteria := createRuntimeHysteriaClient(t, app, "hysteria-only")
	for _, format := range []struct{ name, text string }{
		{"json", "JSON profile is unavailable"},
		{"qr", "VLESS is not available"},
		{"vmess-qr", "VMess is not available"},
		{"ss-qr", "Shadowsocks is not enabled"},
		{"trojan-qr", "Trojan is not enabled"},
	} {
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+hysteria.ID+"/profile?format="+format.name, nil, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), format.text) {
			t.Errorf("Hysteria-only %s format = %d %s", format.name, response.Code, response.Body.String())
		}
	}

	vless := createRuntimeTestClient(t, app, "vless-only")
	for _, format := range []struct{ name, text string }{
		{"hysteria-qr", "Hysteria 2 is not enabled"},
		{"vmess-qr", "VMess is not available"},
		{"ss-qr", "Shadowsocks is not enabled"},
		{"trojan-qr", "Trojan is not enabled"},
	} {
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+vless.ID+"/profile?format="+format.name, nil, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), format.text) {
			t.Errorf("VLESS-only %s format = %d %s", format.name, response.Code, response.Body.String())
		}
	}

	vmess := createRuntimeVMessClient(t, app, "vmess-only")
	response := requestJSON(t, app, http.MethodGet, "/api/clients/"+vmess.ID+"/profile?format=hysteria-qr", nil, true)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "Hysteria 2 is not enabled") {
		t.Fatalf("VMess-only Hysteria QR = %d %s", response.Code, response.Body.String())
	}
}

func TestProfileRouteReportsTransportSettingsAndCertificateFailures(t *testing.T) {
	t.Run("Hysteria settings cannot be read", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "profile-settings-error")
		execSQLiteTestMutation(t, app, "drop Hysteria settings", `DROP TABLE hysteria_settings`)
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not read Hysteria 2 settings") {
			t.Fatalf("profile with unreadable Hysteria settings = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("shared TLS certificate is missing", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeVMessClient(t, app, "profile-certificate-error")
		if err := os.Remove(filepath.Join(app.server.hysteriaTLSDir(), "fullchain.pem")); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "could not read the shared TLS certificate fingerprint") {
			t.Fatalf("profile with missing shared certificate = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("Shadowsocks server key derivation fails", func(t *testing.T) {
		t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
		app := newTestApp(t, true)
		client := createRuntimeShadowsocksClient(t, app, "profile-shadowsocks-key-error")
		app.server.masterKey = []byte("short")
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not prepare Shadowsocks settings") {
			t.Fatalf("profile with invalid master key = %d %s", response.Code, response.Body.String())
		}
	})

}

func TestProfileQRCodeRejectsOversizedPayloads(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "11443")
	app := newTestApp(t, true)
	app.server.trojanPort = 11443
	clients := []struct {
		client domain.Client
		format string
		want   string
	}{
		{client: createRuntimeTestClient(t, app, "oversized-vless"), format: "qr", want: "could not encode QR"},
		{client: createRuntimeHysteriaClient(t, app, "oversized-hysteria"), format: "hysteria-qr", want: "could not encode Hysteria QR"},
		{client: createRuntimeVMessClient(t, app, "oversized-vmess"), format: "vmess-qr", want: "could not encode VMess QR"},
		{client: createRuntimeShadowsocksClient(t, app, "oversized-ss"), format: "ss-qr", want: "could not encode Shadowsocks QR"},
		{client: createRuntimeTrojanClient(t, app, "oversized-trojan"), format: "trojan-qr", want: "could not encode Trojan QR"},
	}
	for _, test := range clients {
		t.Run(test.format, func(t *testing.T) {
			largeName := strings.Repeat("x", 5000)
			execSQLiteTestMutation(t, app, "set long profile name", "UPDATE clients SET name='"+largeName+"' WHERE id='"+test.client.ID+"'")
			response := requestJSON(t, app, http.MethodGet, "/api/clients/"+test.client.ID+"/profile?format="+test.format, nil, true)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("oversized QR response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}
