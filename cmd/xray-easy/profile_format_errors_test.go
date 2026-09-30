package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestProfileRouteReportsUnavailableProtocolFormats(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	hysteria := createRuntimeHysteriaClient(t, app, "hysteria-only")
	for _, format := range []struct{ name, text string }{
		{"json", "JSON profile is unavailable"},
		{"qr", "VLESS is not available"},
		{"vmess-qr", "VMess is not available"},
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
