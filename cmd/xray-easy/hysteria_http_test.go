package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/xray"
)

func TestHysteriaSettingsStatusAndPreviewRequireAuthenticationAndCertificate(t *testing.T) {
	app := newTestApp(t, true)
	if err := os.RemoveAll(filepath.Join(app.server.dataDir, "hysteria-tls")); err != nil {
		t.Fatal(err)
	}
	initial := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := app.server.store.InitializeHysteriaSettings(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	unauthorized := requestJSON(t, app, "GET", "/api/transports/hysteria2", nil, false)
	if unauthorized.Code != 401 {
		t.Fatalf("unauthorized Hysteria status = %d %s", unauthorized.Code, unauthorized.Body.String())
	}
	response := requestJSON(t, app, "GET", "/api/transports/hysteria2", nil, true)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"state":"needs_certificate"`) {
		t.Fatalf("Hysteria settings status = %d %s", response.Code, response.Body.String())
	}
	request := hysteriaSettingsRequest{Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	response = requestJSON(t, app, "POST", "/api/transports/hysteria2/preview", request, true)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "certificate_not_ready") {
		t.Fatalf("enable without a cert = %d %s", response.Code, response.Body.String())
	}
}

func TestHysteriaSettingsPreviewAndApplyPersistsDisabledNodeSettings(t *testing.T) {
	app := newTestApp(t, true)
	initial := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := app.server.store.InitializeHysteriaSettings(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	request := hysteriaSettingsRequest{
		Host: "udp.example.test", TLSMode: domain.HysteriaTLSCustom, TLSServerName: "udp.example.test",
		UDPIdleTimeout: 120, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	preview := requestJSON(t, app, "POST", "/api/transports/hysteria2/preview", request, true)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"requires_confirmation":true`) {
		t.Fatalf("Hysteria preview = %d %s", preview.Code, preview.Body.String())
	}
	var result struct {
		ChangeID             string `json:"change_id"`
		ExpectedConfirmation string `json:"expected_confirmation"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ChangeID == "" || result.ExpectedConfirmation != "APPLY" {
		t.Fatalf("preview confirmation = %+v", result)
	}
	badConfirmation := requestJSON(t, app, "POST", "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: result.ChangeID}, true)
	if badConfirmation.Code != 400 {
		t.Fatalf("apply without confirmation = %d %s", badConfirmation.Code, badConfirmation.Body.String())
	}
	applied := requestJSON(t, app, "POST", "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: result.ChangeID, Confirmation: "APPLY"}, true)
	if applied.Code != 200 || !strings.Contains(applied.Body.String(), `"applied":true`) {
		t.Fatalf("Hysteria apply = %d %s", applied.Code, applied.Body.String())
	}
	got, err := app.server.store.GetHysteriaSettings(context.Background())
	if err != nil || got.Enabled || got.Host != "udp.example.test" || got.UDPIdleTimeout != 120 {
		t.Fatalf("persisted Hysteria settings = %+v, %v", got, err)
	}
	if len(app.sup.applyCalls) != 0 {
		t.Fatalf("disabled transport settings restarted Xray: %v", app.sup.applyCalls)
	}
}

func TestTLSSettingsApplyUpdatesExistingVMessInboundWhenHysteriaIsOff(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	createRuntimeVMessClient(t, app, "macbook")
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	app.server.supervisor = replacer

	invalid := hysteriaSettingsRequest{
		TLSMode: domain.HysteriaTLSCustom, TLSServerName: "missing.example.test",
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	response := requestJSON(t, app, "POST", "/api/transports/hysteria2/preview", invalid, true)
	if response.Code != 409 || !strings.Contains(response.Body.String(), "certificate_not_ready") {
		t.Fatalf("mismatched certificate accepted for existing VMess inbound: %d %s", response.Code, response.Body.String())
	}

	request := invalid
	request.TLSServerName = "vpn.example.test"
	preview := requestJSON(t, app, "POST", "/api/transports/hysteria2/preview", request, true)
	if preview.Code != 200 || strings.Contains(preview.Body.String(), "VMess TLS certificate or server name will be updated") {
		t.Fatalf("VMess SNI-only change preview = %d %s", preview.Code, preview.Body.String())
	}
	var result struct {
		ChangeID string `json:"change_id"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	response = requestJSON(t, app, "POST", "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: result.ChangeID, Confirmation: "APPLY"}, true)
	if response.Code != 200 || len(replacer.calls) != 0 {
		t.Fatalf("SNI-only update replaced a VMess inbound: %d calls=%v body=%s", response.Code, replacer.calls, response.Body.String())
	}

	request.CertificateID = "0123456789abcdef0123456789abcdef"
	writeTestHysteriaCertificate(t, filepath.Join(app.server.dataDir, "hysteria-tls", request.CertificateID))
	preview = requestJSON(t, app, "POST", "/api/transports/hysteria2/preview", request, true)
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "VMess TLS certificate or server name will be updated") {
		t.Fatalf("VMess TLS change preview = %d %s", preview.Code, preview.Body.String())
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	response = requestJSON(t, app, "POST", "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: result.ChangeID, Confirmation: "APPLY"}, true)
	if response.Code != 200 {
		t.Fatalf("VMess TLS update = %d %s", response.Code, response.Body.String())
	}
	if len(replacer.calls) != 1 || replacer.calls[0][2] != xray.VMessInboundTag {
		t.Fatalf("certificate change replaced wrong inbounds: %v", replacer.calls)
	}
	if hasInboundTag(filepath.Join(app.server.configDir, "active.json"), xray.HysteriaInboundTag) {
		t.Fatal("updating VMess TLS unexpectedly enabled the Hysteria 2 inbound")
	}
}

func TestHysteriaCertificateGenerationRejectsInvalidAddressesAndMethods(t *testing.T) {
	app := newTestApp(t, true)
	wrongMethod := requestJSON(t, app, "GET", "/api/transports/hysteria2/certificate/mkcert", nil, true)
	if wrongMethod.Code != 405 {
		t.Fatalf("GET mkcert status = %d", wrongMethod.Code)
	}
	invalid := requestJSON(t, app, "POST", "/api/transports/hysteria2/certificate/mkcert", map[string]string{"ipv4": "2001:db8::1"}, true)
	if invalid.Code != 400 || !strings.Contains(invalid.Body.String(), "public IPv4") {
		t.Fatalf("invalid mkcert address = %d %s", invalid.Code, invalid.Body.String())
	}
}
