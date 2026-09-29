package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestHysteriaSettingsStatusAndPreviewRequireAuthenticationAndCertificate(t *testing.T) {
	app := newTestApp(t, true)
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
