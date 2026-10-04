package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/xray"
)

func TestHysteriaApplyRejectsMethodAuthenticationAndMalformedConfirmation(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/transports/hysteria2/apply", hysteriaApplyRequest{}, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET apply status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: "missing"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated apply status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed apply status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("missing change ID status = %d", got)
	}
}

func TestHysteriaApplySettingsLookupAndOperationPersistenceFailures(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, app testApp)
		want   string
	}{
		{
			name: "node settings lookup",
			mutate: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "drop node settings", `DROP TABLE settings`)
			},
			want: "settings_incomplete",
		},
		{
			name: "record apply operation",
			mutate: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "reject applying operation", `CREATE TRIGGER reject_applying_operation BEFORE UPDATE ON apply_operations WHEN NEW.state = 'applying' BEGIN SELECT RAISE(ABORT, 'injected apply operation failure'); END`)
			},
			want: "could not record apply operation",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			changeID := prepareEnabledHysteriaChange(t, app)
			test.mutate(t, app)
			response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: changeID, Confirmation: "APPLY"}, true)
			if response.Code < http.StatusConflict || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("apply failure = %d %s; want %q", response.Code, response.Body.String(), test.want)
			}
			app.server.hysteriaMu.Lock()
			pending, exists := app.server.pendingHysteria[changeID]
			app.server.hysteriaMu.Unlock()
			if !exists || pending.Applying {
				t.Fatalf("failed apply is not retryable: exists=%t pending=%+v", exists, pending)
			}
		})
	}
}

func TestHysteriaPreviewReplacesPreviousChangeForSameAdministrator(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	firstID := prepareEnabledHysteriaChange(t, app)
	second := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/preview", hysteriaSettingsRequest{
		Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "vpn.example.test", CertificateID: "0123456789abcdef0123456789abcdef",
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}, true)
	if second.Code != http.StatusOK {
		t.Fatalf("second Hysteria preview = %d %s", second.Code, second.Body.String())
	}
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, second)
	app.server.hysteriaMu.Lock()
	defer app.server.hysteriaMu.Unlock()
	if len(app.server.pendingHysteria) != 1 {
		t.Fatalf("pending Hysteria changes = %+v", app.server.pendingHysteria)
	}
	if _, exists := app.server.pendingHysteria[firstID]; exists {
		t.Fatal("previous pending Hysteria change was retained")
	}
	if _, exists := app.server.pendingHysteria[change.ChangeID]; !exists {
		t.Fatalf("new Hysteria change %q was not retained", change.ChangeID)
	}
}

func TestHysteriaStatusReportsNodeSettingsReadFailure(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	execSQLiteTestMutation(t, app, "drop node settings", `DROP TABLE settings`)
	if _, err := app.server.hysteriaSettingsStatus(t.Context()); err == nil {
		t.Fatal("Hysteria status succeeded without node settings")
	}
}

func TestHysteriaApplyRollsBackEarlierInboundWhenLaterReplacementFails(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	baseCertificateID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	candidateCertificateID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	writeTestHysteriaCertificate(t, filepath.Join(app.server.dataDir, "hysteria-tls", baseCertificateID))
	writeTestHysteriaCertificate(t, filepath.Join(app.server.dataDir, "hysteria-tls", candidateCertificateID))
	base := domain.HysteriaSettings{
		Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "vpn.example.test", CertificateID: baseCertificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	if err := app.server.store.InitializeHysteriaSettings(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	createRuntimeVMessClient(t, app, "vmess-device")
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup, errs: []error{nil, errors.New("VMess replacement failed"), nil}}
	app.server.xrayRuntime = replacer
	preview := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/preview", hysteriaSettingsRequest{
		Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "vpn.example.test", CertificateID: candidateCertificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}, true)
	if preview.Code != http.StatusOK {
		t.Fatalf("prepare multi-inbound change = %d %s", preview.Code, preview.Body.String())
	}
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, preview)
	response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: change.ChangeID, Confirmation: "APPLY"}, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "previous state was restored") {
		t.Fatalf("second inbound replacement failure = %d %s", response.Code, response.Body.String())
	}
	if len(replacer.calls) != 3 || replacer.calls[0][2] != xray.HysteriaInboundTag || replacer.calls[1][2] != xray.VMessInboundTag || replacer.calls[2][2] != xray.HysteriaInboundTag || !strings.HasSuffix(replacer.calls[2][3], "-rollback") {
		t.Fatalf("runtime replacement/rollback order = %+v", replacer.calls)
	}
}
