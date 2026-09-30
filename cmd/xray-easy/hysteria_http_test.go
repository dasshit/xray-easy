package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/xray"
)

func TestHysteriaCertificateUploadRejectsInvalidRequests(t *testing.T) {
	app := newTestApp(t, true)
	if response := requestJSON(t, app, http.MethodGet, "/api/transports/hysteria2/certificate", nil, true); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status = %d", response.Code)
	}
	if response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/certificate", nil, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous upload status = %d", response.Code)
	}
	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{name: "malformed multipart", body: "not multipart", want: http.StatusBadRequest},
		{name: "missing files", body: "--boundary--\r\n", want: http.StatusBadRequest},
		{name: "invalid PEM", body: certificateUploadBody(t, "not pem", "not a key", ""), want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/transports/hysteria2/certificate", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
			response := httptest.NewRecorder()
			newMux(app.server).ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("upload status = %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestHysteriaCertificateUploadRejectsOversizeAndMissingInitialSetup(t *testing.T) {
	t.Run("request exceeds upload limit", func(t *testing.T) {
		app := newTestApp(t, true)
		body := bytes.Repeat([]byte("x"), hysteriaCertificateMaxBytes+1)
		request := httptest.NewRequest(http.MethodPost, "/api/transports/hysteria2/certificate", bytes.NewReader(body))
		request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
		request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
		response := httptest.NewRecorder()
		newMux(app.server).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "2 MiB limit") {
			t.Fatalf("oversize upload = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("node setup is required when server name is omitted", func(t *testing.T) {
		app := newTestApp(t, true)
		body := certificateUploadBody(t, "not parsed before node settings", "key", "")
		execSQLiteTestMutation(t, app, "drop Xray settings", `DROP TABLE settings`)
		request := httptest.NewRequest(http.MethodPost, "/api/transports/hysteria2/certificate", strings.NewReader(body))
		request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
		request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
		response := httptest.NewRecorder()
		newMux(app.server).ServeHTTP(response, request)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "complete initial Xray setup") {
			t.Fatalf("upload before initial setup = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestReadMultipartFileValidatesExactlyOneBoundedFile(t *testing.T) {
	form := &multipart.Form{File: map[string][]*multipart.FileHeader{}}
	if _, err := readMultipartFile(form, "certificate"); err == nil {
		t.Fatal("missing multipart file was accepted")
	}
	form.File["certificate"] = []*multipart.FileHeader{{Size: hysteriaCertificateMaxBytes + 1}}
	if _, err := readMultipartFile(form, "certificate"); err == nil {
		t.Fatal("oversized multipart file was accepted")
	}
	form.File["certificate"] = []*multipart.FileHeader{{}, {}}
	if _, err := readMultipartFile(form, "certificate"); err == nil {
		t.Fatal("multiple multipart files were accepted")
	}
	form.File["certificate"] = []*multipart.FileHeader{{}}
	if _, err := readMultipartFile(form, "certificate"); err == nil {
		t.Fatal("multipart file without an uploaded body was accepted")
	}
}

func certificateUploadBody(t *testing.T, certificate, privateKey, serverName string) string {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.SetBoundary("boundary")
	for _, file := range []struct{ field, name, contents string }{
		{"fullchain", "fullchain.pem", certificate}, {"private_key", "privkey.pem", privateKey},
	} {
		part, err := writer.CreateFormFile(file.field, file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(file.contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.WriteField("server_name", serverName); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.String()
}

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

func TestHysteriaSettingsStatusReportsTransportAndRuntimeMismatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		settings   domain.HysteriaSettings
		activeJSON string
		wantState  string
		wantError  string
	}{
		{name: "ready disabled", settings: domain.HysteriaSettings{TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, wantState: "ready"},
		{name: "disabled but active", settings: domain.HysteriaSettings{TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, activeJSON: `{"inbounds":[{"tag":"hysteria2"}]}`, wantState: "error", wantError: "while the transport is disabled"},
		{name: "enabled but absent", settings: domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, wantState: "error", wantError: "inbound is absent"},
		{name: "enabled and active", settings: domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, activeJSON: `{"inbounds":[{"tag":"hysteria2"}]}`, wantState: "on"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			if err := app.server.store.InitializeHysteriaSettings(context.Background(), test.settings); err != nil {
				t.Fatal(err)
			}
			if test.activeJSON != "" {
				if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte(test.activeJSON), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			response := requestJSON(t, app, http.MethodGet, "/api/transports/hysteria2", nil, true)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"`+test.wantState+`"`) || !strings.Contains(response.Body.String(), test.wantError) {
				t.Fatalf("Hysteria runtime status = %d %s", response.Code, response.Body.String())
			}
		})
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

func TestHysteriaSettingsPreviewAndApplyEnablesInboundWithRuntimeReplacement(t *testing.T) {
	app := newTestApp(t, true)
	certificateID := "0123456789abcdef0123456789abcdef"
	writeTestHysteriaCertificate(t, filepath.Join(app.server.dataDir, "hysteria-tls", certificateID))
	initial := domain.HysteriaSettings{
		TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", CertificateID: certificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	if err := app.server.store.InitializeHysteriaSettings(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	app.server.supervisor = replacer
	request := hysteriaSettingsRequest{
		Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "vpn.example.test", CertificateID: certificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	preview := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/preview", request, true)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "Hysteria 2 inbound will be changed") {
		t.Fatalf("enable preview = %d %s", preview.Code, preview.Body.String())
	}
	var pending struct {
		ChangeID string `json:"change_id"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &pending); err != nil || pending.ChangeID == "" {
		t.Fatalf("preview change ID = %+v, %v", pending, err)
	}
	response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: pending.ChangeID, Confirmation: "APPLY"}, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"applied":true`) {
		t.Fatalf("enable apply = %d %s", response.Code, response.Body.String())
	}
	if len(replacer.calls) != 1 || replacer.calls[0][2] != xray.HysteriaInboundTag {
		t.Fatalf("runtime replacement calls = %v", replacer.calls)
	}
	updated, err := app.server.store.GetHysteriaSettings(context.Background())
	if err != nil || !updated.Enabled || updated.CertificateID != certificateID {
		t.Fatalf("persisted enabled Hysteria settings = %+v, %v", updated, err)
	}
}

func TestHysteriaApplyRequiresInboundReplacementWhenTopologyChanges(t *testing.T) {
	app := newTestApp(t, true)
	changeID := prepareEnabledHysteriaChange(t, app)
	// The basic supervisor interface can validate a full config, but cannot
	// atomically switch an optional inbound while it is live.
	app.server.supervisor = app.sup
	response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: changeID, Confirmation: "APPLY"}, true)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "inbound replacement is unavailable") {
		t.Fatalf("apply without inbound replacement = %d %s", response.Code, response.Body.String())
	}
	settings, err := app.server.store.GetHysteriaSettings(t.Context())
	if err != nil || settings.Enabled {
		t.Fatalf("failed runtime replacement persisted Hysteria settings: %+v, %v", settings, err)
	}
}

func TestHysteriaApplyRollsBackWhenCandidateConfigCannotBePromoted(t *testing.T) {
	app := newTestApp(t, true)
	activePath := filepath.Join(app.server.configDir, "active.json")
	if err := os.WriteFile(activePath, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var mutateErr error
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	replacer.hook = func() {
		if err := os.Remove(activePath); err != nil {
			mutateErr = err
			return
		}
		mutateErr = os.Mkdir(activePath, 0o700)
	}
	app.server.supervisor = replacer
	changeID := prepareEnabledHysteriaChange(t, app)
	response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: changeID, Confirmation: "APPLY"}, true)
	if mutateErr != nil {
		t.Fatalf("inject active config promotion failure: %v", mutateErr)
	}
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not promote Xray configuration") {
		t.Fatalf("apply with blocked active config path = %d %s", response.Code, response.Body.String())
	}
	if len(replacer.calls) != 2 || replacer.calls[1][3] != replacer.calls[0][3]+"-rollback" {
		t.Fatalf("runtime inbound was not rolled back after failed promotion: %+v", replacer.calls)
	}
	settings, err := app.server.store.GetHysteriaSettings(t.Context())
	if err != nil || settings.Enabled {
		t.Fatalf("failed config promotion persisted Hysteria settings: %+v, %v", settings, err)
	}
}

func TestHysteriaApplyFailurePathsRemainExplicitAndRetryable(t *testing.T) {
	for _, test := range []struct {
		name     string
		prepare  func(t *testing.T, app testApp, replacer *recordingInboundReplacer)
		wantCode int
		wantBody string
	}{
		{name: "backup", prepare: func(t *testing.T, app testApp, _ *recordingInboundReplacer) {
			if err := os.WriteFile(filepath.Join(app.server.dataDir, "backups"), []byte("blocked"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantCode: http.StatusInternalServerError, wantBody: "backup_failed"},
		{name: "private key decryption", prepare: func(t *testing.T, app testApp, _ *recordingInboundReplacer) {
			settings, err := app.server.store.GetSettings(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			settings.RealityPrivateKeyEnc = "broken"
			if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
				t.Fatal(err)
			}
		}, wantCode: http.StatusInternalServerError, wantBody: "could not decrypt REALITY private key"},
		{name: "profiles query", prepare: func(t *testing.T, app testApp, _ *recordingInboundReplacer) {
			execSQLiteTestMutation(t, app, "drop profiles", `DROP TABLE clients`)
		}, wantCode: http.StatusInternalServerError, wantBody: "could not list profiles"},
		{name: "reserved short IDs query", prepare: func(t *testing.T, app testApp, _ *recordingInboundReplacer) {
			execSQLiteTestMutation(t, app, "drop short IDs", `DROP TABLE reality_short_ids`)
		}, wantCode: http.StatusInternalServerError, wantBody: "could not read REALITY short IDs"},
		{name: "candidate validation", prepare: func(_ *testing.T, app testApp, _ *recordingInboundReplacer) {
			app.sup.validateErr = errors.New("injected candidate error")
		}, wantCode: http.StatusBadGateway, wantBody: "Xray rejected"},
		{name: "inbound replacement", prepare: func(_ *testing.T, _ testApp, replacer *recordingInboundReplacer) {
			replacer.err = errors.New("injected replacement error")
		}, wantCode: http.StatusBadGateway, wantBody: "previous state was restored"},
		{name: "settings persistence", prepare: func(t *testing.T, app testApp, _ *recordingInboundReplacer) {
			execSQLiteTestMutation(t, app, "reject settings", `CREATE TRIGGER reject_hysteria_settings BEFORE UPDATE ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'injected Hysteria settings failure'); END`)
		}, wantCode: http.StatusInternalServerError, wantBody: "could not persist Hysteria 2 settings"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
			app.server.supervisor = replacer
			changeID := prepareEnabledHysteriaChange(t, app)
			test.prepare(t, app, replacer)
			response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: changeID, Confirmation: "APPLY"}, true)
			if response.Code != test.wantCode || !strings.Contains(response.Body.String(), test.wantBody) {
				t.Fatalf("apply failure = %d %s, want %d containing %q", response.Code, response.Body.String(), test.wantCode, test.wantBody)
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

func TestHysteriaApplyRejectsExpiredForeignAndStaleConfirmations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, app testApp, changeID string)
		want   string
	}{
		{name: "expired", mutate: func(t *testing.T, app testApp, id string) {
			app.server.hysteriaMu.Lock()
			pending := app.server.pendingHysteria[id]
			pending.ExpiresAt = time.Now().UTC().Add(-time.Second)
			app.server.pendingHysteria[id] = pending
			app.server.hysteriaMu.Unlock()
		}, want: "confirmation_expired"},
		{name: "another administrator", mutate: func(t *testing.T, app testApp, id string) {
			app.server.hysteriaMu.Lock()
			pending := app.server.pendingHysteria[id]
			pending.AdminID = "different-admin"
			app.server.pendingHysteria[id] = pending
			app.server.hysteriaMu.Unlock()
		}, want: "confirmation_expired"},
		{name: "already applying", mutate: func(t *testing.T, app testApp, id string) {
			app.server.hysteriaMu.Lock()
			pending := app.server.pendingHysteria[id]
			pending.Applying = true
			app.server.pendingHysteria[id] = pending
			app.server.hysteriaMu.Unlock()
		}, want: "confirmation_expired"},
		{name: "settings changed after preview", mutate: func(t *testing.T, app testApp, _ string) {
			current, err := app.server.store.GetHysteriaSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			current.Host = "changed.example.test"
			if err := app.server.store.UpdateHysteriaSettings(t.Context(), current); err != nil {
				t.Fatal(err)
			}
		}, want: "settings changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			changeID := prepareEnabledHysteriaChange(t, app)
			test.mutate(t, app, changeID)
			response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/apply", hysteriaApplyRequest{ChangeID: changeID, Confirmation: "APPLY"}, true)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("apply stale confirmation = %d %s", response.Code, response.Body.String())
			}
		})
	}

	app := newTestApp(t, true)
	changeID := prepareEnabledHysteriaChange(t, app)
	lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/transports/hysteria2/apply", strings.NewReader(`{"change_id":"`+changeID+`","confirmation":"APPLY"}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	response := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "apply_pending") {
		t.Fatalf("busy Hysteria apply = %d %s", response.Code, response.Body.String())
	}
}

func prepareEnabledHysteriaChange(t *testing.T, app testApp) string {
	t.Helper()
	certificateID := "0123456789abcdef0123456789abcdef"
	writeTestHysteriaCertificate(t, filepath.Join(app.server.dataDir, "hysteria-tls", certificateID))
	settings := domain.HysteriaSettings{
		TLSMode: domain.HysteriaTLSCustom, TLSServerName: "vpn.example.test", CertificateID: certificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	if err := app.server.store.InitializeHysteriaSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	request := hysteriaSettingsRequest{
		Enabled: true, Host: "vpn.example.test", TLSMode: domain.HysteriaTLSCustom,
		TLSServerName: "vpn.example.test", CertificateID: certificateID,
		UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}
	preview := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/preview", request, true)
	if preview.Code != http.StatusOK {
		t.Fatalf("prepare Hysteria apply = %d %s", preview.Code, preview.Body.String())
	}
	var pending struct {
		ChangeID string `json:"change_id"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &pending); err != nil || pending.ChangeID == "" {
		t.Fatalf("Hysteria preview ID = %+v, %v", pending, err)
	}
	return pending.ChangeID
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

func TestHysteriaCertificateGenerateUsesMkcertAndPersistsVersion(t *testing.T) {
	app := newTestApp(t, true)
	root := t.TempDir()
	materialDir := filepath.Join(root, "material")
	writeTestMkcertMaterial(t, materialDir, "8.8.8.8")
	binDir := filepath.Join(root, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mkcert := "#!/bin/sh\nset -eu\ncp \"$XRAY_EASY_TEST_CERT\" \"$2\"\ncp \"$XRAY_EASY_TEST_KEY\" \"$4\"\ncp \"$XRAY_EASY_TEST_CA\" \"$CAROOT/rootCA.pem\"\n"
	mkcertPath := filepath.Join(binDir, "mkcert")
	if err := os.WriteFile(mkcertPath, []byte(mkcert), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_EASY_TEST_CERT", filepath.Join(materialDir, "leaf.pem"))
	t.Setenv("XRAY_EASY_TEST_KEY", filepath.Join(materialDir, "key.pem"))
	t.Setenv("XRAY_EASY_TEST_CA", filepath.Join(materialDir, "ca.pem"))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/certificate/mkcert", map[string]string{"ipv4": "8.8.8.8"}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("mkcert generation = %d %s", response.Code, response.Body.String())
	}
	generated := decodeResponse[struct {
		CertificateID string `json:"certificate_id"`
		Certificate   struct {
			Fingerprint string   `json:"fingerprint"`
			IPAddresses []string `json:"ip_addresses"`
		} `json:"certificate"`
	}](t, response)
	if len(generated.CertificateID) != 32 || generated.Certificate.Fingerprint == "" || len(generated.Certificate.IPAddresses) != 1 || generated.Certificate.IPAddresses[0] != "8.8.8.8" {
		t.Fatalf("generated certificate metadata = %+v", generated)
	}
	for name, wantMode := range map[string]os.FileMode{"fullchain.pem": 0o444, "privkey.pem": 0o400} {
		path := filepath.Join(app.server.hysteriaTLSDir(), generated.CertificateID, name)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("generated %s mode = %v, %v", name, info, err)
		}
	}
}

func TestHysteriaSettingsRouteHandlesMethodBusyAndStorageFailures(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		app := newTestApp(t, true)
		response := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2", nil, true)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("settings route method status = %d", response.Code)
		}
	})
	t.Run("maintenance is busy", func(t *testing.T) {
		app := newTestApp(t, true)
		lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		request := httptest.NewRequest(http.MethodGet, "/api/transports/hysteria2", nil).WithContext(ctx)
		request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
		response := httptest.NewRecorder()
		newMux(app.server).ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "storage is busy") {
			t.Fatalf("busy settings route = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("settings table is unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop Hysteria settings", `DROP TABLE hysteria_settings`)
		response := requestJSON(t, app, http.MethodGet, "/api/transports/hysteria2", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not read Hysteria 2 settings") {
			t.Fatalf("settings read error = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestHysteriaPreviewRejectsInvalidRequestsAndReturnsUnchangedState(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		prepare   func(t *testing.T, app testApp)
		body      any
		bodyBytes string
		wantCode  int
		wantText  string
	}{
		{name: "method", method: http.MethodGet, wantCode: http.StatusMethodNotAllowed},
		{name: "malformed JSON", bodyBytes: "{", wantCode: http.StatusBadRequest, wantText: "validation_error"},
		{name: "invalid settings", body: hysteriaSettingsRequest{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 1, MasqueradeType: domain.HysteriaMasqueradeOff}, wantCode: http.StatusBadRequest, wantText: "validation_error"},
		{name: "invalid host", body: hysteriaSettingsRequest{Host: "bad host!", TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, wantCode: http.StatusBadRequest, wantText: "Hysteria 2 host must be a DNS name or public IP"},
		{name: "incomplete initial settings", prepare: func(t *testing.T, app testApp) {
			execSQLiteTestMutation(t, app, "drop Xray settings", `DROP TABLE settings`)
		}, body: hysteriaSettingsRequest{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, wantCode: http.StatusConflict, wantText: "settings_incomplete"},
		{name: "profile query failure", prepare: func(t *testing.T, app testApp) {
			execSQLiteTestMutation(t, app, "drop profiles", `DROP TABLE clients`)
		}, body: hysteriaSettingsRequest{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}, wantCode: http.StatusInternalServerError, wantText: "could not list profiles"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			if test.prepare != nil {
				test.prepare(t, app)
			}
			var response *httptest.ResponseRecorder
			if test.bodyBytes != "" {
				request := httptest.NewRequest(method, "/api/transports/hysteria2/preview", strings.NewReader(test.bodyBytes))
				request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
				response = httptest.NewRecorder()
				newMux(app.server).ServeHTTP(response, request)
			} else {
				response = requestJSON(t, app, method, "/api/transports/hysteria2/preview", test.body, true)
			}
			if response.Code != test.wantCode || (test.wantText != "" && !strings.Contains(response.Body.String(), test.wantText)) {
				t.Fatalf("preview response = %d %s; want %d containing %q", response.Code, response.Body.String(), test.wantCode, test.wantText)
			}
		})
	}

	app := newTestApp(t, true)
	initial := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := app.server.store.InitializeHysteriaSettings(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	unchanged := requestJSON(t, app, http.MethodPost, "/api/transports/hysteria2/preview", hysteriaSettingsRequest{
		TLSMode: domain.HysteriaTLSCustom, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
	}, true)
	if unchanged.Code != http.StatusOK || !strings.Contains(unchanged.Body.String(), `"changed":false`) {
		t.Fatalf("unchanged preview = %d %s", unchanged.Code, unchanged.Body.String())
	}
}
