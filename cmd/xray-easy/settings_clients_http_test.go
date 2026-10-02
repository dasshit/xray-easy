package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/xray"
)

type logLevelXrayRuntime struct {
	*fakeXrayRuntime
	levels []string
	err    error
}

func (runtime *logLevelXrayRuntime) SetLogLevel(_ context.Context, level string) error {
	runtime.levels = append(runtime.levels, level)
	return runtime.err
}

func seedTestClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	clientID := randomTestID(t)
	uuid, err := xray.NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := xray.NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	client, err := domain.NewClient(clientID, name, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	email := "device-" + clientID + "@xray-easy"
	if err := app.server.store.CreateClient(context.Background(), client, uuid, email, shortID); err != nil {
		t.Fatal(err)
	}
	client.UUID, client.Email, client.ShortID = uuid, email, shortID
	return client
}

func randomTestID(t *testing.T) string {
	t.Helper()
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSettingsReadValidationAndFingerprintApply(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/settings", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated settings status = %d", got)
	}
	response := requestJSON(t, app, http.MethodGet, "/api/settings", nil, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"vmess_public_port":9443`) || strings.Contains(response.Body.String(), "reality_private_key") || strings.Contains(response.Body.String(), "RealityPrivateKeyEnc") {
		t.Fatalf("settings response exposed secret or failed: %d %s", response.Code, response.Body.String())
	}
	if got := requestJSON(t, app, http.MethodDelete, "/api/settings", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE settings status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed settings patch status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{}, true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"changed":false`) {
		t.Fatalf("empty settings patch = %d %s", got.Code, got.Body.String())
	}
	badHost := "bad/host"
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &badHost}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid public host settings status = %d", got)
	}
	badTarget := "localhost"
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RealityTarget: &badTarget}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid target settings status = %d", got)
	}
	target, sni := "alt.example.com:443", "alt.example.com"
	app.sup.probeErr = errors.New("probe failed")
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RealityTarget: &target, RealitySNI: &sni}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("target probe failure status = %d", got)
	}
	app.sup.probeErr = nil
	rotateOnly := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RotatePrivateKey: true}, true)
	if rotateOnly.Code != http.StatusOK || !strings.Contains(rotateOnly.Body.String(), `"expected_confirmation":"ROTATE"`) {
		t.Fatalf("private-key-only confirmation = %d %s", rotateOnly.Code, rotateOnly.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: "missing", Confirmation: "ROTATE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("missing settings confirmation status = %d", got)
	}
	badFingerprint := "unsupported"
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{ClientFingerprint: &badFingerprint}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("unsupported fingerprint status = %d", got)
	}
	newFingerprint := "safari"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{ClientFingerprint: &newFingerprint}, true)
	if prepared.Code != http.StatusOK || !strings.Contains(prepared.Body.String(), `"requires_confirmation":false`) || !strings.Contains(prepared.Body.String(), `"changed":true`) {
		t.Fatalf("prepare fingerprint change = %d %s", prepared.Code, prepared.Body.String())
	}
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	applied := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true)
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"applied":true`) {
		t.Fatalf("apply fingerprint change = %d %s", applied.Code, applied.Body.String())
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.ClientFingerprint != "safari" {
		t.Fatalf("fingerprint after apply = %q, %v", settings.ClientFingerprint, err)
	}
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{ClientFingerprint: &newFingerprint}, true); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"changed":false`) {
		t.Fatalf("unchanged fingerprint response = %d %s", got.Code, got.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true).Code; got != http.StatusConflict {
		t.Fatalf("reused settings token status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("missing change id status = %d", got)
	}
}

func TestSettingsLogLevelApplyRestartsXrayWithoutRevokingProfiles(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "family-phone")
	invalid := "trace"
	if response := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{LogLevel: &invalid}, true); response.Code != http.StatusBadRequest {
		t.Fatalf("unsupported log level response = %d %s", response.Code, response.Body.String())
	}
	level := "debug"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{LogLevel: &level}, true)
	if prepared.Code != http.StatusOK || !strings.Contains(prepared.Body.String(), `"requires_confirmation":false`) || !strings.Contains(prepared.Body.String(), `"revoked_clients":0`) || !strings.Contains(prepared.Body.String(), "active connections remain running") {
		t.Fatalf("prepare log-level change = %d %s", prepared.Code, prepared.Body.String())
	}
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	applied := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true)
	if applied.Code != http.StatusOK || strings.Contains(applied.Body.String(), `"backup"`) {
		t.Fatalf("apply log-level change = %d %s", applied.Code, applied.Body.String())
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.LogLevel != "debug" {
		t.Fatalf("stored log level = %q, %v; want debug", settings.LogLevel, err)
	}
	clientAfter, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || !clientAfter.Enabled || clientAfter.Revoked {
		t.Fatalf("profile state after log-level apply = %+v, %v", clientAfter, err)
	}
	activeConfig, err := os.ReadFile(filepath.Join(app.server.configDir, "active.json"))
	if err != nil || !strings.Contains(string(activeConfig), `"loglevel": "debug"`) || !strings.Contains(string(activeConfig), client.UUID) {
		t.Fatalf("active config did not update log level while retaining profile: %v %s", err, activeConfig)
	}
	if len(app.sup.applyCalls) != 1 {
		t.Fatalf("Xray runtime apply count = %d, want one Xray apply", len(app.sup.applyCalls))
	}
	if entries, err := os.ReadDir(filepath.Join(app.server.dataDir, "backups")); (err == nil && len(entries) != 0) || (err != nil && !os.IsNotExist(err)) {
		t.Fatalf("non-destructive log-level update created backups: %d, %v", len(entries), err)
	}
}

func TestSettingsLogLevelUsesRuntimeControlPlaneWithoutApplyingFullConfig(t *testing.T) {
	app := newTestApp(t, true)
	if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte(`{"log":{"loglevel":"warning"},"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &logLevelXrayRuntime{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = runtime
	level := "debug"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{LogLevel: &level}, true)
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"runtime_restarted":false`) {
		t.Fatalf("dynamic log-level apply = %d %s", response.Code, response.Body.String())
	}
	if len(runtime.levels) != 1 || runtime.levels[0] != level || len(app.sup.applyCalls) != 0 {
		t.Fatalf("runtime log-level calls=%v full applies=%v", runtime.levels, app.sup.applyCalls)
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.LogLevel != level {
		t.Fatalf("persisted log level=%q err=%v", settings.LogLevel, err)
	}
}

func TestSettingsPreviewCanonicalizesIPv6BeforeComparing(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "2001:db8::1"
	if err := app.server.store.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	expanded := "2001:0db8:0000:0000:0000:0000:0000:0001"
	response := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &expanded}, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"changed":false`) {
		t.Fatalf("equivalent IPv6 settings preview = %d %s", response.Code, response.Body.String())
	}
}

func TestSettingsRotationBacksUpAppliesAndRevokesProfiles(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "macbook")
	newTarget, newSNI, newHost := "www.google.com:443", "www.google.com", "new-vpn.example.test"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost, RealityTarget: &newTarget, RealitySNI: &newSNI, RotatePrivateKey: true}, true)
	if prepared.Code != http.StatusOK || !strings.Contains(prepared.Body.String(), `"expected_confirmation":"REVOKE"`) || !strings.Contains(prepared.Body.String(), `"revoked_clients":1`) {
		t.Fatalf("prepare rotation = %d %s", prepared.Code, prepared.Body.String())
	}
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "wrong"}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("wrong confirmation status = %d", got)
	}
	result := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"revoked_clients":1`) || !strings.Contains(result.Body.String(), `"backup":`) {
		t.Fatalf("rotation apply = %d %s", result.Code, result.Body.String())
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.PublicHost != newHost || settings.RealityTarget != newTarget || settings.RealitySNI != newSNI {
		t.Fatalf("rotated settings = %+v, %v", settings, err)
	}
	updated, err := app.server.store.GetClient(t.Context(), client.ID)
	vlessState, vlessErr := updated.AccessState(domain.ProtocolVLESS)
	hysteriaState, hysteriaErr := updated.AccessState(domain.ProtocolHysteria2)
	if err != nil || vlessErr != nil || hysteriaErr != nil || vlessState != (domain.ClientState{Enabled: false, Revoked: true}) || hysteriaState != (domain.ClientState{Enabled: true, Revoked: false}) {
		t.Fatalf("rotation must revoke only VLESS access; got client=%+v VLESS=%+v/%v Hysteria=%+v/%v err=%v", updated, vlessState, vlessErr, hysteriaState, hysteriaErr, err)
	}
	activeConfig, err := os.ReadFile(filepath.Join(app.server.configDir, "active.json"))
	if err != nil || strings.Contains(string(activeConfig), client.UUID) || !strings.Contains(string(activeConfig), newTarget) {
		t.Fatalf("promoted Xray config should use new settings and exclude revoked client: %v %s", err, activeConfig)
	}
	if entries, err := os.ReadDir(filepath.Join(app.server.dataDir, "backups")); err != nil || len(entries) != 1 {
		t.Fatalf("automatic backup files = %d, %v", len(entries), err)
	}
	if len(app.sup.probes) < 2 || len(app.sup.validatedPath) == 0 || len(app.sup.applyCalls) != 1 {
		t.Fatalf("expected probe/validate/apply: probes=%d validate=%d apply=%d", len(app.sup.probes), len(app.sup.validatedPath), len(app.sup.applyCalls))
	}
}

func TestSettingsRotationApplyFailureKeepsDatabaseAndClientState(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "phone")
	newHost := "rotated.example.test"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	app.sup.applyErrors = []error{errors.New("Xray rejected candidate")}
	failed := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "apply_failed") {
		t.Fatalf("failed rotation response = %d %s", failed.Code, failed.Body.String())
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.PublicHost != "vpn.example.test" {
		t.Fatalf("settings changed after failed apply: %+v, %v", settings, err)
	}
	updated, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || !updated.Enabled || updated.Revoked {
		t.Fatalf("client changed after failed apply: %+v, %v", updated, err)
	}
	app.server.settingsMu.Lock()
	pending := app.server.pendingSettings[change.ChangeID]
	app.server.settingsMu.Unlock()
	if !pendingExists(app.server, change.ChangeID) || pending.Applying {
		t.Fatalf("failed change should be retryable: %+v", pending)
	}
}

func pendingExists(s *server, id string) bool {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	_, ok := s.pendingSettings[id]
	return ok
}

func TestClientCreateProfileStateTransitionsAndDiagnostics(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/clients", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated clients status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodDelete, "/api/clients", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE clients status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed create client body status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone", Fingerprint: "bad"}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("unsupported fingerprint client status = %d", got)
	}
	created := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "  iPhone  ", Fingerprint: "safari"}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create client = %d %s", created.Code, created.Body.String())
	}
	client := decodeResponse[clientResponse](t, created)
	if client.Name != "iPhone" || client.ClientFingerprint != "safari" || client.ID == "" || !client.Enabled || client.Revoked {
		t.Fatalf("created client = %+v", client)
	}
	if len(app.sup.applyCalls) != 1 || len(app.sup.validatedPath) != 1 {
		t.Fatalf("client creation did not validate/apply candidate: %+v", app.sup.applyCalls)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "invalid name"}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("invalid device name response = %d", got)
	}
	app.sup.validateErr = errors.New("candidate validation failed")
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "validation-failure"}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("candidate validation failure status = %d", got)
	}
	app.sup.validateErr = nil
	app.sup.applyErrors = []error{errors.New("candidate apply failed")}
	app.handler.addErr = errors.New("live AddUser unavailable")
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "apply-failure"}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("candidate apply failure status = %d", got)
	}
	app.handler.addErr = nil
	if got := requestJSON(t, app, http.MethodGet, "/api/clients/", nil, true).Code; got != http.StatusNotFound {
		t.Fatalf("empty client route status = %d", got)
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || profile.Header().Get("Cache-Control") != "no-store" || !strings.Contains(profile.Body.String(), "vless://") || !strings.Contains(profile.Body.String(), client.ID) {
		t.Fatalf("profile response = %d headers=%v body=%s", profile.Code, profile.Header(), profile.Body.String())
	}
	profileJSON := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile?format=json", nil, true)
	if profileJSON.Code != http.StatusOK || profileJSON.Header().Get("Content-Type") != "application/json" || !strings.Contains(profileJSON.Header().Get("Content-Disposition"), "iPhone.json") {
		t.Fatalf("JSON profile headers/status = %d %v", profileJSON.Code, profileJSON.Header())
	}
	var jsonProfile map[string]any
	if err := json.Unmarshal(profileJSON.Body.Bytes(), &jsonProfile); err != nil || jsonProfile["outbounds"] == nil {
		t.Fatalf("profile JSON invalid: %v %s", err, profileJSON.Body.String())
	}
	qr := httptest.NewRecorder()
	qrRequest := httptest.NewRequest(http.MethodGet, "/api/clients/"+client.ID+"/profile?format=qr", nil)
	qrRequest.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	newMux(app.server).ServeHTTP(qr, qrRequest)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || len(qr.Body.Bytes()) < 8 {
		t.Fatalf("QR profile = %d headers=%v len=%d", qr.Code, qr.Header(), qr.Body.Len())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/unknown/enable", nil, true).Code; got != http.StatusNotFound {
		t.Fatalf("missing client route status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/unknown", nil, true).Code; got != http.StatusNotFound {
		t.Fatalf("unknown client action status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID, nil, true).Code; got != http.StatusOK {
		t.Fatalf("client detail status = %d", got)
	}
	activePath := filepath.Join(app.server.configDir, "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(activePath, 0o700); err != nil {
		t.Fatal(err)
	}
	rollback := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
	if rollback.Code != http.StatusBadGateway {
		t.Fatalf("failed profile promotion status = %d %s", rollback.Code, rollback.Body.String())
	}
	unchanged, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || !unchanged.Enabled || unchanged.Revoked {
		t.Fatalf("client state wasn't rolled back after promotion failure: %+v %v", unchanged, err)
	}
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true).Code; got != http.StatusOK {
		t.Fatalf("disable client status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true).Code; got != http.StatusOK {
		t.Fatalf("repeated disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true).Code; got != http.StatusOK {
		t.Fatalf("enable client status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/revoke", nil, true).Code; got != http.StatusOK {
		t.Fatalf("revoke client status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true).Code; got != http.StatusConflict {
		t.Fatalf("re-enable revoked profile status = %d", got)
	}
	all := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if all.Code != http.StatusOK || !strings.Contains(all.Body.String(), `"revoked":true`) {
		t.Fatalf("client list response = %d %s", all.Code, all.Body.String())
	}
	app.sup.status.InboundTags = []string{"vless-reality", "trojan-tls"}
	status := requestJSON(t, app, http.MethodGet, "/api/status", nil, true)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"state":"running"`) || !strings.Contains(status.Body.String(), `"inbound_tags":["vless-reality","trojan-tls"]`) {
		t.Fatalf("status response = %d %s", status.Code, status.Body.String())
	}
	app.sup.statusErr = errors.New(`connection password="hidden"`)
	app.sup.status.InboundTags = nil
	status = requestJSON(t, app, http.MethodGet, "/api/status", nil, true)
	if !strings.Contains(status.Body.String(), `"state":"unavailable"`) || !strings.Contains(status.Body.String(), `"inbound_tags":[]`) || strings.Contains(status.Body.String(), "hidden") {
		t.Fatalf("runtime failure was not safely reported: %s", status.Body.String())
	}
	logs := requestJSON(t, app, http.MethodGet, "/api/logs?component=xray&limit=1", nil, true)
	if logs.Code != http.StatusOK || strings.Contains(logs.Body.String(), "hidden") {
		t.Fatalf("Xray logs response = %d %s", logs.Code, logs.Body.String())
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/logs?component=bogus", nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid log component status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/logs?limit=201", nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid log limit status = %d", got)
	}
	app.sup.logsErr = errors.New("offline")
	if got := requestJSON(t, app, http.MethodGet, "/api/logs?component=xray", nil, true).Code; got != http.StatusBadGateway {
		t.Fatalf("failed Xray logs status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/logs?component=app", nil, true).Code; got != http.StatusOK {
		t.Fatalf("app logs status = %d", got)
	}
	if level := diagnosticLevel("panic while loading"); level != "error" || diagnosticLevel("warning: disk") != "warn" || diagnosticLevel("connected") != "info" {
		t.Fatalf("diagnostic levels = panic:%s warning:%s info:%s", level, diagnosticLevel("warning: disk"), diagnosticLevel("connected"))
	}
}

func TestClientCreationRejectsIncompleteOrUndecryptableSettings(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	settings.RealityPrivateKeyEnc = ""
	if err := app.server.store.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone"}, true).Code; got != http.StatusConflict {
		t.Fatalf("incomplete settings create status = %d", got)
	}
	settings.RealityPrivateKeyEnc = "broken-envelope"
	if err := app.server.store.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone"}, true).Code; got != http.StatusInternalServerError {
		t.Fatalf("invalid encrypted key create status = %d", got)
	}
}
