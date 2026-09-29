package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

type recordingInboundReplacer struct {
	*fakeSupervisor
	calls [][4]string
	err   error
	hook  func()
}

func (r *recordingInboundReplacer) ReplaceInbound(_ context.Context, candidate, previous, tag, operationID string) error {
	r.calls = append(r.calls, [4]string{candidate, previous, tag, operationID})
	if r.hook != nil {
		r.hook()
	}
	return r.err
}

type recordingHysteriaHandler struct {
	*fakeXrayHandler
	users     []string
	added     []string
	removed   []string
	listErr   error
	addErr    error
	removeErr error
	afterAdd  func()
}

func (h *recordingHysteriaHandler) AddHysteriaUser(_ context.Context, email, _ string) error {
	h.added = append(h.added, email)
	if h.addErr != nil {
		return h.addErr
	}
	h.users = append(h.users, email)
	if h.afterAdd != nil {
		h.afterAdd()
	}
	return nil
}

func (h *recordingHysteriaHandler) RemoveHysteriaUser(_ context.Context, email string) error {
	h.removed = append(h.removed, email)
	if h.removeErr != nil {
		return h.removeErr
	}
	for i, value := range h.users {
		if value == email {
			h.users = append(h.users[:i], h.users[i+1:]...)
			break
		}
	}
	return nil
}

func (h *recordingHysteriaHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if tag != "hysteria2" {
		return nil, fmt.Errorf("unexpected inbound tag %q", tag)
	}
	return append([]string(nil), h.users...), h.listErr
}

func createRuntimeTestClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createRuntimeHysteriaClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create Hysteria 2 profile %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestVLESSShortIDReserveAddsUsersThenReplacesInbound(t *testing.T) {
	app := newTestApp(t, true)
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	app.server.supervisor = replacer
	for i := 1; i <= 6; i++ {
		createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
	}
	if len(app.sup.applyCalls) != 1 || len(app.handler.addCall) != 4 || len(replacer.calls) != 1 {
		t.Fatalf("runtime operations: apply=%d AddUser=%d ReplaceInbound=%d", len(app.sup.applyCalls), len(app.handler.addCall), len(replacer.calls))
	}
	if replacer.calls[0][2] != "vless-reality" {
		t.Fatalf("wrong inbound replaced: %v", replacer.calls[0])
	}
	active := filepath.Join(app.server.configDir, "active.json")
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []json.RawMessage `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				RealitySettings struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Settings.Clients) != 6 || len(config.Inbounds[0].StreamSettings.RealitySettings.ShortIDs) != 11 {
		t.Fatalf("persisted config did not include six clients and five free IDs: %s", content)
	}
	if len(app.server.diagnosticBuffer.Snapshot(0)) == 0 {
		t.Fatal("short-ID exhaustion was not reported in diagnostics")
	}

	replacer.err = errors.New("replace failed")
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "failed-replace"}, true)
	if failed.Code != http.StatusCreated {
		// The pool was refilled by the previous replacement, so this attempt must
		// use the hot AddUser path rather than invoking the failing replacer.
		t.Fatalf("refilled reserve was not usable: %d %s", failed.Code, failed.Body.String())
	}
	for i := 8; i <= 11; i++ {
		createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
	}
	failed = requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "actual-replace-failure"}, true)
	if failed.Code != http.StatusBadGateway || len(replacer.calls) != 2 {
		t.Fatalf("failed inbound replacement = %d calls=%v body=%s", failed.Code, replacer.calls, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 11 {
		t.Fatalf("failed replacement persisted a client: %d, %v", len(clients), err)
	}
}

func TestHysteriaProfileDeliveryAndLiveUserRollback(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	first := createRuntimeHysteriaClient(t, app, "phone-1")
	if len(app.sup.applyCalls) != 1 {
		t.Fatalf("first Hysteria inbound was not applied: %v", app.sup.applyCalls)
	}
	second := createRuntimeHysteriaClient(t, app, "phone-2")
	if len(handler.added) != 1 || handler.added[0] != second.Email || len(app.handler.addCall) != 0 {
		t.Fatalf("Hysteria profile did not use only its live user API: Hysteria=%v VLESS=%v", handler.added, app.handler.addCall)
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+first.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"protocol":"hysteria2"`) || !strings.Contains(profile.Body.String(), `"hysteria_uri":"hysteria2://`) || strings.Contains(profile.Body.String(), `"uri":`) {
		t.Fatalf("Hysteria profile response = %d %s", profile.Code, profile.Body.String())
	}
	var delivered struct {
		HysteriaURI string `json:"hysteria_uri"`
	}
	if err := json.Unmarshal(profile.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(delivered.HysteriaURI)
	if err != nil || uri.Query().Get("sni") != "cert.example.test" || uri.Query().Has("insecure") || uri.User.Username() != first.HysteriaAuth {
		t.Fatalf("custom certificate profile must verify its DNS name: %q, %v", delivered.HysteriaURI, err)
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/"+first.ID+"/profile?format=hysteria-qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() < 8 {
		t.Fatalf("Hysteria QR response = %d %v", qr.Code, qr.Header())
	}
	handler.addErr = errors.New("Hysteria AddUser failed")
	app.sup.applyErrors = []error{errors.New("validated fallback failed")}
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "phone-3"}, true)
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("failed Hysteria AddUser status = %d %s", failed.Code, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 2 {
		t.Fatalf("failed profile remained in database: %v, %v", clients, err)
	}
	if len(app.handler.users) != 0 || len(handler.users) != 1 || handler.users[0] != second.Email {
		t.Fatalf("failed Hysteria creation changed runtime users: Hysteria=%v VLESS=%v", handler.users, app.handler.users)
	}
}

func TestProtocolSpecificProfilesKeepAccessAndCredentialsIsolated(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler

	vless := createRuntimeTestClient(t, app, "phone")
	hysteria := createRuntimeHysteriaClient(t, app, "phone")
	if vless.Protocol != domain.ProtocolVLESS || vless.UUID == "" || vless.ShortID == "" || vless.HysteriaAuth != "" {
		t.Fatalf("VLESS profile credentials = %+v", vless)
	}
	if hysteria.Protocol != domain.ProtocolHysteria2 || hysteria.UUID != "" || hysteria.ShortID != "" || hysteria.HysteriaAuth == "" {
		t.Fatalf("Hysteria profile credentials = %+v", hysteria)
	}
	if len(app.handler.addCall) != 0 || len(handler.added) != 1 || handler.added[0] != hysteria.Email {
		t.Fatalf("profile creation mutated the wrong inbound: VLESS=%v Hysteria=%v", app.handler.addCall, handler.added)
	}

	list := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), vless.UUID) || strings.Contains(list.Body.String(), hysteria.HysteriaAuth) {
		t.Fatalf("client list exposed protocol credentials: %d %s", list.Code, list.Body.String())
	}
	var listed []clientResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].VLESS == nil || listed[0].Hysteria2 != nil || listed[1].VLESS != nil || listed[1].Hysteria2 == nil {
		t.Fatalf("typed access state in client list = %+v", listed)
	}

	handler.users = []string{hysteria.Email}
	disabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/disable", nil, true)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable Hysteria profile = %d %s", disabled.Code, disabled.Body.String())
	}
	state := decodeResponse[clientResponse](t, disabled)
	if state.Hysteria2 == nil || state.Hysteria2.Enabled || state.VLESS != nil || len(handler.removed) != 1 || len(app.handler.addCall) != 0 {
		t.Fatalf("disable changed the wrong protocol access: state=%+v Hysteria removals=%v VLESS additions=%v", state, handler.removed, app.handler.addCall)
	}

	enabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/enable", nil, true)
	if enabled.Code != http.StatusOK || len(handler.added) != 2 || len(app.handler.addCall) != 0 {
		t.Fatalf("enable Hysteria profile = %d Hysteria additions=%v VLESS additions=%v body=%s", enabled.Code, handler.added, app.handler.addCall, enabled.Body.String())
	}
	revoked := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/revoke", nil, true)
	if revoked.Code != http.StatusOK || len(handler.removed) != 2 {
		t.Fatalf("revoke Hysteria profile = %d Hysteria removals=%v body=%s", revoked.Code, handler.removed, revoked.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/enable", nil, true).Code; got != http.StatusConflict {
		t.Fatalf("enable revoked Hysteria profile = %d", got)
	}
	storedVLESS, err := app.server.store.GetClient(t.Context(), vless.ID)
	if err != nil || !storedVLESS.VLESSCanConnect() {
		t.Fatalf("Hysteria state transitions affected VLESS profile: %+v, %v", storedVLESS, err)
	}
}

func TestClientCreateRejectsOptionsFromOtherProtocolAndUnavailableHysteria(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "false")
	app := newTestApp(t, true)
	badVLESS := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "wrong-vless", Auth: "secret"}, true)
	if badVLESS.Code != http.StatusBadRequest || !strings.Contains(badVLESS.Body.String(), "auth is only valid for Hysteria") {
		t.Fatalf("VLESS accepted Hysteria auth: %d %s", badVLESS.Code, badVLESS.Body.String())
	}
	badHysteria := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "wrong-hysteria", Fingerprint: "safari"}, true)
	if badHysteria.Code != http.StatusBadRequest || !strings.Contains(badHysteria.Body.String(), "fingerprint is only valid for VLESS") {
		t.Fatalf("Hysteria accepted VLESS fingerprint: %d %s", badHysteria.Code, badHysteria.Body.String())
	}
	unavailable := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "unavailable"}, true)
	if unavailable.Code != http.StatusConflict || !strings.Contains(unavailable.Body.String(), `"code":"transport_disabled"`) {
		t.Fatalf("disabled Hysteria create = %d %s", unavailable.Code, unavailable.Body.String())
	}
}

func TestReconcilePersistsRuntimeUsersAndRepairsHysteriaRoster(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler, users: []string{"stray@example.test"}}
	app.server.handler = handler
	client := createRuntimeHysteriaClient(t, app, "phone")
	handler.added = nil
	handler.removed = nil
	app.handler.users = []string{"stray@example.test"}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(handler.removed) != 1 || handler.removed[0] != "stray@example.test" || len(handler.added) != 1 || handler.added[0] != client.Email {
		t.Fatalf("Hysteria roster was not repaired: removed=%v added=%v", handler.removed, handler.added)
	}
	active := filepath.Join(app.server.configDir, "active.json")
	if err := os.WriteFile(active, []byte(`{"inbounds":[{"tag":"vless-reality","settings":{"clients":[]}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !activeConfigUsersMatch(active, []domain.Client{client}, true) {
		t.Fatal("reconciler did not persist the Hysteria roster")
	}
	handler.listErr = errors.New("Hysteria inbound unavailable")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Hysteria inbound unavailable") {
		t.Fatalf("Hysteria list failure = %v", err)
	}
}

func TestPersistedClientReconciliationRepairsDriftAndReportsFailures(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	active := filepath.Join(app.server.configDir, "active.json")
	stale := []byte(`{"inbounds":[{"tag":"vless-reality","settings":{"clients":[]}}]}`)
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatal(err)
	}
	if !activeConfigUsersMatch(active, []domain.Client{client}, false) {
		t.Fatal("persisted client list was not repaired")
	}
	validated := len(app.sup.validatedPath)
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err != nil || len(app.sup.validatedPath) != validated {
		t.Fatalf("matching config was needlessly rewritten: %v", err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	app.sup.validateErr = errors.New("candidate rejected")
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "candidate rejected") {
		t.Fatalf("candidate validation failure = %v", err)
	}
	app.sup.validateErr = nil
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "promote reconciled") {
		t.Fatalf("config promotion failure = %v", err)
	}
}

func TestRealityShortIDReconciliationUsesInboundReplacementAndPreservesActiveOnFailure(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	app.server.supervisor = replacer
	active := filepath.Join(app.server.configDir, "active.json")
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatalf("matching REALITY short IDs should not be replaced: %v", err)
	}
	if len(replacer.calls) != 0 {
		t.Fatal("matching inbound was replaced")
	}
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	settings := inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	settings["shortIds"] = []string{client.ShortID}
	stale, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatal(err)
	}
	if len(replacer.calls) != 1 || replacer.calls[0][2] != "vless-reality" {
		t.Fatalf("REALITY drift did not replace only the VLESS inbound: %v", replacer.calls)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	replacer.err = errors.New("Xray rejected replacement")
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "Xray rejected") {
		t.Fatalf("failed replacement = %v", err)
	}
	unchanged, err := os.ReadFile(active)
	if err != nil || string(unchanged) != string(stale) {
		t.Fatalf("failed replacement changed active config: %v", err)
	}
	if err := os.WriteFile(active, []byte("invalid JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("invalid active config error = %v", err)
	}
}

func TestClientCreateFallsBackToValidatedApplyWhenLiveAPIIsUnavailable(t *testing.T) {
	t.Run("first apply failure", func(t *testing.T) {
		app := newTestApp(t, true)
		app.sup.applyErrors = []error{errors.New("first apply failed")}
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone"}, true)
		if response.Code != http.StatusBadGateway {
			t.Fatalf("failed initial apply status = %d %s", response.Code, response.Body.String())
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 0 {
			t.Fatalf("failed initial apply persisted a client: %v, %v", clients, err)
		}
	})
	t.Run("missing live handler", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTestClient(t, app, "first")
		app.server.handler = nil
		createRuntimeTestClient(t, app, "second")
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("missing live handler did not use supervisor apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("AddUser failure", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTestClient(t, app, "first")
		app.handler.addErr = errors.New("live AddUser unavailable")
		createRuntimeTestClient(t, app, "second")
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("AddUser failure did not use supervisor apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("reserve exhaustion without replacer", func(t *testing.T) {
		app := newTestApp(t, true)
		for i := 0; i < 6; i++ {
			createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
		}
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("reserve exhaustion did not fall back to supervisor apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("missing Hysteria handler", func(t *testing.T) {
		t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
		app := newTestApp(t, true)
		first := createRuntimeHysteriaClient(t, app, "first")
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "second"}, true)
		if response.Code != http.StatusCreated || len(app.handler.users) != 0 || len(app.sup.applyCalls) != 2 {
			t.Fatalf("missing Hysteria API should use validated apply fallback = %d, VLESS users=%v applies=%v", response.Code, app.handler.users, app.sup.applyCalls)
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 2 || clients[0].Protocol != domain.ProtocolHysteria2 || clients[1].Protocol != domain.ProtocolHysteria2 || first.UUID != "" {
			t.Fatalf("missing Hysteria API fallback created wrong profiles: %+v, %v", clients, err)
		}
	})
}

func TestHysteriaClientCreateRollsBackLiveUserWhenConfigPromotionFails(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeTestClient(t, app, "first-vless")
	active := filepath.Join(app.server.configDir, "active.json")
	handler.afterAdd = func() {
		if err := os.Remove(active); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(active, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "second"}, true)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("failed config promotion status = %d %s", response.Code, response.Body.String())
	}
	if len(handler.removed) != 1 || len(handler.users) != 0 || len(app.handler.users) != 0 {
		t.Fatalf("live users were not rolled back: Hysteria=%v VLESS=%v", handler.removed, app.handler.users)
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 1 {
		t.Fatalf("failed config promotion persisted a client: %v, %v", clients, err)
	}
}

func TestRealityShortIDReconciliationRollsBackInboundWhenPromotionFails(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	active := filepath.Join(app.server.configDir, "active.json")
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["shortIds"] = []string{client.ShortID}
	stale, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	replacer := &recordingInboundReplacer{fakeSupervisor: app.sup}
	changed := false
	replacer.hook = func() {
		if changed {
			return
		}
		changed = true
		if err := os.Remove(active); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(active, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	app.server.supervisor = replacer
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "promote reconciled") {
		t.Fatalf("failed promotion = %v", err)
	}
	if len(replacer.calls) != 2 || !strings.HasSuffix(replacer.calls[1][3], "-rollback") {
		t.Fatalf("inbound was not rolled back after failed promotion: %v", replacer.calls)
	}
}

func TestRuntimeReconcilerHandlesFirstSetupAndHysteriaAPIFailures(t *testing.T) {
	firstRun := newTestApp(t, false)
	if err := firstRun.server.reconcileRunning(t.Context()); err != nil {
		t.Fatalf("reconciliation before first setup: %v", err)
	}
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeHysteriaClient(t, app, "phone")
	app.server.handler = app.handler
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Hysteria 2 HandlerService") {
		t.Fatalf("missing Hysteria API = %v", err)
	}
	app.server.handler = handler
	handler.users = []string{"stray@example.test"}
	handler.removeErr = errors.New("remove Hysteria user failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "remove Hysteria user failed") {
		t.Fatalf("Hysteria removal failure = %v", err)
	}
	handler.removeErr = nil
	handler.users = nil
	handler.addErr = errors.New("add Hysteria user failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "add Hysteria user failed") {
		t.Fatalf("Hysteria addition failure = %v", err)
	}
}

func TestProfileRejectsHysteriaQRWhenOptionalInboundIsDisabled(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile?format=hysteria-qr", nil, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("disabled Hysteria QR status = %d %s", response.Code, response.Body.String())
	}
}
