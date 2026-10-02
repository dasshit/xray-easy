package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/xray"
)

type recordingTrojanHandler struct {
	*fakeXrayHandler
	users     []string
	added     []string
	removed   []string
	addErr    error
	removeErr error
}

func (h *recordingTrojanHandler) AddTrojanUser(_ context.Context, email, password string) error {
	if h.addErr != nil {
		return h.addErr
	}
	if password == "" {
		return context.Canceled
	}
	h.added = append(h.added, email)
	h.users = append(h.users, email)
	return nil
}

func (h *recordingTrojanHandler) RemoveTrojanUser(_ context.Context, email string) error {
	h.removed = append(h.removed, email)
	if h.removeErr != nil {
		return h.removeErr
	}
	h.users = removeEmail(h.users, email)
	return nil
}

func (h *recordingTrojanHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if tag != xray.TrojanInboundTag {
		return nil, context.Canceled
	}
	return append([]string(nil), h.users...), nil
}

func createRuntimeTrojanClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolTrojan), Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create Trojan profile %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestTrojanProfileLifecycleDeliveryAndReconciliation(t *testing.T) {
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "11443")
	app := newTestApp(t, true)
	app.server.trojanPort = 11443
	handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler

	_ = createRuntimeTrojanClient(t, app, "family-watch")
	client := createRuntimeTrojanClient(t, app, "family-phone")
	if client.TrojanPasswordEnc == "" || len(handler.added) != 1 || handler.added[0] != client.Email {
		t.Fatalf("created Trojan credentials/runtime user = %+v, added=%v", client, handler.added)
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), "\"protocol\":\"trojan\"") || !strings.Contains(profile.Body.String(), "\"trojan_uri\":\"trojan://") || !strings.Contains(profile.Body.String(), "\"json\":") {
		t.Fatalf("Trojan delivery = %d %s", profile.Code, profile.Body.String())
	}
	jsonProfile := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile?format=json", nil, true)
	if jsonProfile.Code != http.StatusOK || !strings.Contains(jsonProfile.Body.String(), "\"password\"") {
		t.Fatalf("Trojan JSON profile = %d %s", jsonProfile.Code, jsonProfile.Body.String())
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile?format=trojan-qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() < 8 {
		t.Fatalf("Trojan QR = %d %v", qr.Code, qr.Header())
	}

	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
		t.Fatalf("disable Trojan = %d %s", response.Code, response.Body.String())
	}
	if len(handler.removed) != 1 || len(handler.users) != 0 {
		t.Fatalf("disabled Trojan roster = removed %v, users %v", handler.removed, handler.users)
	}
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true); response.Code != http.StatusOK {
		t.Fatalf("enable Trojan = %d %s", response.Code, response.Body.String())
	}
	if len(handler.added) != 2 || len(handler.users) != 1 {
		t.Fatalf("enabled Trojan roster = added %v, users %v", handler.added, handler.users)
	}
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/revoke", nil, true); response.Code != http.StatusOK {
		t.Fatalf("revoke Trojan = %d %s", response.Code, response.Body.String())
	}
	if len(handler.removed) != 2 || len(handler.users) != 0 {
		t.Fatalf("revoked Trojan roster = removed %v, users %v", handler.removed, handler.users)
	}
}

func TestTrojanReconcilerRepairsRosterAndFailsClosed(t *testing.T) {
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "11443")

	t.Run("repair stale and missing users", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		client := createRuntimeTrojanClient(t, app, "family-tablet")
		handler.users = []string{"stale@example.test"}
		if err := app.server.reconcileRunning(t.Context()); err != nil {
			t.Fatalf("reconcile Trojan roster: %v", err)
		}
		if len(handler.removed) != 1 || handler.removed[0] != "stale@example.test" || len(handler.added) != 1 || handler.added[0] != client.Email {
			t.Fatalf("reconciled roster removed=%v added=%v", handler.removed, handler.added)
		}
	})

	t.Run("handler unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTrojanClient(t, app, "family-watch")
		app.server.handler = app.handler
		if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Trojan HandlerService is unavailable") {
			t.Fatalf("missing Trojan handler error = %v", err)
		}
	})
}

func TestTrojanProfileCreationRejectsDisabledTransportAndMissingCertificate(t *testing.T) {
	t.Run("transport disabled", func(t *testing.T) {
		t.Setenv("XRAY_TROJAN_ENABLED", "false")
		app := newTestApp(t, true)
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolTrojan), Name: "phone"}, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "transport_disabled") {
			t.Fatalf("disabled Trojan creation = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("certificate missing", func(t *testing.T) {
		t.Setenv("XRAY_TROJAN_ENABLED", "true")
		t.Setenv("XRAY_TROJAN_PORT", "11443")
		app := newTestApp(t, true)
		if err := os.Remove(filepath.Join(app.server.hysteriaTLSDir(), "fullchain.pem")); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolTrojan), Name: "phone"}, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "certificate_not_ready") {
			t.Fatalf("Trojan without certificate = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestTrojanLiveMutationFailuresUseSafeFallbackAndRollback(t *testing.T) {
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	t.Setenv("XRAY_TROJAN_PORT", "11443")

	t.Run("failed live add falls back to full config apply", func(t *testing.T) {
		app := newTestApp(t, true)
		app.server.trojanPort = 11443
		handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		_ = createRuntimeTrojanClient(t, app, "first-watch")
		before := len(app.sup.applyCalls)
		handler.addErr = errors.New("injected Trojan add failure")
		_ = createRuntimeTrojanClient(t, app, "second-phone")
		if len(app.sup.applyCalls) != before+1 {
			t.Fatalf("failed Trojan live add did not trigger full apply: before=%d after=%d", before, len(app.sup.applyCalls))
		}
	})

	t.Run("state mutations roll back after handler failures", func(t *testing.T) {
		app := newTestApp(t, true)
		app.server.trojanPort = 11443
		handler := &recordingTrojanHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		_ = createRuntimeTrojanClient(t, app, "first-watch")
		client := createRuntimeTrojanClient(t, app, "second-phone")
		if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
			t.Fatalf("disable Trojan before failure = %d %s", response.Code, response.Body.String())
		}
		handler.addErr = errors.New("injected Trojan add failure")
		failedEnable := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
		stored, err := app.server.store.GetClient(t.Context(), client.ID)
		if failedEnable.Code != http.StatusBadGateway || err != nil || stored.TrojanEnabled {
			t.Fatalf("failed Trojan enable = %d, stored=%+v, err=%v", failedEnable.Code, stored, err)
		}
		handler.addErr = nil
		if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true); response.Code != http.StatusOK {
			t.Fatalf("enable Trojan after recovery = %d %s", response.Code, response.Body.String())
		}
		handler.removeErr = errors.New("injected Trojan remove failure")
		failedDisable := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
		stored, err = app.server.store.GetClient(t.Context(), client.ID)
		if failedDisable.Code != http.StatusBadGateway || err != nil || !stored.TrojanEnabled {
			t.Fatalf("failed Trojan disable = %d, stored=%+v, err=%v", failedDisable.Code, stored, err)
		}
	})
}
