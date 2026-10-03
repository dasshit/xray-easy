package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
)

func TestProfileExpiryAPIAndExplicitReenableAfterExtension(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "expiry-phone")
	past := time.Now().UTC().Add(-time.Minute)
	if err := app.server.store.SetClientExpiry(t.Context(), client.ID, &past); err != nil {
		t.Fatal(err)
	}

	listed := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID, nil, true)
	if listed.Code != http.StatusOK {
		t.Fatalf("get expired profile = %d %s", listed.Code, listed.Body.String())
	}
	response := decodeResponse[clientResponse](t, listed)
	if !response.Expired || !response.ExpirationPending || !response.Enabled || response.ExpiresAt == nil || !response.ExpiresAt.Equal(past) {
		t.Fatalf("expired profile response = %+v", response)
	}

	enable := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
	if enable.Code != http.StatusConflict || !strings.Contains(enable.Body.String(), "expired client") {
		t.Fatalf("enable before expiry extension = %d %s", enable.Code, enable.Body.String())
	}

	app.handler.remove = map[string]bool{client.Email: true}
	if err := app.server.expireDueClients(t.Context()); err == nil {
		t.Fatal("expiry sweep did not report the failed Xray operation")
	}
	future := time.Now().UTC().Add(time.Hour)
	pendingExtension := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: &future}, true)
	if pendingExtension.Code != http.StatusConflict || !strings.Contains(pendingExtension.Body.String(), "expiration_pending") {
		t.Fatalf("expiry change while enforcement is pending = %d %s", pendingExtension.Code, pendingExtension.Body.String())
	}
	stored, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || !stored.Enabled {
		t.Fatalf("profile after failed expiry attempt = %+v, %v", stored, err)
	}

	app.handler.remove = nil
	if err := app.server.expireDueClients(t.Context()); err != nil {
		t.Fatalf("retry expiry sweep: %v", err)
	}
	stored, err = app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || stored.Enabled || stored.Revoked || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(past) {
		t.Fatalf("profile after expiry = %+v, %v", stored, err)
	}

	extended := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: &future}, true)
	if extended.Code != http.StatusOK {
		t.Fatalf("extend expiry = %d %s", extended.Code, extended.Body.String())
	}
	updated := decodeResponse[clientResponse](t, extended)
	if updated.Enabled || updated.Expired || updated.ExpiresAt == nil || !updated.ExpiresAt.Equal(future) {
		t.Fatalf("extended profile response = %+v; extension must not enable access", updated)
	}

	enabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
	if enabled.Code != http.StatusOK {
		t.Fatalf("explicit enable after extension = %d %s", enabled.Code, enabled.Body.String())
	}
}

func TestProfileExpiryAPIValidatesAndClearsDeadline(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "expiry-api-phone")

	past := time.Now().UTC().Add(-time.Second)
	invalid := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: &past}, true)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("past expiry accepted: %d %s", invalid.Code, invalid.Body.String())
	}

	future := time.Now().UTC().Add(time.Hour)
	set := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: &future}, true)
	if set.Code != http.StatusOK {
		t.Fatalf("set expiry = %d %s", set.Code, set.Body.String())
	}
	clear := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{}, true)
	if clear.Code != http.StatusOK {
		t.Fatalf("clear expiry = %d %s", clear.Code, clear.Body.String())
	}
	stored, err := app.server.store.GetClient(t.Context(), client.ID)
	if err != nil || stored.ExpiresAt != nil || !stored.Enabled {
		t.Fatalf("profile after clearing expiry = %+v, %v", stored, err)
	}
}

func TestProfileExpiryAPIRejectsMalformedRequestsAndBusyMaintenance(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "expiry-error-phone")
	malformed := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", "not-an-object", true)
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed expiry body = %d %s", malformed.Code, malformed.Body.String())
	}
	zero := time.Time{}
	invalid := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: &zero}, true)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("zero expiry accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	future := futureTimePtr()
	body, err := json.Marshal(clientExpiryRequest{ExpiresAt: future})
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	request := httptest.NewRequest(http.MethodPut, "/api/clients/"+client.ID+"/expiry", strings.NewReader(string(body))).WithContext(requestCtx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	busy := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(busy, request)
	if busy.Code != http.StatusConflict {
		t.Fatalf("expiry change during maintenance = %d %s", busy.Code, busy.Body.String())
	}
}

func TestProfileExpiryAPIMissingProfileAndStorageFailure(t *testing.T) {
	app := newTestApp(t, true)
	future := futureTimePtr()
	body, err := json.Marshal(clientExpiryRequest{ExpiresAt: future})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/clients/missing/expiry", strings.NewReader(string(body)))
	response := httptest.NewRecorder()
	app.server.updateClientExpiry(response, request, domain.Client{ID: "missing"}, app.admin.ID)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expiry update for a missing profile = %d %s", response.Code, response.Body.String())
	}

	client := createRuntimeTestClient(t, app, "expiry-storage-phone")
	execSQLiteTestMutation(t, app, "reject expiry persistence", `CREATE TRIGGER reject_expiry BEFORE UPDATE OF expires_at ON clients BEGIN SELECT RAISE(ABORT, 'expiry write blocked'); END`)
	storedFailure := requestJSON(t, app, http.MethodPut, "/api/clients/"+client.ID+"/expiry", clientExpiryRequest{ExpiresAt: future}, true)
	if storedFailure.Code != http.StatusInternalServerError {
		t.Fatalf("expiry persistence failure = %d %s", storedFailure.Code, storedFailure.Body.String())
	}
}

func TestExpirationWorkerSweepsOnStartupAndKeepsSweepingWithoutSSE(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "startup-expiry-phone")
	second := createRuntimeTestClient(t, app, "ticker-expiry-phone")
	past := time.Now().UTC().Add(-time.Minute)
	if err := app.server.store.SetClientExpiry(t.Context(), client.ID, &past); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(t.Context())
	done := app.server.startExpirationWorkerWithInterval(workerCtx, 10*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	startupSweepComplete := false
	for time.Now().Before(deadline) {
		stored, err := app.server.store.GetClient(t.Context(), client.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !stored.Enabled {
			startupSweepComplete = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !startupSweepComplete {
		cancel()
		<-done
		t.Fatal("startup expiry sweep did not disable the overdue profile")
	}
	if err := app.server.store.SetClientExpiry(t.Context(), second.ID, &past); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stored, err := app.server.store.GetClient(t.Context(), second.ID)
		if err != nil {
			cancel()
			<-done
			t.Fatal(err)
		}
		if !stored.Enabled {
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("expiry worker did not stop after cancellation")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("periodic expiry sweep did not disable the overdue profile")
}

func TestExpirationWorkerHandlesNilServerAndStoreFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var missingServer *server
	done := missingServer.startExpirationWorkerWithInterval(ctx, time.Hour)
	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("expiry worker did not stop for a nil server")
	}
	cancel()

	app := newTestApp(t, true)
	if err := app.server.store.Close(); err != nil {
		t.Fatal(err)
	}
	workerCtx, stop := context.WithCancel(t.Context())
	done = app.server.startExpirationWorkerWithInterval(workerCtx, time.Hour)
	time.Sleep(20 * time.Millisecond)
	stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expiry worker did not stop after store failure")
	}
}

func TestProfileCreationRejectsExpiryForUnsupportedProtocolAndPastDeadline(t *testing.T) {
	app := newTestApp(t, true)
	future := futureTimePtr()
	created := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "expiring-phone", ExpiresAt: future}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create expiring profile = %d %s", created.Code, created.Body.String())
	}
	profile := decodeResponse[clientResponse](t, created)
	if profile.ExpiresAt == nil || !profile.ExpiresAt.Equal(*future) {
		t.Fatalf("created profile expiry = %v, want %v", profile.ExpiresAt, future)
	}

	past := time.Now().UTC().Add(-time.Second)
	for _, test := range []struct {
		name string
		body clientRequest
	}{
		{name: "past date", body: clientRequest{Name: "past-phone", ExpiresAt: &past}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := requestJSON(t, app, http.MethodPost, "/api/clients", test.body, true)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid expiry request = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func futureTimePtr() *time.Time {
	value := time.Now().UTC().Add(time.Hour)
	return &value
}
