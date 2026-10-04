package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
)

func TestChangeClientStateHandlesMissingAndSystemReconciliationCases(t *testing.T) {
	t.Run("unknown client", func(t *testing.T) {
		app := newTestApp(t, true)
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), domain.Client{ID: "missing-client"}, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusNotFound {
			t.Fatalf("missing client status = %d, body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("system reconciliation skips a non-expired client", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "not-expired")
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, expirySystemActorID)
		if response.Code != http.StatusOK {
			t.Fatalf("system reconciliation status = %d, body=%s", response.Code, response.Body.String())
		}
		stored, err := app.server.store.GetClient(t.Context(), client.ID)
		if err != nil || !stored.VLESSEnabled {
			t.Fatalf("system reconciliation unexpectedly changed profile: %+v, %v", stored, err)
		}
	})

	t.Run("missing settings", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "missing-settings")
		execSQLiteTestMutation(t, app, "remove settings for profile-state test", "DELETE FROM settings")
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusConflict {
			t.Fatalf("missing settings status = %d, body=%s", response.Code, response.Body.String())
		}
	})
}

func TestChangeClientStateStopsAtPreflightFailures(t *testing.T) {
	t.Run("unavailable client store", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "closed-store")
		if err := app.server.store.Close(); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("closed client store status = %d, body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("unsupported transition", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "bad-action")
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ClientAction("invalid"), app.admin.ID)
		if response.Code != http.StatusConflict {
			t.Fatalf("unsupported action status = %d, body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("maintenance lock is held", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "maintenance-lock")
		lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancelAfter := time.AfterFunc(20*time.Millisecond, cancel)
		defer cancelAfter.Stop()
		defer cancel()
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusConflict {
			t.Fatalf("busy maintenance status = %d, body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("encrypted REALITY key cannot be opened", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "bad-reality-key")
		execSQLiteTestMutation(t, app, "corrupt REALITY key", `UPDATE settings SET reality_private_key_enc='invalid' WHERE id=1`)
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("invalid REALITY key status = %d, body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("reserved short ID table is unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "missing-short-id-table")
		execSQLiteTestMutation(t, app, "drop REALITY short ID table", `DROP TABLE reality_short_ids`)
		response := httptest.NewRecorder()
		app.server.changeClientState(response, httptest.NewRequest(http.MethodPost, "/", nil), client, domain.ActionDisable, app.admin.ID)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("missing short ID table status = %d, body=%s", response.Code, response.Body.String())
		}
	})
}

func TestChangeClientStateRejectsEnablingRevokedProfile(t *testing.T) {
	client := domain.Client{
		Protocol: domain.ProtocolVLESS, VLESSEnabled: false, VLESSRevoked: true,
	}
	if _, _, err := transitionClientAccesses(client, domain.ActionEnable); !errors.Is(err, domain.ErrClientRevoked) {
		t.Fatalf("enable revoked profile error = %v", err)
	}
}

func TestTransitionClientAccessesRejectsProfileWithoutSupportedAccess(t *testing.T) {
	if _, _, err := transitionClientAccesses(domain.Client{}, domain.ActionDisable); err == nil || err.Error() != "profile has no supported protocol access" {
		t.Fatalf("transition without protocol access error = %v", err)
	}
}

func TestChangeClientStateRejectsUndecryptableRealityKey(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "bad-key-state")
	execSQLiteTestMutation(t, app, "corrupt REALITY key", `UPDATE settings SET reality_private_key_enc='invalid' WHERE id=1`)
	response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not decrypt REALITY private key") {
		t.Fatalf("state change with an undecryptable key = %d %s", response.Code, response.Body.String())
	}
}
