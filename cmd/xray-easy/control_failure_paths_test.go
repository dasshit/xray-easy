package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlPlaneReportsDiagnosticProfileAndBackupFailures(t *testing.T) {
	t.Run("status redacts supervisor errors", func(t *testing.T) {
		app := newTestApp(t, true)
		if got := requestJSON(t, app, http.MethodGet, "/api/status", nil, false).Code; got != http.StatusUnauthorized {
			t.Fatalf("unauthenticated status endpoint = %d", got)
		}
		app.sup.statusErr = errors.New(`token="do-not-return"`)
		response := requestJSON(t, app, http.MethodGet, "/api/status", nil, true)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"unavailable"`) || strings.Contains(response.Body.String(), "do-not-return") || !strings.Contains(response.Body.String(), "[REDACTED]") {
			t.Fatalf("status error response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("supervisor logs unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		for _, path := range []string{"/api/logs?component=other", "/api/logs?limit=nope", "/api/logs?limit=201"} {
			if got := requestJSON(t, app, http.MethodGet, path, nil, true).Code; got != http.StatusBadRequest {
				t.Errorf("invalid diagnostics query %s status = %d", path, got)
			}
		}
		app.sup.logsErr = errors.New("supervisor offline")
		response := requestJSON(t, app, http.MethodGet, "/api/logs", nil, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "diagnostics_unavailable") {
			t.Fatalf("logs error response = %d %s", response.Code, response.Body.String())
		}
		entries := app.server.diagnosticBuffer.Snapshot(10)
		if len(entries) != 1 || !strings.Contains(entries[0].Message, "supervisor offline") {
			t.Fatalf("diagnostic entry after logs error = %+v", entries)
		}
	})

	t.Run("profile refuses undecryptable server key", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "laptop")
		settings, err := app.server.store.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.RealityPrivateKeyEnc = "invalid-envelope"
		if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not decrypt REALITY private key") {
			t.Fatalf("profile key error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("profile reports incomplete settings", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "incomplete-settings")
		execSQLiteTestMutation(t, app, "drop settings", `DROP TABLE settings`)
		response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "settings are incomplete") {
			t.Fatalf("profile with incomplete settings = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("profile client detail and create database error", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "device-detail")
		detail := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID, nil, true)
		if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), client.ID) {
			t.Fatalf("client detail = %d %s", detail.Code, detail.Body.String())
		}
		execSQLiteTestMutation(t, app, "drop clients", `DROP TABLE clients`)
		created := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "new-device"}, true)
		if created.Code != http.StatusBadGateway || !strings.Contains(created.Body.String(), "list clients") {
			t.Fatalf("create client database error = %d %s", created.Code, created.Body.String())
		}
	})

	t.Run("backup list and create report filesystem errors", func(t *testing.T) {
		app := newTestApp(t, true)
		backupPath := filepath.Join(app.server.dataDir, "backups")
		if err := os.WriteFile(backupPath, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		listed := requestJSON(t, app, http.MethodGet, "/api/backups", nil, true)
		if listed.Code != http.StatusInternalServerError || !strings.Contains(listed.Body.String(), "could not list backups") {
			t.Fatalf("backup list error = %d %s", listed.Code, listed.Body.String())
		}
		created := requestJSON(t, app, http.MethodPost, "/api/backups", nil, true)
		if created.Code != http.StatusInternalServerError || !strings.Contains(created.Body.String(), "could not create backup") {
			t.Fatalf("backup create error = %d %s", created.Code, created.Body.String())
		}
	})

	t.Run("database read failures become service errors", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop clients", `DROP TABLE clients`)
		clients := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
		if clients.Code != http.StatusInternalServerError || !strings.Contains(clients.Body.String(), "could not list clients") {
			t.Fatalf("client list database error = %d %s", clients.Code, clients.Body.String())
		}
	})

	t.Run("settings read failures stay explicit", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop settings", `DROP TABLE settings`)
		read := requestJSON(t, app, http.MethodGet, "/api/settings", nil, true)
		if read.Code != http.StatusNotFound || !strings.Contains(read.Body.String(), "no such table: settings") {
			t.Fatalf("settings read error = %d %s", read.Code, read.Body.String())
		}
		update := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{}, true)
		if update.Code != http.StatusNotFound || !strings.Contains(update.Body.String(), "no such table: settings") {
			t.Fatalf("settings change without persisted settings = %d %s", update.Code, update.Body.String())
		}
	})

	t.Run("settings preparation reports missing client table", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop clients", `DROP TABLE clients`)
		target, sni := "new.example.com:443", "new.example.com"
		response := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RealityTarget: &target, RealitySNI: &sni}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not list clients") {
			t.Fatalf("settings preparation client query error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("fingerprint update persistence failure is returned", func(t *testing.T) {
		app := newTestApp(t, true)
		fingerprint := "safari"
		prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{ClientFingerprint: &fingerprint}, true)
		change := decodeResponse[struct {
			ChangeID string `json:"change_id"`
		}](t, prepared)
		execSQLiteTestMutation(t, app, "settings update", `CREATE TRIGGER reject_settings_update BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT, 'injected settings update failure'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "persist settings") {
			t.Fatalf("fingerprint persistence error = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("settings apply reports missing current settings and client list", func(t *testing.T) {
		t.Run("settings table", func(t *testing.T) {
			app := newTestApp(t, true)
			newHost := "pending.example.test"
			prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
			change := decodeResponse[struct {
				ChangeID string `json:"change_id"`
			}](t, prepared)
			execSQLiteTestMutation(t, app, "drop settings", `DROP TABLE settings`)
			response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "settings_incomplete") {
				t.Fatalf("settings apply without settings = %d %s", response.Code, response.Body.String())
			}
		})
		t.Run("client table", func(t *testing.T) {
			app := newTestApp(t, true)
			newHost := "pending.example.test"
			prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
			change := decodeResponse[struct {
				ChangeID string `json:"change_id"`
			}](t, prepared)
			execSQLiteTestMutation(t, app, "drop clients", `DROP TABLE clients`)
			response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not list clients") {
				t.Fatalf("settings apply without client table = %d %s", response.Code, response.Body.String())
			}
		})
	})
}

func TestStartReconcilerRetriesAndReportsBackgroundFailure(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "background")
	if client.ID == "" {
		t.Fatal("test client was not created")
	}
	app.handler.usersErr = errors.New("stats API temporarily unavailable")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.server.startReconcilerWithInterval(ctx, 5*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, entry := range app.server.diagnosticBuffer.Snapshot(10) {
			if strings.Contains(entry.Message, "Xray reconciliation skipped") {
				cancel()
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("periodic reconciler did not record its retry failure")
}
