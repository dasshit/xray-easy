package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/secret"
)

func TestCandidateApplicationHelpersCommitRollbackAndRejectInvalidConfigs(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "tablet")
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := client.AccessState(domain.ProtocolVLESS); err != nil || got != (domain.ClientState{Enabled: true, Revoked: false}) {
		t.Fatalf("VLESS access state = %+v, %v", got, err)
	}
	if err := app.server.applyClientsLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "test.apply", client.ID); err != nil {
		t.Fatalf("applyClientsLocked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(app.server.configDir, "active.json")); err != nil {
		t.Fatalf("active config not promoted: %v", err)
	}

	app.sup.applyErrors = []error{errors.New("apply failed")}
	if err := app.server.applyClientsLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "test.apply", client.ID); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("applyClientsLocked apply failure = %v", err)
	}
	if _, _, err := app.server.prepareCandidateLocked(context.Background(), domain.Settings{RealityTarget: "bad"}, privateKey, nil); err == nil || !strings.Contains(err.Error(), "render Xray config") {
		t.Fatalf("invalid render settings error = %v", err)
	}
	app.sup.validateErr = errors.New("validation failed")
	if _, _, err := app.server.prepareCandidateLocked(context.Background(), settings, privateKey, []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("candidate validation failure = %v", err)
	}
	app.sup.validateErr = nil

	path := filepath.Join(app.server.configDir, "candidates", "already-rendered.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.promoteCandidateLocked(context.Background(), path, "op-success", app.admin.ID, "test.promote", client.ID); err != nil {
		t.Fatalf("promote candidate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(app.server.configDir, "active.json")); err != nil {
		t.Fatalf("promoted candidate missing: %v", err)
	}
	if err := app.server.promoteCandidateLocked(context.Background(), filepath.Join(app.server.configDir, "missing.json"), "op-fail", app.admin.ID, "test.promote", client.ID); err == nil || !strings.Contains(err.Error(), "promote Xray config") {
		t.Fatalf("promotion failure = %v", err)
	}
}

func TestLiveClientApplyRollsBackPersistedStateWhenPromotionFails(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "watch")
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(app.server.configDir, "active.json")
	if err := os.Mkdir(activePath, 0o700); err != nil {
		t.Fatal(err)
	}
	persisted, rolledBack := false, false
	err = app.server.applyClientsLiveLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "client.state", client.ID, func() error {
		persisted = true
		return nil
	}, func() error {
		rolledBack = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "promote Xray config") || !persisted || !rolledBack || len(app.sup.applyCalls) != 2 {
		t.Fatalf("promotion failure err=%v persisted=%v rollback=%v applyCalls=%d", err, persisted, rolledBack, len(app.sup.applyCalls))
	}
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	err = app.server.applyClientsLiveLocked(ctx, settings, privateKey, []domain.Client{client}, app.admin.ID, "client.state", client.ID, nil, nil)
	_ = lock.Close()
	if err == nil || !strings.Contains(err.Error(), "context deadline") {
		t.Fatalf("live apply while maintenance lock held = %v", err)
	}
}

func TestLiveClientApplyRestoresXrayWhenPersistenceFails(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "phone")
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}
	rollbackCalled := false
	err = app.server.applyClientsLiveLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "client.state", client.ID, func() error {
		return errors.New("injected persistence failure")
	}, func() error {
		rollbackCalled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "persist client change") || rollbackCalled || len(app.sup.applyCalls) != 2 || !strings.HasSuffix(app.sup.applyCalls[1][1], "-rollback") {
		t.Fatalf("persistence failure recovery err=%v rollbackCalled=%v applyCalls=%v", err, rollbackCalled, app.sup.applyCalls)
	}
}

func TestApplyClientsLockedReportsMaintenanceApplyAndPromotionFailures(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "tablet")
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		t.Fatal(err)
	}

	lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	lockCtx, cancelLock := context.WithTimeout(context.Background(), 40*time.Millisecond)
	lockErr := app.server.applyClientsLocked(lockCtx, settings, privateKey, []domain.Client{client}, app.admin.ID, "test.apply", client.ID)
	cancelLock()
	if lockErr == nil {
		t.Fatal("apply ignored held maintenance lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	app.sup.applyErrors = []error{errors.New("supervisor apply failed")}
	if err := app.server.applyClientsLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "test.apply", client.ID); err == nil || !strings.Contains(err.Error(), "supervisor apply failed") {
		t.Fatalf("supervisor apply failure = %v", err)
	}

	if err := os.Mkdir(filepath.Join(app.server.configDir, "active.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	err = app.server.applyClientsLocked(context.Background(), settings, privateKey, []domain.Client{client}, app.admin.ID, "test.apply", client.ID)
	if err == nil || !strings.Contains(err.Error(), "promote Xray config") || len(app.sup.applyCalls) != 3 || !strings.HasSuffix(app.sup.applyCalls[2][1], "-rollback") {
		t.Fatalf("promotion rollback err=%v calls=%v", err, app.sup.applyCalls)
	}
}

func TestSettingsApplyConflictExpiredAndLockGuardPaths(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "tablet")
	newHost := "node-new.example.test"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)

	app.server.settingsMu.Lock()
	pending := app.server.pendingSettings[change.ChangeID]
	pending.ExpiresAt = time.Now().Add(-time.Second)
	app.server.pendingSettings[change.ChangeID] = pending
	app.server.settingsMu.Unlock()
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("expired confirmation status = %d", got)
	}

	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	app.server.settingsMu.Lock()
	pending = app.server.pendingSettings[change.ChangeID]
	pending.AdminID = "different-admin"
	app.server.pendingSettings[change.ChangeID] = pending
	app.server.settingsMu.Unlock()
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("wrong-admin confirmation status = %d", got)
	}
	app.server.settingsMu.Lock()
	pending = app.server.pendingSettings[change.ChangeID]
	pending.AdminID = app.admin.ID
	pending.Applying = true
	app.server.pendingSettings[change.ChangeID] = pending
	app.server.settingsMu.Unlock()
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("already-applying confirmation status = %d", got)
	}

	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	settings, err := app.server.store.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	settings.PublicHost = "out-of-band.example.test"
	if err := app.server.store.UpdateSettings(context.Background(), settings); err != nil {
		t.Fatal(err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("stale settings confirmation status = %d", got)
	}

	currentHost := "fresh.example.test"
	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &currentHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	if err := app.server.store.SetClientState(context.Background(), client.ID, false, false); err != nil {
		t.Fatal(err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusConflict {
		t.Fatalf("stale profile list confirmation status = %d", got)
	}

	target, sni := "other.example.com:443", "other.example.com"
	app.sup.probeErr = errors.New("unreachable")
	if got := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RealityTarget: &target, RealitySNI: &sni}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("failed validation probe status = %d", got)
	}
	app.sup.probeErr = nil
	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{RealityTarget: &target, RealitySNI: &sni}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	app.sup.probeErr = errors.New("target changed during confirmation")
	if got := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true).Code; got != http.StatusBadGateway {
		t.Fatalf("failed re-probe status = %d", got)
	}
	app.sup.probeErr = nil

	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/settings/apply", strings.NewReader(`{"change_id":"`+change.ChangeID+`","confirmation":"REVOKE"}`))
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	response := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(response, request)
	_ = lock.Close()
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("settings apply while maintenance lock held = %d %s", response.Code, response.Body.String())
	}
}

func TestSettingsApplyBackupAndCandidateValidationFailures(t *testing.T) {
	app := newTestApp(t, true)
	newHost := "rotated.example.test"
	prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change := decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	activePath := filepath.Join(app.server.configDir, "active.json")
	if err := os.WriteFile(activePath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupFailure := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
	if backupFailure.Code != http.StatusInternalServerError || !strings.Contains(backupFailure.Body.String(), "backup_failed") {
		t.Fatalf("automatic backup failure response = %d %s", backupFailure.Code, backupFailure.Body.String())
	}
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	app.sup.validateErr = errors.New("candidate rejected")
	validationFailure := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
	app.sup.validateErr = nil
	if validationFailure.Code != http.StatusBadGateway || !strings.Contains(validationFailure.Body.String(), "candidate rejected") {
		t.Fatalf("candidate validation failure response = %d %s", validationFailure.Code, validationFailure.Body.String())
	}

	prepared = requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
	change = decodeResponse[struct {
		ChangeID string `json:"change_id"`
	}](t, prepared)
	app.server.settingsMu.Lock()
	pending := app.server.pendingSettings[change.ChangeID]
	pending.Settings.RealityPrivateKeyEnc = "not-an-envelope"
	app.server.pendingSettings[change.ChangeID] = pending
	app.server.settingsMu.Unlock()
	decryptFailure := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
	if decryptFailure.Code != http.StatusInternalServerError || !strings.Contains(decryptFailure.Body.String(), "could not decrypt candidate") {
		t.Fatalf("candidate key decryption failure = %d %s", decryptFailure.Code, decryptFailure.Body.String())
	}
}

func TestSettingsApplyDatabaseAndPromotionFailureRollBack(t *testing.T) {
	newHost := "rotated.example.test"
	t.Run("database transaction", func(t *testing.T) {
		app := newTestApp(t, true)
		client := seedTestClient(t, app, "phone")
		prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
		change := decodeResponse[struct {
			ChangeID string `json:"change_id"`
		}](t, prepared)
		app.sup.applyHook = func(_, _ string) {
			// Remove the row after the Xray candidate is active so the transactional
			// settings-plus-device-state update fails as one unit.
			_ = app.server.store.DeleteClient(context.Background(), client.ID)
			app.sup.applyHook = nil
		}
		response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "persist settings rotation") {
			t.Fatalf("settings transaction failure = %d %s", response.Code, response.Body.String())
		}
		settings, err := app.server.store.GetSettings(context.Background())
		if err != nil || settings.PublicHost != "vpn.example.test" {
			t.Fatalf("transaction changed node settings: %+v, %v", settings, err)
		}
	})

	t.Run("promote candidate", func(t *testing.T) {
		app := newTestApp(t, true)
		prepared := requestJSON(t, app, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &newHost}, true)
		change := decodeResponse[struct {
			ChangeID string `json:"change_id"`
		}](t, prepared)
		activePath := filepath.Join(app.server.configDir, "active.json")
		app.sup.applyHook = func(_, operationID string) {
			if !strings.HasSuffix(operationID, "-rollback") {
				_ = os.Mkdir(activePath, 0o700)
			}
		}
		response := requestJSON(t, app, http.MethodPost, "/api/settings/apply", settingsApplyRequest{ChangeID: change.ChangeID, Confirmation: "REVOKE"}, true)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "promote Xray config") {
			t.Fatalf("candidate promotion failure = %d %s", response.Code, response.Body.String())
		}
		settings, err := app.server.store.GetSettings(context.Background())
		if err != nil || settings.PublicHost != "vpn.example.test" {
			t.Fatalf("promotion failure did not restore settings: %+v, %v", settings, err)
		}
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("promotion failure should ask Xray to roll back, apply calls=%d", len(app.sup.applyCalls))
		}
	})
}

func TestIssueSessionAndHealthHandlersReportClosedStore(t *testing.T) {
	app := newTestApp(t, true)
	if err := app.server.store.Close(); err != nil {
		t.Fatal(err)
	}
	health := requestJSON(t, app, http.MethodGet, "/api/healthz", nil, false)
	if health.Code != http.StatusServiceUnavailable || !strings.Contains(health.Body.String(), "database unavailable") {
		t.Fatalf("closed DB health response = %d %s", health.Code, health.Body.String())
	}
	setupStatus := requestJSON(t, app, http.MethodGet, "/api/setup/status", nil, false)
	if setupStatus.Code != http.StatusInternalServerError {
		t.Fatalf("closed DB setup status = %d", setupStatus.Code)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	request = request.WithContext(context.Background())
	app.server.issueSession(response, request, app.admin)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not create session") {
		t.Fatalf("failed session issuance = %d %s", response.Code, response.Body.String())
	}
}

func TestApplyRestoredStateReportsValidationAndPromotionFailures(t *testing.T) {
	app := newTestApp(t, true)
	if err := applyRestoredStateWithSupervisor(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, &fakeSupervisor{validateErr: errors.New("invalid Xray config")}); err == nil || !strings.Contains(err.Error(), "invalid Xray config") {
		t.Fatalf("restored-state validation failure = %v", err)
	}
	if err := applyRestoredStateWithSupervisor(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, &fakeSupervisor{applyErrors: []error{errors.New("apply failed")}}); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("restored-state apply failure = %v", err)
	}
	if err := os.Mkdir(filepath.Join(app.server.configDir, "active.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := applyRestoredStateWithSupervisor(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443, &fakeSupervisor{}); err == nil {
		t.Fatal("restored-state promotion failure ignored")
	}
}

func TestStartReconcilerPerformsInitialSyncAndHonorsCancellation(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "initial-sync")
	app.handler.users = []string{"stale@xray-easy"}
	ctx, cancel := context.WithCancel(context.Background())
	app.server.startReconciler(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		app.handler.mu.Lock()
		calls := app.handler.usersCalls
		users := append([]string(nil), app.handler.users...)
		app.handler.mu.Unlock()
		if calls > 0 && len(users) == 1 && users[0] == client.Email {
			cancel()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	t.Fatal("reconciler did not perform its initial sync")
}

func TestApplyRestoredStateWrapperReturnsStorageErrorsBeforeNetwork(t *testing.T) {
	app := newTestApp(t, false)
	tokenPath := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	if err := applyRestoredState(context.Background(), app.server.store, app.server.masterKey, app.server.configDir, 443); err == nil || !strings.Contains(err.Error(), "settings are not initialized") {
		t.Fatalf("applyRestoredState missing settings error = %v", err)
	}
}
