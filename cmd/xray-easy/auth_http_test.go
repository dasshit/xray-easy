package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/secret"
	"xray-easy/internal/totp"
)

func TestSetupInitializeValidatesInputsAndPersistsFirstAdmin(t *testing.T) {
	app := newTestApp(t, false)
	if got := requestJSON(t, app, http.MethodGet, "/api/setup/initialize", nil, false).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET initialize status = %d", got)
	}
	if got := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/setup/status", nil, false)); got["initialized"] != false || got["public_port"] != float64(443) {
		t.Fatalf("initial setup status = %+v", got)
	}
	for name, request := range map[string]initializeRequest{
		"username":      {Username: "bad name", Password: "correct horse battery", PublicHost: "vpn.example.test", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"},
		"password":      {Username: "admin", Password: "short", PublicHost: "vpn.example.test", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"},
		"port override": {Username: "admin", Password: "correct horse battery", PublicHost: "vpn.example.test", PublicPort: 8443, RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"},
		"missing host":  {Username: "admin", Password: "correct horse battery", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"},
		"bad host":      {Username: "admin", Password: "correct horse battery", PublicHost: "bad/host", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"},
		"bad target":    {Username: "admin", Password: "correct horse battery", PublicHost: "vpn.example.test", RealityTarget: "localhost", RealitySNI: "www.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid initialization status = %d, body=%s", response.Code, response.Body.String())
			}
		})
	}
	app.sup.probeErr = testError("probe failed")
	request := initializeRequest{Username: " ADMIN ", Password: "correct horse battery", PublicHost: "vpn.example.test", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"}
	response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "REALITY target probe failed") {
		t.Fatalf("failed target probe response = %d %s", response.Code, response.Body.String())
	}
	app.sup.probeErr = nil
	response = requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
	if response.Code != http.StatusCreated {
		t.Fatalf("initialize response = %d %s", response.Code, response.Body.String())
	}
	admin := decodeResponse[map[string]any](t, response)
	if admin["username"] != "admin" || admin["id"] == "" {
		t.Fatalf("initialized admin = %+v", admin)
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.PublicHost != "vpn.example.test" || settings.PublicPort != 443 || settings.RealityPrivateKeyEnc == "" || settings.RealityPublicKey == "" || settings.RealityTarget != "www.example.com:443" {
		t.Fatalf("persisted settings = %+v, %v", settings, err)
	}
	privateKey, err := secret.Open(app.server.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil || privateKey == "" {
		t.Fatalf("stored REALITY key did not decrypt: %v", err)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false).Code; got != http.StatusConflict {
		t.Fatalf("second initialization status = %d", got)
	}
}

func TestSetupInitializeReportsSecretAndStorageFailures(t *testing.T) {
	request := initializeRequest{Username: "admin", Password: "correct horse battery", PublicHost: "vpn.example.test", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"}

	t.Run("master key cannot encrypt generated REALITY key", func(t *testing.T) {
		app := newTestApp(t, false)
		app.server.masterKey = []byte("too-short")
		response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not encrypt REALITY private key") {
			t.Fatalf("invalid master key initialization = %d %s", response.Code, response.Body.String())
		}
		status := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/setup/status", nil, false))
		if status["initialized"] != false {
			t.Fatalf("failed key encryption initialized setup: %+v", status)
		}
	})

	t.Run("administrator insert fails", func(t *testing.T) {
		app := newTestApp(t, false)
		execSQLiteTestMutation(t, app, "reject admin insert", `CREATE TRIGGER reject_admin_insert BEFORE INSERT ON admin_users BEGIN SELECT RAISE(ABORT, 'admin insert blocked'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "admin insert blocked") {
			t.Fatalf("admin insert failure = %d %s", response.Code, response.Body.String())
		}
		status := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/setup/status", nil, false))
		if status["initialized"] != false {
			t.Fatalf("failed admin insert initialized setup: %+v", status)
		}
	})

	t.Run("password salt entropy fails", func(t *testing.T) {
		app := newTestApp(t, false)
		original := cryptorand.Reader
		cryptorand.Reader = failingReader{}
		t.Cleanup(func() { cryptorand.Reader = original })
		response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "generate password salt") {
			t.Fatalf("password hash entropy failure = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("Xray settings update fails", func(t *testing.T) {
		app := newTestApp(t, false)
		execSQLiteTestMutation(t, app, "reject initial settings update", `CREATE TRIGGER reject_initial_settings_update BEFORE UPDATE ON settings BEGIN SELECT RAISE(ABORT, 'settings update blocked'); END`)
		response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not save Xray API settings") {
			t.Fatalf("initial settings update failure = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestSetupInitializeCanonicalizesIPv6PublicHost(t *testing.T) {
	app := newTestApp(t, false)
	request := initializeRequest{
		Username: "admin", Password: "correct horse battery",
		PublicHost:    "2001:0db8:0000:0000:0000:0000:0000:0001",
		RealityTarget: "www.example.com:443", RealitySNI: "www.example.com",
	}
	response := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
	if response.Code != http.StatusCreated {
		t.Fatalf("IPv6 setup response = %d %s", response.Code, response.Body.String())
	}
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil || settings.PublicHost != "2001:db8::1" {
		t.Fatalf("persisted IPv6 public host = %q, %v", settings.PublicHost, err)
	}
}

func TestMkcertIPv4IsSuggestedAndRequiredDuringSetup(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "self-signed")
	t.Setenv("XRAY_HYSTERIA2_CERT_IP", "89.169.13.234")
	app := newTestApp(t, false)
	status := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/setup/status", nil, false))
	if status["suggested_public_host"] != "89.169.13.234" {
		t.Fatalf("mkcert setup status = %+v", status)
	}
	request := initializeRequest{Username: "admin", Password: "correct horse battery", PublicHost: "vpn.example.test", RealityTarget: "www.example.com:443", RealitySNI: "www.example.com"}
	bad := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "XRAY_HYSTERIA2_CERT_IP") {
		t.Fatalf("mismatched mkcert host = %d %s", bad.Code, bad.Body.String())
	}
	request.PublicHost = "89.169.13.234"
	if got := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", request, false); got.Code != http.StatusCreated {
		t.Fatalf("matching mkcert host = %d %s", got.Code, got.Body.String())
	}
	settingsApp := newTestApp(t, true)
	other := "vpn.example.test"
	bad = requestJSON(t, settingsApp, http.MethodPatch, "/api/settings", settingsPatchRequest{PublicHost: &other}, true)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "XRAY_HYSTERIA2_CERT_IP") {
		t.Fatalf("mismatched mkcert settings host = %d %s", bad.Code, bad.Body.String())
	}
}

func TestLoginSessionCookieLogoutAndProtectedRoutes(t *testing.T) {
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/me", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/healthz", nil, false); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"master_key_loaded":true`) {
		t.Fatalf("healthz = %d %s", got.Code, got.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: "admin", Password: "incorrect password"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/totp", loginRequest{Username: "admin", Password: "correct horse battery", TOTPCode: "123456"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("TOTP login while disabled status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/recovery", loginRequest{Username: "admin", Password: "correct horse battery", RecoveryCode: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("recovery login while TOTP disabled status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/login", nil, false).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET login status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login", nil, false).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed login status = %d", got)
	}
	response := requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: " ADMIN ", Password: "correct horse battery"}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d %s", response.Code, response.Body.String())
	}
	cookie := response.Result().Cookies()[0]
	if cookie.Name != "xray_easy_session" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 3*60*60 || cookie.Value == "" {
		t.Fatalf("session cookie = %+v", cookie)
	}
	app.token = cookie.Value
	me := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/me", nil, true))
	if me["username"] != "admin" || me["totp_enabled"] != false || me["recovery_codes_remaining"] != float64(0) {
		t.Fatalf("me response = %+v", me)
	}
	secondSession, err := app.server.store.CreateSession(t.Context(), app.admin.ID, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	app.token = secondSession
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/logout-all", nil, true).Code; got != http.StatusNoContent {
		t.Fatalf("logout-all status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/me", nil, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("session survived logout-all: status=%d", got)
	}
	response = requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: "admin", Password: "correct horse battery"}, false)
	app.token = response.Result().Cookies()[0].Value
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/logout-all", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout-all status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/logout", nil, true).Code; got != http.StatusNoContent {
		t.Fatalf("logout status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/me", nil, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("session survived logout: status=%d", got)
	}
}

func TestLogoutAllRequiresAnAuthenticatedAdmin(t *testing.T) {
	app := newTestApp(t, true)
	response := requestJSON(t, app, http.MethodPost, "/api/auth/logout-all", nil, false)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "authentication required") {
		t.Fatalf("unauthenticated logout-all = %d %s", response.Code, response.Body.String())
	}
}

func TestTOTPSetupEnableLoginRecoveryAndDisable(t *testing.T) {
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated TOTP setup status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/totp/setup", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET TOTP setup status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/totp/status", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated TOTP status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/totp/disable", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET TOTP disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "correct horse battery", Code: "000000"}, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("disable before enabling TOTP status = %d", got)
	}
	setupResponse := requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true)
	if setupResponse.Code != http.StatusOK {
		t.Fatalf("TOTP setup response = %d %s", setupResponse.Code, setupResponse.Body.String())
	}
	type enrollment struct {
		SetupToken    string   `json:"setup_token"`
		Secret        string   `json:"secret"`
		OTPAuthURI    string   `json:"otpauth_uri"`
		QRPNG         string   `json:"qr_png"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	setup := decodeResponse[enrollment](t, setupResponse)
	qr, err := base64.StdEncoding.DecodeString(setup.QRPNG)
	if err != nil || len(qr) < 8 || string(qr[:8]) != "\x89PNG\r\n\x1a\n" || !strings.HasPrefix(setup.OTPAuthURI, "otpauth://totp/") || len(setup.RecoveryCodes) != 10 {
		t.Fatalf("invalid setup enrollment data: QR=%d URI=%q recovery=%d err=%v", len(qr), setup.OTPAuthURI, len(setup.RecoveryCodes), err)
	}
	// Starting setup again invalidates the previous token and secret.
	setupResponse = requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true)
	setup = decodeResponse[enrollment](t, setupResponse)
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: "wrong", Code: "000000"}, true).Code; got != http.StatusConflict {
		t.Fatalf("wrong setup token status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: "000000"}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("wrong TOTP code status = %d", got)
	}
	expired := app.server.pendingTOTP[app.admin.ID]
	expired.ExpiresAt = time.Now().Add(-time.Second)
	app.server.pendingTOTP[app.admin.ID] = expired
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: "000000"}, true).Code; got != http.StatusConflict {
		t.Fatalf("expired setup token status = %d", got)
	}
	setupResponse = requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true)
	setup = decodeResponse[enrollment](t, setupResponse)
	code, err := totp.Code(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	enable := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: code}, true)
	if enable.Code != http.StatusOK || !strings.Contains(enable.Body.String(), `"recovery_codes_remaining":10`) {
		t.Fatalf("TOTP enable = %d %s", enable.Code, enable.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: code}, true).Code; got != http.StatusConflict {
		t.Fatalf("reused setup token status = %d", got)
	}
	status := decodeResponse[map[string]any](t, requestJSON(t, app, http.MethodGet, "/api/auth/totp/status", nil, true))
	if status["enabled"] != true || status["recovery_codes_remaining"] != float64(10) {
		t.Fatalf("TOTP status = %+v", status)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: "admin", Password: "correct horse battery"}, false); got.Code != http.StatusUnauthorized || !strings.Contains(got.Body.String(), "totp_required") {
		t.Fatalf("password-only login with TOTP enabled = %d %s", got.Code, got.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true).Code; got != http.StatusConflict {
		t.Fatalf("TOTP setup when already enabled status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: "admin", Password: "correct horse battery", TOTPCode: "000000"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("invalid TOTP on password login status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/totp", loginRequest{Username: "admin", Password: "wrong", TOTPCode: code}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("invalid second-factor login status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/totp", loginRequest{Username: "admin", Password: "correct horse battery", TOTPCode: "000000"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong TOTP code login status = %d", got)
	}
	login := requestJSON(t, app, http.MethodPost, "/api/auth/login/totp", loginRequest{Username: "admin", Password: "correct horse battery", TOTPCode: code}, false)
	if login.Code != http.StatusOK {
		t.Fatalf("TOTP login = %d %s", login.Code, login.Body.String())
	}
	app.token = login.Result().Cookies()[0].Value
	recovery := requestJSON(t, app, http.MethodPost, "/api/auth/login/recovery", loginRequest{Username: "admin", Password: "correct horse battery", RecoveryCode: setup.RecoveryCodes[0]}, false)
	if recovery.Code != http.StatusOK {
		t.Fatalf("recovery login = %d %s", recovery.Code, recovery.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/recovery", loginRequest{Username: "admin", Password: "correct horse battery", RecoveryCode: setup.RecoveryCodes[0]}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("replayed recovery code status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login/recovery", loginRequest{Username: "admin", Password: "correct horse battery", RecoveryCode: "bad-code"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("malformed recovery code status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "wrong", Code: code}, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong-password TOTP disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "correct horse battery", Code: "000000"}, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong-code TOTP disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/totp/disable", totpDisableRequest{Password: "correct horse battery", Code: code}, true).Code; got != http.StatusNoContent {
		t.Fatalf("TOTP disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/me", nil, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("TOTP disable did not revoke sessions: status=%d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/auth/login", loginRequest{Username: "admin", Password: "correct horse battery"}, false).Code; got != http.StatusOK {
		t.Fatalf("password login after TOTP disable status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/auth/totp/disable", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET TOTP disable after reset status = %d", got)
	}
}

func TestTOTPEnableReportsEncryptionFailure(t *testing.T) {
	app := newTestApp(t, true)
	setupResponse := requestJSON(t, app, http.MethodPost, "/api/auth/totp/setup", nil, true)
	setup := decodeResponse[struct {
		SetupToken string `json:"setup_token"`
		Secret     string `json:"secret"`
	}](t, setupResponse)
	code, err := totp.Code(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	app.server.masterKey = []byte("short")
	response := requestJSON(t, app, http.MethodPost, "/api/auth/totp/enable", totpSetupRequest{SetupToken: setup.SetupToken, Code: code}, true)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not encrypt TOTP secret") {
		t.Fatalf("TOTP encryption error = %d %s", response.Code, response.Body.String())
	}
}

type testError string

func (e testError) Error() string { return string(e) }
