package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSettingsPreparationReportsAuthenticationAndStorageFailures(t *testing.T) {
	t.Run("authentication required", func(t *testing.T) {
		app := newTestApp(t, true)
		request := httptest.NewRequest(http.MethodPatch, "/api/settings", strings.NewReader(`{}`))
		response := httptest.NewRecorder()
		app.server.prepareSettingsChange(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated settings preview = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("settings unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop settings", `DROP TABLE settings`)
		response := settingsPreviewDirect(t, app, `{"log_level":"debug"}`, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "settings_incomplete") {
			t.Fatalf("settings storage failure = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestSettingsPreparationReportsRandomGenerationAndEncryptionFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		entropy   []byte
		wantError string
	}{
		{name: "change ID entropy", wantError: "could not create settings change"},
		{name: "REALITY key encryption", entropy: make([]byte, 48), wantError: "could not encrypt REALITY private key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			original := cryptorand.Reader
			cryptorand.Reader = io.MultiReader(bytes.NewReader(test.entropy), failingReader{})
			t.Cleanup(func() { cryptorand.Reader = original })
			response := settingsPreviewDirect(t, app, `{"rotate_private_key":true}`, true)
			if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), test.wantError) {
				t.Fatalf("settings preparation failure = %d %s, want %q", response.Code, response.Body.String(), test.wantError)
			}
		})
	}
}

func settingsPreviewDirect(t *testing.T, app testApp, body string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPatch, "/api/settings", strings.NewReader(body))
	if authenticated {
		request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	}
	response := httptest.NewRecorder()
	app.server.prepareSettingsChange(response, request)
	return response
}
