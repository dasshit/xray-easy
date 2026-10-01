package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failingStreamWriter struct {
	header   http.Header
	writes   int
	failAt   int
	status   int
	writeErr error
}

func (w *failingStreamWriter) Header() http.Header    { return w.header }
func (w *failingStreamWriter) WriteHeader(status int) { w.status = status }
func (w *failingStreamWriter) Write(data []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, w.writeErr
	}
	return len(data), nil
}
func (*failingStreamWriter) Flush() {}

func TestHTTPBoundaryValidationAndProfileRenderingErrors(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/auth/login/totp"},
		{http.MethodGet, "/api/auth/login/recovery"},
		{http.MethodGet, "/api/auth/totp/enable"},
		{http.MethodGet, "/api/auth/totp/disable"},
	} {
		if got := requestJSON(t, app, tc.method, tc.path, nil, true).Code; got != http.StatusMethodNotAllowed {
			t.Errorf("%s %s status = %d", tc.method, tc.path, got)
		}
	}
	for _, path := range []string{"/api/auth/login/totp", "/api/auth/login/recovery", "/api/auth/totp/enable", "/api/auth/totp/disable"} {
		if got := requestJSON(t, app, http.MethodPost, path, nil, true).Code; got != http.StatusBadRequest {
			t.Errorf("malformed POST %s status = %d", path, got)
		}
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/setup/initialize", nil, false).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed initialization status = %d", got)
	}

	client := seedTestClient(t, app, "invalid-target")
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	settings.RealityTarget = "invalid-target"
	if err := app.server.store.UpdateSettings(t.Context(), settings); err != nil {
		t.Fatal(err)
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
	if profile.Code != http.StatusConflict || !strings.Contains(profile.Body.String(), "host:port") {
		t.Fatalf("invalid persisted settings profile response = %d %s", profile.Code, profile.Body.String())
	}
}

func TestSSEStopsOnStatsAndStatusWriteFailures(t *testing.T) {
	t.Parallel()
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "stats", 2: "status"}[failAt], func(t *testing.T) {
			app := newTestApp(t, true)
			writer := &failingStreamWriter{header: make(http.Header), failAt: failAt, writeErr: errors.New("client disconnected")}
			request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
			request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
			newMux(app.server).ServeHTTP(writer, request)
			if writer.writes != failAt {
				t.Fatalf("SSE writes = %d, wanted failure at %d", writer.writes, failAt)
			}
			app.server.eventsMu.Lock()
			remaining := len(app.server.eventSubs)
			app.server.eventsMu.Unlock()
			if remaining != 0 {
				t.Fatalf("failed stream left %d event subscriptions", remaining)
			}
		})
	}
}
