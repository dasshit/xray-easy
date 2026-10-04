package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/stats"
)

type failingStreamWriter struct {
	header   http.Header
	writes   int
	failAt   int
	status   int
	writeErr error
	flushes  int
	onFlush  func(int)
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
func (w *failingStreamWriter) Flush() {
	w.flushes++
	if w.onFlush != nil {
		w.onFlush(w.flushes)
	}
}

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
	for _, path := range []string{
		"/api/setup/initialize", "/api/auth/login", "/api/auth/logout-all",
		"/api/auth/password", "/api/auth/totp/setup", "/api/auth/totp/enable", "/api/auth/totp/disable",
		"/api/settings", "/api/transports/hysteria2", "/api/transports/amneziawg",
		"/api/transports/hysteria2/certificate", "/api/transports/hysteria2/certificate/mkcert",
		"/api/transports/hysteria2/preview", "/api/transports/hysteria2/apply", "/api/clients", "/api/backups",
	} {
		if response := requestJSON(t, app, http.MethodPut, path, nil, true); response.Code != http.StatusMethodNotAllowed {
			t.Errorf("unsupported PUT %s status = %d %s", path, response.Code, response.Body.String())
		}
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

func TestSSEStopsOnStreamedStatsAndStatusWriteFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		wake func(*testing.T, testApp, *failingStreamWriter)
	}{
		{
			name: "stats update",
			wake: func(t *testing.T, app testApp, writer *failingStreamWriter) {
				manager := stats.NewManager(app.server.store, fixedStatsAPI{})
				app.server.stats = manager
				writer.onFlush = func(flush int) {
					if flush == 2 {
						if err := manager.Poll(context.Background()); err != nil {
							t.Errorf("publish stats notification: %v", err)
						}
					}
				}
			},
		},
		{
			name: "status event",
			wake: func(_ *testing.T, app testApp, writer *failingStreamWriter) {
				writer.onFlush = func(flush int) {
					if flush == 2 {
						app.server.notifyEvents()
					}
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			writer := &failingStreamWriter{header: make(http.Header), failAt: 3, writeErr: errors.New("client disconnected")}
			test.wake(t, app, writer)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
			request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
			newMux(app.server).ServeHTTP(writer, request)
			if writer.writes != 3 {
				t.Fatalf("SSE writes = %d, want third event write to fail", writer.writes)
			}
		})
	}
}

func TestSSEStopsWhenSessionExpiresDuringStream(t *testing.T) {
	app := newTestApp(t, true)
	manager := stats.NewManager(app.server.store, fixedStatsAPI{})
	app.server.stats = manager
	writer := &failingStreamWriter{header: make(http.Header)}
	writer.onFlush = func(flush int) {
		if flush == 2 {
			if err := app.server.store.DeleteAllSessions(t.Context(), app.admin.ID); err != nil {
				t.Errorf("expire SSE administrator session: %v", err)
				return
			}
			if err := manager.Poll(t.Context()); err != nil {
				t.Errorf("publish stats after session expiry: %v", err)
			}
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	newMux(app.server).ServeHTTP(writer, request)
	if writer.writes != 2 {
		t.Fatalf("SSE writes after session expiry = %d, want only initial stats/status", writer.writes)
	}
}

func TestWriteSSEEventHandlesEncodingAndWriteErrors(t *testing.T) {
	writer := &failingStreamWriter{header: make(http.Header), failAt: 1, writeErr: errors.New("stream closed")}
	if err := writeSSEEvent(writer, "bad", make(chan int)); err == nil || writer.writes != 0 {
		t.Fatalf("unencodable SSE payload result = %v, writes=%d", err, writer.writes)
	}
	if err := writeSSEEvent(writer, "stats", map[string]bool{"online": true}); !errors.Is(err, writer.writeErr) || writer.writes != 1 {
		t.Fatalf("failed SSE write result = %v, writes=%d", err, writer.writes)
	}
	writer = &failingStreamWriter{header: make(http.Header)}
	if err := writeSSEEvent(writer, "status", map[string]string{"state": "running"}); err != nil || writer.writes != 1 {
		t.Fatalf("successful SSE event result = %v, writes=%d", err, writer.writes)
	}
}
