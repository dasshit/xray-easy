package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/stats"
	"xray-easy/internal/xrayapi"
)

type fixedStatsAPI struct{ rows []xrayapi.UserStats }

func (f fixedStatsAPI) Poll(context.Context) ([]xrayapi.UserStats, error) {
	return append([]xrayapi.UserStats(nil), f.rows...), nil
}

func TestClientResponsesAndSSEIncludePersistedTrafficSnapshot(t *testing.T) {
	app := newTestApp(t, true)
	client := seedTestClient(t, app, "laptop")
	lastSeen := time.Now().UTC().Add(-time.Minute)
	manager := stats.NewManager(app.server.store, fixedStatsAPI{rows: []xrayapi.UserStats{{Email: client.Email, UploadBytes: 4321, DownloadBytes: 9876, LastSeen: lastSeen}}})
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	app.server.stats = manager
	clients := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if clients.Code != http.StatusOK || !strings.Contains(clients.Body.String(), `"online":true`) || !strings.Contains(clients.Body.String(), `"upload_bytes":4321`) || !strings.Contains(clients.Body.String(), `"download_bytes":9876`) || !strings.Contains(clients.Body.String(), `"last_seen":`) {
		t.Fatalf("client traffic response = %d %s", clients.Code, clients.Body.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	response := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	response.onFlush = func(flush int) {
		if flush == 2 {
			cancel()
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	newMux(app.server).ServeHTTP(response, request)
	defer cancel()
	if !strings.Contains(response.Body.String(), `"type":"stats"`) || !strings.Contains(response.Body.String(), client.ID) || !strings.Contains(response.Body.String(), `"upload_bytes":4321`) || !strings.Contains(response.Body.String(), `"type":"status"`) {
		t.Fatalf("SSE traffic/status snapshot = %s", response.Body.String())
	}
	if snapshot := manager.Snapshot()[client.ID]; !snapshot.Online || snapshot.UploadBytes != 4321 || snapshot.DownloadBytes != 9876 {
		t.Fatalf("stats manager snapshot = %+v", snapshot)
	}
}
