package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/maintenance"
	"xray-easy/internal/xray"
)

type flushRecorder struct {
	*httptest.ResponseRecorder
	onFlush func(int)
	flushes int
}

func (w *flushRecorder) Flush() {
	w.flushes++
	w.ResponseRecorder.Flush()
	if w.onFlush != nil {
		w.onFlush(w.flushes)
	}
}

type noFlushWriter struct {
	header http.Header
	status int
}

func (w *noFlushWriter) Header() http.Header            { return w.header }
func (w *noFlushWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *noFlushWriter) WriteHeader(status int)         { w.status = status }

func TestSSEInitialSnapshotStatusEventsAndCancellation(t *testing.T) {
	app := newTestApp(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	response := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	response.onFlush = func(count int) {
		if count == 2 {
			app.server.notifyEvents()
		}
		if count == 3 {
			cancel()
		}
	}
	newMux(app.server).ServeHTTP(response, request)
	defer cancel()
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream" || !strings.Contains(body, "event: stats") || !strings.Contains(body, "event: status") || strings.Count(body, "event: status") < 2 {
		t.Fatalf("SSE status/events = %d headers=%v body=%s", response.Code, response.Header(), body)
	}
	app.server.eventsMu.Lock()
	remaining := len(app.server.eventSubs)
	app.server.eventsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("SSE request left %d event subscriptions", remaining)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/events", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated SSE status = %d", got)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	noFlush := &noFlushWriter{header: make(http.Header)}
	newMux(app.server).ServeHTTP(noFlush, request)
	if noFlush.status != http.StatusInternalServerError {
		t.Fatalf("non-flushing SSE response status = %d", noFlush.status)
	}
}

func TestEventSubscriptionsCoalesceAndCanUnsubscribeTwice(t *testing.T) {
	app := newTestApp(t, true)
	channel, unsubscribe := app.server.subscribeEvents()
	app.server.notifyEvents()
	app.server.notifyEvents()
	select {
	case <-channel:
	default:
		t.Fatal("event notification was not sent")
	}
	select {
	case <-channel:
		t.Fatal("buffered event notification should coalesce")
	default:
	}
	unsubscribe()
	unsubscribe()
	app.server.notifyEvents()
	select {
	case _, open := <-channel:
		if open {
			t.Fatal("unsubscribed channel remained open")
		}
	default:
		t.Fatal("unsubscribe did not close its channel")
	}
	app.server.recordDiagnostic("warn", "warn: sanitized")
	entries := app.server.diagnosticBuffer.Snapshot(10)
	if len(entries) != 1 || entries[0].Component != "app" || entries[0].Level != "warn" {
		t.Fatalf("diagnostic buffer = %+v", entries)
	}
}

func TestSSEStopsWhenSessionExpiresAndRedactsRuntimeError(t *testing.T) {
	app := newTestApp(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	response := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	response.onFlush = func(flush int) {
		if flush == 1 {
			_ = app.server.store.DeleteAllSessions(context.Background(), app.admin.ID)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	newMux(app.server).ServeHTTP(response, request)
	cancel()
	if !strings.Contains(response.Body.String(), "event: stats") || strings.Contains(response.Body.String(), "event: status") {
		t.Fatalf("SSE continued after session removal: %s", response.Body.String())
	}
	app.server.eventsMu.Lock()
	if len(app.server.eventSubs) != 0 {
		app.server.eventsMu.Unlock()
		t.Fatal("SSE left event subscription after session expiration")
	}
	app.server.eventsMu.Unlock()

	app = newTestApp(t, true)
	app.sup.statusErr = errors.New(`connection password="hidden"`)
	ctx2, cancel2 := context.WithCancel(context.Background())
	response = &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	response.onFlush = func(flush int) {
		if flush == 2 {
			cancel2()
		}
	}
	request = httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx2)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	newMux(app.server).ServeHTTP(response, request)
	defer cancel2()
	if !strings.Contains(response.Body.String(), `"state":"unavailable"`) || strings.Contains(response.Body.String(), "hidden") {
		t.Fatalf("SSE Xray runtime error not redacted: %s", response.Body.String())
	}
}

func TestBackupRoutesListCreateAndMaintenanceLock(t *testing.T) {
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/backups", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated backups status = %d", got)
	}
	listed := requestJSON(t, app, http.MethodGet, "/api/backups", nil, true)
	if listed.Code != http.StatusOK || strings.TrimSpace(listed.Body.String()) != "[]" {
		t.Fatalf("empty backups response = %d %s", listed.Code, listed.Body.String())
	}
	created := requestJSON(t, app, http.MethodPost, "/api/backups", nil, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"name":"backup-`) {
		t.Fatalf("create backup = %d %s", created.Code, created.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPut, "/api/backups", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("PUT backups status = %d", got)
	}
	lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	lockCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	request := httptest.NewRequest(http.MethodPost, "/api/backups", nil).WithContext(lockCtx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	blocked := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(blocked, request)
	cancel()
	_ = lock.Close()
	if blocked.Code != http.StatusServiceUnavailable {
		t.Fatalf("backup while maintenance lock held = %d %s", blocked.Code, blocked.Body.String())
	}
	listed = requestJSON(t, app, http.MethodGet, "/api/backups", nil, true)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "backup-") {
		t.Fatalf("backup list after creation = %d %s", listed.Code, listed.Body.String())
	}
}

func TestReconcileRunningSynchronizesHandlerUsers(t *testing.T) {
	app := newTestApp(t, true)
	active := seedTestClient(t, app, "active")
	disabled := seedTestClient(t, app, "disabled")
	revoked := seedTestClient(t, app, "revoked")
	if err := app.server.store.SetClientState(context.Background(), disabled.ID, false, false); err != nil {
		t.Fatal(err)
	}
	if err := app.server.store.SetClientState(context.Background(), revoked.ID, false, true); err != nil {
		t.Fatal(err)
	}
	app.handler.users = []string{disabled.Email, revoked.Email, "stray@xray-easy"}
	if err := app.server.reconcileRunning(context.Background()); err != nil {
		t.Fatal(err)
	}
	app.handler.mu.Lock()
	users := append([]string(nil), app.handler.users...)
	addCalls := append([][3]string(nil), app.handler.addCall...)
	app.handler.mu.Unlock()
	if len(users) != 1 || users[0] != active.Email || len(addCalls) != 1 || addCalls[0][0] != active.Email || addCalls[0][1] != active.UUID || addCalls[0][2] != xray.Flow {
		t.Fatalf("reconciled users=%v add calls=%v", users, addCalls)
	}
	if err := app.server.store.DeleteAllSessions(context.Background(), app.admin.ID); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRunning(context.Background()); err != nil {
		t.Fatalf("empty handler roster should remain reconcilable: %v", err)
	}

	app.handler.addErr = errors.New("add failed")
	app.handler.users = nil
	if err := app.server.reconcileRunning(context.Background()); err == nil || !strings.Contains(err.Error(), "add failed") {
		t.Fatalf("AddUser failure = %v", err)
	}
	app.handler.addErr = nil
	app.handler.remove = map[string]bool{"stray@xray-easy": true}
	app.handler.users = []string{"stray@xray-easy"}
	if err := app.server.reconcileRunning(context.Background()); err == nil || !strings.Contains(err.Error(), "remove failed") {
		t.Fatalf("RemoveUser failure = %v", err)
	}
	app.handler.remove = nil
	lock, err := maintenance.Acquire(context.Background(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	reconcileCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	err = app.server.reconcileRunning(reconcileCtx)
	cancel()
	if err == nil {
		t.Fatal("reconcile ignored maintenance lock")
	}
	_ = lock.Close()
	app.server.handler = nil
	if err := app.server.reconcileRunning(context.Background()); err != nil {
		t.Fatalf("reconcile with no Xray handler = %v", err)
	}
}
