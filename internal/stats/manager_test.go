package stats

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/store"
	"xray-easy/internal/xrayapi"
)

type fakeStatsAPI struct {
	mu    sync.Mutex
	users []xrayapi.UserStats
	err   error
	calls int
}

func (f *fakeStatsAPI) Poll(context.Context) ([]xrayapi.UserStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return append([]xrayapi.UserStats(nil), f.users...), f.err
}

func (f *fakeStatsAPI) set(users []xrayapi.UserStats, err error) {
	f.mu.Lock()
	f.users, f.err = append([]xrayapi.UserStats(nil), users...), err
	f.mu.Unlock()
}

func (f *fakeStatsAPI) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func openStatsTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stats.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Initialize(context.Background(), "admin", "hash", "vpn.example.com", 443); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func createStatsClient(t *testing.T, db *store.Store, id, email string) {
	t.Helper()
	err := db.CreateClient(context.Background(), domain.Client{ID: id, Name: "device-" + id, Enabled: true}, "uuid-"+id, email, "short-"+id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPollAccumulatesCountersAcrossRestartsAndKeepsLastSeen(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	createStatsClient(t, db, "tablet", "tablet@example.test")
	api := &fakeStatsAPI{}
	manager := NewManager(db, api)
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	lastSeen := now.Add(-4 * time.Minute)
	api.set([]xrayapi.UserStats{
		{Email: "phone@example.test", UploadBytes: 100, DownloadBytes: 200, LastSeen: lastSeen},
		{Email: "unknown@example.test", UploadBytes: 500, DownloadBytes: 900},
	}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()
	if got := first["phone"]; !got.Online || got.UploadBytes != 100 || got.DownloadBytes != 200 || got.LastSeen == nil || !got.LastSeen.Equal(lastSeen) {
		t.Fatalf("first phone stats = %+v", got)
	}
	if got := first["tablet"]; got.Online || got.UploadBytes != 0 || got.DownloadBytes != 0 || got.LastSeen != nil {
		t.Fatalf("device without traffic stats = %+v", got)
	}
	first["phone"] = ClientStats{UploadBytes: -1}
	if got := manager.Snapshot()["phone"]; got.UploadBytes != 100 {
		t.Fatalf("Snapshot exposed internal map: %+v", got)
	}

	now = now.Add(10 * time.Second)
	api.set([]xrayapi.UserStats{{Email: "phone@example.test", UploadBytes: 120, DownloadBytes: 250, LastSeen: lastSeen.Add(-time.Second)}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()["phone"]
	if second.UploadBytes != 120 || second.DownloadBytes != 250 || second.LastSeen == nil || !second.LastSeen.Equal(lastSeen) {
		t.Fatalf("monotonic snapshot = %+v", second)
	}

	// Xray's process-local counters have restarted and are now lower than the
	// previous raw sample. The manager adds the post-restart values to totals.
	now = now.Add(10 * time.Second)
	newLastSeen := now.Add(-2 * time.Minute)
	api.set([]xrayapi.UserStats{{Email: "phone@example.test", UploadBytes: 5, DownloadBytes: 7, LastSeen: newLastSeen}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	third := manager.Snapshot()["phone"]
	if third.UploadBytes != 125 || third.DownloadBytes != 257 || third.LastSeen == nil || !third.LastSeen.Equal(newLastSeen) {
		t.Fatalf("post-restart stats = %+v", third)
	}
	if got := manager.LastError(); got != "" {
		t.Fatalf("successful poll left error %q", got)
	}

	now = now.Add(10 * time.Minute)
	api.set(nil, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	stale := manager.Snapshot()["phone"]
	if stale.Online || stale.UploadBytes != 125 || stale.DownloadBytes != 257 || stale.LastSeen == nil || !stale.LastSeen.Equal(newLastSeen) {
		t.Fatalf("stats after user disappears from Xray poll = %+v", stale)
	}
	snapshots, err := db.ListTrafficSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshots["phone"].RawUpload != 5 || snapshots["phone"].TotalUpload != 125 || !snapshots["phone"].LastPolledAt.Equal(now) {
		t.Fatalf("durable snapshot = %+v", snapshots["phone"])
	}
}

func TestPollNotifiesSubscribersAndCoalescesUpdates(t *testing.T) {
	db, _ := openStatsTestStore(t)
	api := &fakeStatsAPI{}
	manager := NewManager(db, api)
	channel, unsubscribe := manager.Subscribe()
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(channel) != 1 {
		t.Fatalf("edge-triggered channel queued %d events, want one", len(channel))
	}
	<-channel
	unsubscribe()
	unsubscribe()
	if _, ok := <-channel; ok {
		t.Fatal("unsubscribed channel was not closed")
	}
	if len(manager.subs) != 0 {
		t.Fatalf("subscriber was retained after unsubscribe: %d", len(manager.subs))
	}
}

func TestPollRecordsAndClearsStoreAndAPIErrors(t *testing.T) {
	t.Run("list clients", func(t *testing.T) {
		db, _ := openStatsTestStore(t)
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		api := &fakeStatsAPI{}
		manager := NewManager(db, api)
		if err := manager.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "list clients for stats") {
			t.Fatalf("Poll error = %v", err)
		}
		if manager.LastError() == "" || api.callCount() != 0 {
			t.Fatalf("store error state=%q api calls=%d", manager.LastError(), api.callCount())
		}
	})
	t.Run("Xray API", func(t *testing.T) {
		db, _ := openStatsTestStore(t)
		api := &fakeStatsAPI{err: errors.New("StatsService unavailable")}
		manager := NewManager(db, api)
		if err := manager.Poll(context.Background()); err == nil || err.Error() != "StatsService unavailable" {
			t.Fatalf("Poll error = %v", err)
		}
		if manager.LastError() != "StatsService unavailable" {
			t.Fatalf("LastError = %q", manager.LastError())
		}
	})
	t.Run("snapshot query", func(t *testing.T) {
		db, path := openStatsTestStore(t)
		createStatsClient(t, db, "phone", "phone@example.test")
		adminDB, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adminDB.Exec(`DROP TABLE traffic_snapshots`); err != nil {
			t.Fatal(err)
		}
		_ = adminDB.Close()
		manager := NewManager(db, &fakeStatsAPI{})
		if err := manager.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "list traffic snapshots") {
			t.Fatalf("Poll error = %v", err)
		}
		if manager.LastError() == "" {
			t.Fatal("snapshot query error was not retained")
		}
	})
	t.Run("snapshot write", func(t *testing.T) {
		db, path := openStatsTestStore(t)
		createStatsClient(t, db, "phone", "phone@example.test")
		adminDB, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adminDB.Exec(`CREATE TRIGGER reject_snapshot BEFORE INSERT ON traffic_snapshots BEGIN SELECT RAISE(ABORT, 'forced write failure'); END`); err != nil {
			t.Fatal(err)
		}
		_ = adminDB.Close()
		manager := NewManager(db, &fakeStatsAPI{})
		if err := manager.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "save traffic snapshot for phone") {
			t.Fatalf("Poll error = %v", err)
		}
		if manager.LastError() == "" {
			t.Fatal("snapshot write error was not retained")
		}
	})
}

func TestStartPollsImmediatelyAndOnIntervalUntilCanceled(t *testing.T) {
	db, _ := openStatsTestStore(t)
	api := &fakeStatsAPI{}
	manager := NewManager(db, api)
	manager.interval = 5 * time.Millisecond
	channel, unsubscribe := manager.Subscribe()
	defer unsubscribe()
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	defer cancel()
	deadline := time.After(time.Second)
	for api.callCount() < 2 {
		select {
		case <-channel:
		case <-deadline:
			t.Fatal("manager did not poll on its interval")
		}
	}
	cancel()
	calls := api.callCount()
	time.Sleep(20 * time.Millisecond)
	if got := api.callCount(); got != calls {
		t.Fatalf("poll loop continued after cancellation: calls %d -> %d", calls, got)
	}
}

func TestCounterDeltaAndOnlineWindowBoundaries(t *testing.T) {
	for _, test := range []struct{ current, previous, want int64 }{
		{-1, 10, 0}, {0, 0, 0}, {10, 4, 6}, {4, 10, 4},
	} {
		if got := counterDelta(test.current, test.previous); got != test.want {
			t.Errorf("counterDelta(%d, %d) = %d, want %d", test.current, test.previous, got, test.want)
		}
	}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name     string
		lastSeen time.Time
		want     bool
	}{
		{"zero", time.Time{}, false},
		{"online boundary", now.Add(-onlineWindow), true},
		{"expired", now.Add(-onlineWindow - time.Second), false},
		{"future within clock tolerance", now.Add(time.Minute), true},
		{"future beyond clock tolerance", now.Add(time.Minute + time.Second), false},
	} {
		if got := isOnline(test.lastSeen, now); got != test.want {
			t.Errorf("isOnline %s = %v, want %v", test.name, got, test.want)
		}
	}
}
