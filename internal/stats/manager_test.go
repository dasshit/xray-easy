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

type fakeAWGStatsAPI struct {
	peers []domain.AmneziaWGPeerStats
	err   error
}

func (f *fakeAWGStatsAPI) PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error) {
	return append([]domain.AmneziaWGPeerStats(nil), f.peers...), f.err
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
		{Email: "phone@example.test", UploadBytes: 100, DownloadBytes: 200, LastSeen: lastSeen, SourceIPs: []xrayapi.IPObservation{{Address: "198.51.100.12", LastSeen: lastSeen}}},
		{Email: "unknown@example.test", UploadBytes: 500, DownloadBytes: 900},
	}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()
	if got := first["phone"]; !got.Online || got.UploadBytes != 100 || got.DownloadBytes != 200 || got.LastSeen == nil || !got.LastSeen.Equal(now) {
		t.Fatalf("first phone stats = %+v", got)
	}
	if len(first["phone"].SourceIPs) != 1 || first["phone"].SourceIPs[0] != "198.51.100.12" || first["phone"].UploadBytesPerSecond != 0 {
		t.Fatalf("first phone source/rate = %+v", first["phone"])
	}
	if got := first["tablet"]; got.Online || got.UploadBytes != 0 || got.DownloadBytes != 0 || got.LastSeen != nil {
		t.Fatalf("device without traffic stats = %+v", got)
	}
	first["phone"] = ClientStats{UploadBytes: -1}
	if got := manager.Snapshot()["phone"]; got.UploadBytes != 100 {
		t.Fatalf("Snapshot exposed internal map: %+v", got)
	}

	now = now.Add(10 * time.Second)
	api.set([]xrayapi.UserStats{{Email: "phone@example.test", UploadBytes: 120, DownloadBytes: 250, LastSeen: lastSeen.Add(-time.Second), SourceIPs: []xrayapi.IPObservation{{Address: "198.51.100.12", LastSeen: lastSeen}}}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()["phone"]
	if second.UploadBytes != 120 || second.DownloadBytes != 250 || second.LastSeen == nil || !second.LastSeen.Equal(now) {
		t.Fatalf("monotonic snapshot = %+v", second)
	}
	if second.UploadBytesPerSecond != 2 || second.DownloadBytesPerSecond != 5 || len(second.SourceIPs) != 1 {
		t.Fatalf("sampled traffic/source IP = %+v", second)
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
	if third.UploadBytes != 125 || third.DownloadBytes != 257 || third.LastSeen == nil || !third.LastSeen.Equal(now) {
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
	if stale.Online || stale.UploadBytes != 125 || stale.DownloadBytes != 257 || stale.LastSeen == nil {
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

func TestPollDeduplicatesActiveSourceIPObservations(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	api := &fakeStatsAPI{}
	manager := NewManager(db, api)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	api.set([]xrayapi.UserStats{{
		Email: "phone@example.test", LastSeen: now,
		SourceIPs: []xrayapi.IPObservation{
			{Address: "198.51.100.1", LastSeen: now},
			{Address: "198.51.100.1", LastSeen: now.Add(-time.Second)},
			{Address: "2001:db8::1", LastSeen: now},
		},
	}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := manager.Snapshot()["phone"].SourceIPs
	if len(got) != 2 || got[0] != "198.51.100.1" || got[1] != "2001:db8::1" {
		t.Fatalf("source IP observations were not deduplicated in order: %v", got)
	}
}

func TestPollKeepsFreshCachedStatsWhenXrayTemporarilyFails(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	api := &fakeStatsAPI{}
	manager := NewManager(db, api)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	lastSeen := now.Add(-time.Minute)
	api.set([]xrayapi.UserStats{{
		Email: "phone@example.test", UploadBytes: 30, LastSeen: lastSeen,
		SourceIPs: []xrayapi.IPObservation{{Address: "198.51.100.9", LastSeen: lastSeen}},
	}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	now = now.Add(10 * time.Second)
	api.set(nil, errors.New("temporary StatsService outage"))
	if err := manager.Poll(context.Background()); err == nil {
		t.Fatal("Xray stats outage was not returned")
	}
	got := manager.Snapshot()["phone"]
	if !got.Online || got.UploadBytes != 30 || got.UploadBytesPerSecond != 0 || len(got.SourceIPs) != 1 || got.SourceIPs[0] != "198.51.100.9" {
		t.Fatalf("fresh cached connection details were not preserved with rates cleared: %+v", got)
	}
	if !strings.Contains(manager.LastError(), "StatsService outage") {
		t.Fatalf("Xray stats error was not reported: %q", manager.LastError())
	}

	now = now.Add(onlineWindow + time.Second)
	if err := manager.Poll(context.Background()); err == nil {
		t.Fatal("continued Xray stats outage was not returned")
	}
	stale := manager.Snapshot()["phone"]
	if stale.Online || len(stale.SourceIPs) != 0 || stale.UploadBytes != 30 {
		t.Fatalf("stale cached stats retained active connection details: %+v", stale)
	}
}

func TestAWGStatsAreComposedPersistedAndRateLimitedToFreshPolls(t *testing.T) {
	db, _ := openStatsTestStore(t)
	xray := &fakeStatsAPI{}
	awg := &fakeAWGStatsAPI{}
	manager := NewManager(db, xray, awg)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	awg.peers = []domain.AmneziaWGPeerStats{{Name: "iphone", SourceIP: "203.0.113.7", LastSeen: now.Add(-30 * time.Second), UploadBytes: 100, DownloadBytes: 250}}
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()["awg:iphone"]
	if !first.Online || first.UploadBytes != 100 || first.DownloadBytes != 250 || first.LastSeen == nil || first.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("initial AWG telemetry = %+v", first)
	}
	if first.UploadBytesPerSecond != 0 || first.DownloadBytesPerSecond != 0 {
		t.Fatalf("initial sample should not infer a rate: %+v", first)
	}

	now = now.Add(10 * time.Second)
	awg.peers[0] = domain.AmneziaWGPeerStats{Name: "iphone", SourceIP: "203.0.113.7", LastSeen: now.Add(-time.Second), UploadBytes: 150, DownloadBytes: 310}
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()["awg:iphone"]
	if second.UploadBytes != 150 || second.DownloadBytes != 310 || second.UploadBytesPerSecond != 5 || second.DownloadBytesPerSecond != 6 {
		t.Fatalf("second AWG sample = %+v", second)
	}

	// A fresh control-plane manager detects the engine counter reset while
	// preserving the cumulative counters in SQLite.
	now = now.Add(10 * time.Second)
	awg.peers[0] = domain.AmneziaWGPeerStats{Name: "iphone", SourceIP: "203.0.113.8", LastSeen: now.Add(-time.Second), UploadBytes: 10, DownloadBytes: 20}
	restarted := NewManager(db, xray, awg)
	restarted.now = func() time.Time { return now }
	if err := restarted.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	third := restarted.Snapshot()["awg:iphone"]
	if third.UploadBytes != 160 || third.DownloadBytes != 330 || third.SourceIPs[0] != "203.0.113.8" || third.UploadBytesPerSecond != 1 || third.DownloadBytesPerSecond != 2 {
		t.Fatalf("post-restart AWG sample = %+v", third)
	}
	if err := db.DeleteAWGTrafficSnapshot(context.Background(), "iphone"); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := db.ListAWGTrafficSnapshots(context.Background())
	if err != nil || len(checkpoints) != 0 {
		t.Fatalf("revoked AWG stats checkpoints = %+v, %v", checkpoints, err)
	}
}

func TestAWGTrafficKeepsPeerOnlineWhenHandshakeIsStale(t *testing.T) {
	db, _ := openStatsTestStore(t)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	staleHandshake := now.Add(-onlineWindow - time.Minute)
	if err := db.UpsertAWGTrafficSnapshot(context.Background(), store.AWGTrafficSnapshot{
		PeerName: "iphone", RawUpload: 1000, RawDownload: 2000,
		TotalUpload: 100, TotalDownload: 200, LastSeenAt: staleHandshake,
		LastPolledAt: now.Add(-10 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	awg := &fakeAWGStatsAPI{peers: []domain.AmneziaWGPeerStats{{
		Name: "iphone", SourceIP: "203.0.113.7", LastSeen: staleHandshake,
		UploadBytes: 1060, DownloadBytes: 2070,
	}}}
	manager := NewManager(db, &fakeStatsAPI{}, awg)
	manager.now = func() time.Time { return now }
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := manager.Snapshot()["awg:iphone"]
	if !got.Online || got.LastSeen == nil || !got.LastSeen.Equal(now) {
		t.Fatalf("peer with fresh traffic and stale handshake should be online with sampled last-seen: %+v", got)
	}
	if got.UploadBytes != 160 || got.DownloadBytes != 270 || got.UploadBytesPerSecond != 6 || got.DownloadBytesPerSecond != 7 {
		t.Fatalf("AWG counters/rates did not advance from the observed deltas: %+v", got)
	}
	if len(got.SourceIPs) != 1 || got.SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("active peer source IP was not retained: %+v", got)
	}
}

func TestAWGStatsFailureDoesNotBlockXrayAndStalePeersLoseSourceIP(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	xray := &fakeStatsAPI{}
	awg := &fakeAWGStatsAPI{peers: []domain.AmneziaWGPeerStats{{
		Name: "iphone", SourceIP: "203.0.113.7", LastSeen: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC), UploadBytes: 10, DownloadBytes: 20,
	}}}
	manager := NewManager(db, xray, awg)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	xray.set([]xrayapi.UserStats{{Email: "phone@example.test", UploadBytes: 100, LastSeen: now}}, nil)
	if err := manager.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	now = now.Add(10 * time.Second)
	xray.set([]xrayapi.UserStats{{Email: "phone@example.test", UploadBytes: 125, LastSeen: now}}, nil)
	awg.err = errors.New("AWG telemetry unavailable")
	if err := manager.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "AWG telemetry unavailable") {
		t.Fatalf("AWG failure poll error = %v", err)
	}
	current := manager.Snapshot()
	if current["phone"].UploadBytes != 125 || current["phone"].UploadBytesPerSecond != 2.5 {
		t.Fatalf("Xray stats were lost after AWG failure: %+v", current["phone"])
	}
	if !current["awg:iphone"].Online || current["awg:iphone"].UploadBytesPerSecond != 0 || current["awg:iphone"].SourceIPs[0] != "203.0.113.7" {
		t.Fatalf("AWG failure should retain fresh status, clear rates, and preserve source IP: %+v", current["awg:iphone"])
	}

	now = now.Add(onlineWindow + time.Second)
	if err := manager.Poll(context.Background()); err == nil {
		t.Fatal("persistent AWG failure was not returned")
	}
	stale := manager.Snapshot()["awg:iphone"]
	if stale.Online || len(stale.SourceIPs) != 0 || stale.UploadBytesPerSecond != 0 {
		t.Fatalf("stale AWG status retained active connection details: %+v", stale)
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
	done := manager.Start(ctx)
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.After(time.Second)
	for api.callCount() < 2 {
		select {
		case <-channel:
		case <-deadline:
			t.Fatal("manager did not poll on its interval")
		}
	}
	cancel()
	<-done
	calls := api.callCount()
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
