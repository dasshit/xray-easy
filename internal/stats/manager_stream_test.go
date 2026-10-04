package stats

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	controllerv1 "xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
)

type fakeTelemetryStreamOpener struct {
	opened  atomic.Int32
	ctxs    chan context.Context
	openErr error
	recvErr error
}

func (f *fakeTelemetryStreamOpener) WatchTelemetry(ctx context.Context, _ time.Duration) (controllerv1.Controller_WatchTelemetryClient, error) {
	f.opened.Add(1)
	f.ctxs <- ctx
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeControllerTelemetryStream{ctx: ctx, recvErr: f.recvErr}, nil
}

type fakeControllerTelemetryStream struct {
	ctx     context.Context
	recvErr error
	sent    bool
}

func (s *fakeControllerTelemetryStream) Recv() (*controllerv1.TelemetryUpdate, error) {
	if !s.sent {
		s.sent = true
		return &controllerv1.TelemetryUpdate{}, nil
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *fakeControllerTelemetryStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeControllerTelemetryStream) Trailer() metadata.MD         { return nil }
func (s *fakeControllerTelemetryStream) CloseSend() error             { return nil }
func (s *fakeControllerTelemetryStream) Context() context.Context     { return s.ctx }
func (s *fakeControllerTelemetryStream) SendMsg(any) error            { return nil }
func (s *fakeControllerTelemetryStream) RecvMsg(any) error            { return io.EOF }

func TestSubscribeSharesOneTelemetryStreamUntilLastListenerLeaves(t *testing.T) {
	db, _ := openStatsTestStore(t)
	opener := &fakeTelemetryStreamOpener{ctxs: make(chan context.Context, 2)}
	manager := NewManager(db, &fakeStatsAPI{})
	manager.stream = opener
	_, unsubscribeFirst := manager.Subscribe()
	_, unsubscribeSecond := manager.Subscribe()
	defer unsubscribeFirst()
	defer unsubscribeSecond()
	var streamContext context.Context
	select {
	case streamContext = <-opener.ctxs:
	case <-time.After(time.Second):
		t.Fatal("telemetry stream was not opened for the first listener")
	}
	if got := opener.opened.Load(); got != 1 {
		t.Fatalf("upstream stream opened %d times for two listeners", got)
	}
	unsubscribeFirst()
	select {
	case <-streamContext.Done():
		t.Fatal("stream closed while one listener remained")
	default:
	}
	unsubscribeSecond()
	select {
	case <-streamContext.Done():
	case <-time.After(time.Second):
		t.Fatal("upstream stream remained open after the last listener left")
	}
}

func TestApplyStreamUpdatePersistsTotalsRatesAndRejectsReplay(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	update := func(sequence uint64, generation string, upload, download int64) *controllerv1.TelemetryUpdate {
		at := timestamppb.New(now)
		return &controllerv1.TelemetryUpdate{
			SampledAt: at, Sequence: sequence, FullSnapshot: true,
			Sources: []*controllerv1.TelemetrySourceStatus{{Protocol: "xray", Available: true, Generation: generation, Sequence: sequence, SampledAt: at}},
			Clients: []*controllerv1.TelemetryClient{{DeviceKey: "phone@example.test", Protocol: "vless", Online: true, LastActivity: at, UploadBytes: upload, DownloadBytes: download, SourceIps: []string{"198.51.100.4"}}},
		}
	}
	if err := manager.ApplyStreamUpdate(context.Background(), update(1, "runtime-a", 100, 200)); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()["phone"]
	if !first.Online || first.UploadBytes != 100 || first.DownloadBytes != 200 || len(first.SourceIPs) != 1 {
		t.Fatalf("initial stream stats = %+v", first)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), update(2, "runtime-a", 150, 260)); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()["phone"]
	if second.UploadBytes != 150 || second.DownloadBytes != 260 || second.UploadBytesPerSecond != 50 || second.DownloadBytesPerSecond != 60 {
		t.Fatalf("updated stream stats = %+v", second)
	}
	if err := manager.ApplyStreamUpdate(context.Background(), update(2, "runtime-a", 999, 999)); err != nil {
		t.Fatal(err)
	}
	replay := manager.Snapshot()["phone"]
	if replay.UploadBytes != 150 || replay.DownloadBytes != 260 {
		t.Fatalf("replayed sequence changed totals: %+v", replay)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), update(1, "runtime-b", 5, 7)); err != nil {
		t.Fatal(err)
	}
	reset := manager.Snapshot()["phone"]
	if reset.UploadBytes != 155 || reset.DownloadBytes != 267 {
		t.Fatalf("new source generation did not preserve accumulated totals: %+v", reset)
	}
	stored, err := db.ListTrafficSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stored["phone"].TotalUpload != 155 || stored["phone"].TotalDownload != 267 {
		t.Fatalf("SQLite totals = %+v", stored["phone"])
	}
}

func TestApplyStreamUpdateMapsShadowsocksUserAndComputesRates(t *testing.T) {
	db, _ := openStatsTestStore(t)
	client, err := domain.NewShadowsocksClient("ss-device", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	client.Email = "ss-device@xray-easy"
	client.ShadowsocksPasswordEnc = "encrypted"
	if err := db.CreateShadowsocksClient(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	makeUpdate := func(sequence uint64, upload, download int64, online bool) *controllerv1.TelemetryUpdate {
		activity := now
		if !online {
			activity = now.Add(-onlineWindow - time.Second)
		}
		at := timestamppb.New(now)
		return &controllerv1.TelemetryUpdate{
			SampledAt: at,
			Sources:   []*controllerv1.TelemetrySourceStatus{{Protocol: "xray", Available: true, Generation: "xray-runtime", Sequence: sequence}},
			Clients:   []*controllerv1.TelemetryClient{{DeviceKey: client.Email, Protocol: "shadowsocks", Online: online, LastActivity: timestamppb.New(activity), UploadBytes: upload, DownloadBytes: download, SourceIps: []string{"198.51.100.55"}}},
		}
	}
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(1, 10, 20, true)); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()[client.ID]
	if !first.Online || first.UploadBytes != 10 || first.DownloadBytes != 20 || len(first.SourceIPs) != 1 {
		t.Fatalf("initial Shadowsocks stream stats = %+v", first)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(2, 25, 50, true)); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()[client.ID]
	if second.UploadBytes != 25 || second.DownloadBytes != 50 || second.UploadBytesPerSecond != 15 || second.DownloadBytesPerSecond != 30 {
		t.Fatalf("updated Shadowsocks stream stats = %+v", second)
	}
}

func TestApplyStreamUpdateExpiresOnlineAndSourceIPAfterTrafficTTL(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	lastActivity := now
	manager.now = func() time.Time { return now }
	makeUpdate := func(sequence uint64, sampledAt time.Time, online bool) *controllerv1.TelemetryUpdate {
		lastActivity = sampledAt
		if !online {
			lastActivity = sampledAt.Add(-time.Second)
		}
		at := timestamppb.New(sampledAt)
		return &controllerv1.TelemetryUpdate{
			SampledAt: at,
			Sources:   []*controllerv1.TelemetrySourceStatus{{Protocol: "xray", Available: true, Generation: "runtime", Sequence: sequence}},
			Clients:   []*controllerv1.TelemetryClient{{DeviceKey: "phone@example.test", Protocol: "vmess", Online: online, LastActivity: timestamppb.New(lastActivity), UploadBytes: 50, SourceIps: []string{"2001:db8::8"}}},
		}
	}
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(1, now, true)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(onlineWindow + time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(2, now, false)); err != nil {
		t.Fatal(err)
	}
	got := manager.Snapshot()["phone"]
	if got.Online || len(got.SourceIPs) != 0 || got.UploadBytes != 50 {
		t.Fatalf("expired stream client = %+v", got)
	}
}

func TestApplyStreamUpdatePreservesCachedSourcesWhenTelemetryIsUnavailable(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.latest["phone"] = ClientStats{Online: true, LastSeen: &now, SourceIPs: []string{"198.51.100.2"}, UploadBytes: 25, DownloadBytes: 50, UploadBytesPerSecond: 5, DownloadBytesPerSecond: 10}
	manager.latest["awg:ios"] = ClientStats{Online: true, LastSeen: &now, SourceIPs: []string{"203.0.113.5"}, UploadBytes: 12, DownloadBytes: 20, UploadBytesPerSecond: 4, DownloadBytesPerSecond: 6}

	err := manager.ApplyStreamUpdate(context.Background(), &controllerv1.TelemetryUpdate{
		Sources: []*controllerv1.TelemetrySourceStatus{
			{Protocol: "xray", Available: false, Generation: "runtime", Sequence: 2},
			{Protocol: "amneziawg", Available: true, Generation: "", Sequence: 1},
			{Protocol: "unknown", Available: true, Generation: "other", Sequence: 1},
		},
		Clients: []*controllerv1.TelemetryClient{
			nil,
			{DeviceKey: "phone@example.test", Protocol: "vless", UploadBytes: -1},
			{DeviceKey: "unknown@example.test", Protocol: "vless", UploadBytes: 2},
			{DeviceKey: "phone@example.test", Protocol: "unsupported", UploadBytes: 4},
			{DeviceKey: "awg:ignored", Protocol: "amneziawg", UploadBytes: 4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := manager.Snapshot()
	if !got["phone"].Online || got["phone"].UploadBytes != 25 || got["phone"].UploadBytesPerSecond != 0 || len(got["phone"].SourceIPs) != 1 {
		t.Fatalf("cached Xray stats after source failure = %+v", got["phone"])
	}
	if !got["awg:ios"].Online || got["awg:ios"].UploadBytes != 12 || got["awg:ios"].UploadBytesPerSecond != 0 || got["awg:ios"].SourceIPs[0] != "203.0.113.5" {
		t.Fatalf("cached AWG stats after source failure = %+v", got["awg:ios"])
	}
	if manager.LastError() != "xray telemetry is unavailable" {
		t.Fatalf("unavailable source error = %q", manager.LastError())
	}
	if err := manager.ApplyStreamUpdate(context.Background(), nil); err == nil {
		t.Fatal("nil telemetry update was accepted")
	}
}

func TestApplyStreamUpdateRetainsStaleStatsAndCoalescesNotifications(t *testing.T) {
	db, _ := openStatsTestStore(t)
	createStatsClient(t, db, "phone", "phone@example.test")
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Now().UTC()
	stale := now.Add(-onlineWindow - time.Second)
	manager.latest["phone"] = ClientStats{Online: true, LastSeen: &stale, SourceIPs: []string{"198.51.100.2"}, UploadBytes: 40, UploadBytesPerSecond: 5}
	manager.latest["awg:ios"] = ClientStats{Online: true, LastSeen: &stale, SourceIPs: []string{"203.0.113.4"}, UploadBytes: 25, UploadBytesPerSecond: 3}
	notifications, unsubscribe := manager.Subscribe()
	defer unsubscribe()
	update := &controllerv1.TelemetryUpdate{Sources: []*controllerv1.TelemetrySourceStatus{
		nil,
		{Protocol: "xray", Available: false},
		{Protocol: "amneziawg", Available: false},
	}}
	for range 2 {
		if err := manager.ApplyStreamUpdate(context.Background(), update); err != nil {
			t.Fatal(err)
		}
	}
	if len(notifications) != 1 {
		t.Fatalf("coalesced notification count = %d, want 1", len(notifications))
	}
	if got := manager.Snapshot(); got["phone"].Online || len(got["phone"].SourceIPs) != 0 || got["awg:ios"].Online || len(got["awg:ios"].SourceIPs) != 0 {
		t.Fatalf("stale clients retained online/source state: %+v", got)
	}
	if got := manager.LastError(); got != "xray telemetry is unavailable; amneziawg telemetry is unavailable" {
		t.Fatalf("combined source error = %q", got)
	}
}

func TestApplyStreamUpdateReturnsTrafficSnapshotReadAndWriteFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		statement string
		wantError string
	}{
		{"read", "DROP TABLE traffic_snapshots", "list traffic snapshots"},
		{"write", "CREATE TRIGGER reject_stream_snapshot BEFORE INSERT ON traffic_snapshots BEGIN SELECT RAISE(ABORT, 'stream snapshot write failed'); END", "save traffic snapshot for phone"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, path := openStatsTestStore(t)
			createStatsClient(t, db, "phone", "phone@example.test")
			execStatsSQL(t, path, test.statement)
			manager := NewManager(db, &fakeStatsAPI{})
			at := timestamppb.New(time.Now().UTC())
			update := &controllerv1.TelemetryUpdate{
				Sources: []*controllerv1.TelemetrySourceStatus{{Protocol: "xray", Available: true, Generation: "runtime", Sequence: 1}},
				Clients: []*controllerv1.TelemetryClient{{DeviceKey: "phone@example.test", Protocol: "vless", Online: true, LastActivity: at, UploadBytes: 1}},
			}
			if err := manager.ApplyStreamUpdate(context.Background(), update); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ApplyStreamUpdate() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestApplyStreamUpdateReturnsAWGSnapshotStorageFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		statement string
		wantError string
	}{
		{"read", "DROP TABLE awg_traffic_snapshots", "list AmneziaWG traffic snapshots"},
		{"write", "CREATE TRIGGER reject_stream_awg BEFORE INSERT ON awg_traffic_snapshots BEGIN SELECT RAISE(ABORT, 'stream AWG write failed'); END", "save AmneziaWG traffic snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, path := openStatsTestStore(t)
			execStatsSQL(t, path, test.statement)
			manager := NewManager(db, &fakeStatsAPI{})
			at := timestamppb.New(time.Now().UTC())
			update := &controllerv1.TelemetryUpdate{
				Sources: []*controllerv1.TelemetrySourceStatus{{Protocol: "amneziawg", Available: true, Generation: "awg-runtime", Sequence: 1}},
				Clients: []*controllerv1.TelemetryClient{{DeviceKey: "awg:ios", Protocol: "amneziawg", Online: true, LastActivity: at, UploadBytes: 1}},
			}
			if err := manager.ApplyStreamUpdate(context.Background(), update); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("ApplyStreamUpdate() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestAWGObservationFilteringAndCachedStatusExpiry(t *testing.T) {
	db, _ := openStatsTestStore(t)
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Now().UTC()
	next := make(map[string]ClientStats)
	if err := manager.updateAWGObserved(context.Background(), nil, next, now, []domain.AmneziaWGPeerStats{{Name: ""}}); err != nil {
		t.Fatalf("empty peer name caused a persistence error: %v", err)
	}
	stale := now.Add(-onlineWindow - time.Second)
	preserveAWGStats(next, map[string]ClientStats{
		"awg:stale": {Online: true, LastSeen: &stale, SourceIPs: []string{"203.0.113.8"}},
		"vless":     {Online: true, LastSeen: &stale, SourceIPs: []string{"198.51.100.4"}},
	}, now)
	if stats := next["awg:stale"]; stats.Online || len(stats.SourceIPs) != 0 {
		t.Fatalf("stale AWG status was retained: %+v", stats)
	}
	if _, ok := next["vless"]; ok {
		t.Fatal("preserveAWGStats copied a non-AWG profile")
	}
}

func TestApplyStreamUpdateMapsAWGPeerAndComputesRates(t *testing.T) {
	db, _ := openStatsTestStore(t)
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	makeUpdate := func(sequence uint64, upload, download int64, online bool) *controllerv1.TelemetryUpdate {
		lastActivity := now
		if !online {
			// The source's online flag is authoritative. A small clock/sample
			// skew can leave last_activity inside the backend's local TTL.
			lastActivity = now.Add(-time.Second)
		}
		return &controllerv1.TelemetryUpdate{
			SampledAt: timestamppb.New(now),
			Sources:   []*controllerv1.TelemetrySourceStatus{{Protocol: "amneziawg", Available: true, Generation: "awg-runtime", Sequence: sequence}},
			Clients:   []*controllerv1.TelemetryClient{{DeviceKey: "awg:ios", Protocol: "amneziawg", Online: online, UploadBytes: upload, DownloadBytes: download, LastActivity: timestamppb.New(lastActivity), SourceIps: []string{"203.0.113.9"}}},
		}
	}
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(1, 30, 60, true)); err != nil {
		t.Fatal(err)
	}
	first := manager.Snapshot()["awg:ios"]
	if !first.Online || first.UploadBytes != 30 || first.DownloadBytes != 60 || len(first.SourceIPs) != 1 || first.SourceIPs[0] != "203.0.113.9" {
		t.Fatalf("first AWG stream stats = %+v", first)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(2, 50, 90, true)); err != nil {
		t.Fatal(err)
	}
	second := manager.Snapshot()["awg:ios"]
	if second.UploadBytes != 50 || second.DownloadBytes != 90 || second.UploadBytesPerSecond != 20 || second.DownloadBytesPerSecond != 30 {
		t.Fatalf("updated AWG stream stats = %+v", second)
	}

	manager.latest["unrelated"] = ClientStats{Online: true}
	manager.latest["awg:stale"] = ClientStats{Online: false, SourceIPs: []string{"203.0.113.10"}}
	now = now.Add(onlineWindow + time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(3, 50, 90, false)); err != nil {
		t.Fatal(err)
	}
	last := manager.Snapshot()["awg:ios"]
	if last.Online || len(last.SourceIPs) != 0 || last.UploadBytes != 50 {
		t.Fatalf("offline AWG stream stats = %+v", last)
	}
}

func TestApplyStreamUpdateKeepsAWGOfflineStatusAcrossOtherSourceUpdates(t *testing.T) {
	db, _ := openStatsTestStore(t)
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	makeUpdate := func(xraySequence, awgSequence uint64, online bool) *controllerv1.TelemetryUpdate {
		lastActivity := now
		if !online {
			lastActivity = now.Add(-time.Second)
		}
		return &controllerv1.TelemetryUpdate{
			SampledAt: timestamppb.New(now),
			Sources: []*controllerv1.TelemetrySourceStatus{
				{Protocol: "xray", Available: true, Generation: "xray-runtime", Sequence: xraySequence},
				{Protocol: "amneziawg", Available: true, Generation: "awg-runtime", Sequence: awgSequence},
			},
			Clients: []*controllerv1.TelemetryClient{{DeviceKey: "awg:ios", Protocol: "amneziawg", Online: online, LastActivity: timestamppb.New(lastActivity), SourceIps: []string{"203.0.113.9"}}},
		}
	}
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(1, 1, true)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(2, 2, false)); err != nil {
		t.Fatal(err)
	}
	if got := manager.Snapshot()["awg:ios"]; got.Online {
		t.Fatalf("AWG source offline status was ignored: %+v", got)
	}
	now = now.Add(time.Second)
	if err := manager.ApplyStreamUpdate(context.Background(), makeUpdate(3, 2, false)); err != nil {
		t.Fatal(err)
	}
	got := manager.Snapshot()["awg:ios"]
	if got.Online || len(got.SourceIPs) != 0 {
		t.Fatalf("AWG offline status was lost on an Xray-only update: %+v", got)
	}
}

func TestConsumeTelemetryStreamReportsOpenAndReceiveFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		open error
		recv error
	}{
		{name: "open", open: errors.New("controller unavailable")},
		{name: "receive", recv: errors.New("stream interrupted")},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _ := openStatsTestStore(t)
			stream := &fakeTelemetryStreamOpener{ctxs: make(chan context.Context, 1), openErr: test.open, recvErr: test.recv}
			manager := NewManager(db, &fakeStatsAPI{})
			manager.stream = stream
			notifications, unsubscribe := manager.Subscribe()
			defer unsubscribe()
			select {
			case <-stream.ctxs:
			case <-time.After(time.Second):
				t.Fatal("stream manager did not attempt to open its upstream")
			}
			timeout := time.NewTimer(time.Second)
			defer timeout.Stop()
			for manager.LastError() == "" {
				select {
				case <-notifications:
				case <-timeout.C:
					t.Fatal("stream failure did not notify subscribers")
				}
			}
			if manager.LastError() != "live telemetry stream is unavailable" {
				t.Fatalf("stream failure state = %q", manager.LastError())
			}
		})
	}
}

func TestConsumeTelemetryStreamAdvancesRetryBackoff(t *testing.T) {
	db, _ := openStatsTestStore(t)
	stream := &fakeTelemetryStreamOpener{ctxs: make(chan context.Context, 2), openErr: errors.New("controller unavailable")}
	manager := NewManager(db, &fakeStatsAPI{})
	manager.stream = stream
	var delays []time.Duration
	manager.retryWait = func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return len(delays) == 1
	}
	manager.consumeTelemetryStream(context.Background())
	if len(delays) != 2 || delays[0] != time.Second || delays[1] != 2*time.Second {
		t.Fatalf("telemetry stream retry delays = %v, want [1s 2s]", delays)
	}
	if !waitTelemetryRetry(context.Background(), time.Millisecond) {
		t.Fatal("waitTelemetryRetry did not return after its timer fired")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if waitTelemetryRetry(canceled, time.Hour) {
		t.Fatal("waitTelemetryRetry returned true for a canceled context")
	}
}

func TestMarkStreamErrorExpiresStaleClientsAndNotifiesSubscribers(t *testing.T) {
	db, _ := openStatsTestStore(t)
	manager := NewManager(db, &fakeStatsAPI{})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	fresh := now.Add(-time.Second)
	stale := now.Add(-onlineWindow - time.Second)
	manager.latest = map[string]ClientStats{
		"fresh":   {Online: true, LastSeen: &fresh, SourceIPs: []string{"198.51.100.1"}, UploadBytesPerSecond: 5, DownloadBytesPerSecond: 8},
		"stale":   {Online: true, LastSeen: &stale, SourceIPs: []string{"198.51.100.2"}, UploadBytesPerSecond: 3, DownloadBytesPerSecond: 4},
		"unknown": {Online: false, SourceIPs: []string{"198.51.100.3"}, UploadBytesPerSecond: 1, DownloadBytesPerSecond: 2},
	}
	notifications, unsubscribe := manager.Subscribe()
	defer unsubscribe()
	manager.markStreamError(nil)
	if manager.LastError() != "" {
		t.Fatalf("nil stream error changed status: %q", manager.LastError())
	}
	manager.markStreamError(errors.New("sensitive transport detail"))
	manager.markStreamError(errors.New("another transport detail"))
	select {
	case <-notifications:
	default:
		t.Fatal("stream failure did not notify SSE listeners")
	}
	got := manager.Snapshot()
	if !got["fresh"].Online || got["fresh"].UploadBytesPerSecond != 0 || len(got["fresh"].SourceIPs) != 1 {
		t.Fatalf("fresh client after stream failure = %+v", got["fresh"])
	}
	if got["stale"].Online || got["stale"].UploadBytesPerSecond != 0 || len(got["stale"].SourceIPs) != 0 {
		t.Fatalf("stale client after stream failure = %+v", got["stale"])
	}
	if got["unknown"].Online || got["unknown"].DownloadBytesPerSecond != 0 || len(got["unknown"].SourceIPs) != 0 {
		t.Fatalf("client without last-seen after stream failure = %+v", got["unknown"])
	}
	if manager.LastError() != "live telemetry stream is unavailable" {
		t.Fatalf("stream error leaked details: %q", manager.LastError())
	}
}

func TestProtobufTimestampRejectsNilAndInvalidValues(t *testing.T) {
	if got := protobufTimestamp(nil); !got.IsZero() {
		t.Fatalf("nil protobuf timestamp = %v, want zero time", got)
	}
	if got := protobufTimestamp(&timestamppb.Timestamp{Seconds: 999999999999}); !got.IsZero() {
		t.Fatalf("invalid protobuf timestamp = %v, want zero time", got)
	}
	want := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if got := protobufTimestamp(timestamppb.New(want)); !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("valid protobuf timestamp = %v, want UTC %v", got, want)
	}
}
