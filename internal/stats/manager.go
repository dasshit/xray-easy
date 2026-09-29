package stats

import (
	"context"
	"fmt"
	"sync"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/store"
	"xray-easy/internal/xrayapi"
)

const defaultPollInterval = 10 * time.Second
const onlineWindow = 5 * time.Minute
const telemetryCallTimeout = 5 * time.Second

// ClientStats is the UI-facing snapshot. Totals survive Xray restarts because
// Manager accumulates deltas in SQLite rather than exposing process-local
// counters directly.
type ClientStats struct {
	Online                 bool       `json:"online"`
	LastSeen               *time.Time `json:"last_seen,omitempty"`
	SourceIPs              []string   `json:"source_ips,omitempty"`
	UploadBytes            int64      `json:"upload_bytes"`
	DownloadBytes          int64      `json:"download_bytes"`
	UploadBytesPerSecond   float64    `json:"upload_bytes_per_second"`
	DownloadBytesPerSecond float64    `json:"download_bytes_per_second"`
}

// StatsAPI is the small Xray boundary needed by the polling manager.
type StatsAPI interface {
	Poll(context.Context) ([]xrayapi.UserStats, error)
}

// AWGStatsAPI reads runtime counters for the optional AmneziaWG transport.
type AWGStatsAPI interface {
	PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error)
}

type Manager struct {
	store *store.Store
	api   StatsAPI
	awg   AWGStatsAPI

	mu        sync.RWMutex
	latest    map[string]ClientStats
	subs      map[chan struct{}]struct{}
	interval  time.Duration
	lastError string
	now       func() time.Time
}

func NewManager(db *store.Store, api StatsAPI, awg ...AWGStatsAPI) *Manager {
	manager := &Manager{store: db, api: api, latest: make(map[string]ClientStats), subs: make(map[chan struct{}]struct{}), interval: defaultPollInterval, now: time.Now}
	if len(awg) > 0 {
		manager.awg = awg[0]
	}
	return manager
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		_ = m.Poll(ctx)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.Poll(ctx)
			}
		}
	}()
}

func (m *Manager) Poll(ctx context.Context) error {
	clients, err := m.store.ListClients(ctx)
	if err != nil {
		m.setError(err)
		return fmt.Errorf("list clients for stats: %w", err)
	}
	previous, err := m.store.ListTrafficSnapshots(ctx)
	if err != nil {
		m.setError(err)
		return fmt.Errorf("list traffic snapshots: %w", err)
	}
	now := m.now().UTC()
	previousLatest := m.Snapshot()
	next := make(map[string]ClientStats, len(clients))
	xrayCtx, cancelXray := context.WithTimeout(ctx, telemetryCallTimeout)
	observed, xrayErr := m.api.Poll(xrayCtx)
	cancelXray()
	if xrayErr == nil {
		if err := m.updateXray(ctx, clients, previous, observed, previousLatest, next, now); err != nil {
			m.setError(err)
			return err
		}
	} else {
		for _, client := range clients {
			if current, ok := previousLatest[client.ID]; ok {
				current.UploadBytesPerSecond, current.DownloadBytesPerSecond = 0, 0
				current.Online = current.LastSeen != nil && isOnline(*current.LastSeen, now)
				if !current.Online {
					current.SourceIPs = nil
				}
				next[client.ID] = current
			}
		}
	}
	awgErr := m.updateAWG(ctx, previousLatest, next, now)
	m.mu.Lock()
	m.latest = next
	switch {
	case xrayErr != nil && awgErr != nil:
		m.lastError = "Xray stats: " + xrayErr.Error() + "; AmneziaWG stats: " + awgErr.Error()
	case xrayErr != nil:
		m.lastError = xrayErr.Error()
	case awgErr != nil:
		m.lastError = "AmneziaWG stats: " + awgErr.Error()
	default:
		m.lastError = ""
	}
	for subscriber := range m.subs {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	m.mu.Unlock()
	if xrayErr != nil {
		return xrayErr
	}
	if awgErr != nil {
		return awgErr
	}
	return nil
}

func (m *Manager) updateXray(ctx context.Context, clients []domain.Client, previous map[string]store.TrafficSnapshot, observed []xrayapi.UserStats, previousLatest, next map[string]ClientStats, now time.Time) error {
	byEmail := make(map[string]xrayapi.UserStats, len(observed))
	for _, user := range observed {
		byEmail[user.Email] = user
	}
	for _, client := range clients {
		snapshot := previous[client.ID]
		previousPoll := snapshot.LastPolledAt
		snapshot.ClientID = client.ID
		var uploadDelta, downloadDelta int64
		var sourceIPs []string
		if user, ok := byEmail[client.Email]; ok {
			uploadDelta = counterDelta(user.UploadBytes, snapshot.RawUpload)
			downloadDelta = counterDelta(user.DownloadBytes, snapshot.RawDownload)
			snapshot.TotalUpload += uploadDelta
			snapshot.TotalDownload += downloadDelta
			snapshot.RawUpload, snapshot.RawDownload = user.UploadBytes, user.DownloadBytes
			if user.LastSeen.After(snapshot.LastSeenAt) {
				snapshot.LastSeenAt = user.LastSeen
			}
			for _, ip := range user.SourceIPs {
				if isOnline(ip.LastSeen, now) && ip.Address != "" {
					sourceIPs = appendUnique(sourceIPs, ip.Address)
				}
			}
		}
		elapsed := now.Sub(previousPoll)
		snapshot.LastPolledAt = now
		if err := m.store.UpsertTrafficSnapshot(ctx, snapshot); err != nil {
			return fmt.Errorf("save traffic snapshot for %s: %w", client.ID, err)
		}
		lastSeen := optionalTime(snapshot.LastSeenAt)
		online := isOnline(snapshot.LastSeenAt, now)
		if len(sourceIPs) == 0 {
			if old := previousLatest[client.ID]; old.Online && online {
				sourceIPs = append(sourceIPs, old.SourceIPs...)
			}
		}
		stats := ClientStats{Online: online, LastSeen: lastSeen, SourceIPs: sourceIPs, UploadBytes: snapshot.TotalUpload, DownloadBytes: snapshot.TotalDownload}
		if online && validRateWindow(elapsed, m.interval) {
			stats.UploadBytesPerSecond = bytesPerSecond(uploadDelta, elapsed)
			stats.DownloadBytesPerSecond = bytesPerSecond(downloadDelta, elapsed)
		}
		next[client.ID] = stats
	}
	return nil
}

func (m *Manager) updateAWG(ctx context.Context, previousLatest, next map[string]ClientStats, now time.Time) error {
	if m.awg == nil {
		return nil
	}
	previous, err := m.store.ListAWGTrafficSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("list AmneziaWG traffic snapshots: %w", err)
	}
	awgCtx, cancelAWG := context.WithTimeout(ctx, telemetryCallTimeout)
	observed, err := m.awg.PeerStats(awgCtx)
	cancelAWG()
	if err != nil {
		for name := range previous {
			id := "awg:" + name
			current := previousLatest[id]
			current.UploadBytesPerSecond, current.DownloadBytesPerSecond = 0, 0
			if current.LastSeen != nil {
				current.Online = isOnline(*current.LastSeen, now)
			}
			if !current.Online {
				current.SourceIPs = nil
			}
			next[id] = current
		}
		return err
	}
	for _, peer := range observed {
		if peer.Name == "" {
			continue
		}
		snapshot := previous[peer.Name]
		previousPoll := snapshot.LastPolledAt
		uploadDelta := counterDelta(peer.UploadBytes, snapshot.RawUpload)
		downloadDelta := counterDelta(peer.DownloadBytes, snapshot.RawDownload)
		snapshot.PeerName = peer.Name
		snapshot.TotalUpload += uploadDelta
		snapshot.TotalDownload += downloadDelta
		snapshot.RawUpload, snapshot.RawDownload = peer.UploadBytes, peer.DownloadBytes
		if peer.LastSeen.After(snapshot.LastSeenAt) {
			snapshot.LastSeenAt = peer.LastSeen
		}
		if peer.SourceIP != "" && !peer.LastSeen.IsZero() {
			snapshot.SourceIP = peer.SourceIP
		}
		elapsed := now.Sub(previousPoll)
		snapshot.LastPolledAt = now
		if err := m.store.UpsertAWGTrafficSnapshot(ctx, snapshot); err != nil {
			return fmt.Errorf("save AmneziaWG traffic snapshot for %s: %w", peer.Name, err)
		}
		online := isOnline(snapshot.LastSeenAt, now)
		stats := ClientStats{Online: online, LastSeen: optionalTime(snapshot.LastSeenAt), UploadBytes: snapshot.TotalUpload, DownloadBytes: snapshot.TotalDownload}
		if online && snapshot.SourceIP != "" {
			stats.SourceIPs = []string{snapshot.SourceIP}
		}
		if online && validRateWindow(elapsed, m.interval) {
			stats.UploadBytesPerSecond = bytesPerSecond(uploadDelta, elapsed)
			stats.DownloadBytesPerSecond = bytesPerSecond(downloadDelta, elapsed)
		}
		next["awg:"+peer.Name] = stats
	}
	return nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

func validRateWindow(elapsed, interval time.Duration) bool {
	return elapsed > 0 && interval > 0 && elapsed <= 3*interval
}

func bytesPerSecond(delta int64, elapsed time.Duration) float64 {
	if delta <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(delta) / elapsed.Seconds()
}

func (m *Manager) Snapshot() map[string]ClientStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copy := make(map[string]ClientStats, len(m.latest))
	for id, stats := range m.latest {
		copy[id] = stats
	}
	return copy
}

func (m *Manager) LastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

// Subscribe returns a buffered edge-triggered notification channel. Call the
// returned function when the HTTP stream exits.
func (m *Manager) Subscribe() (<-chan struct{}, func()) {
	channel := make(chan struct{}, 1)
	m.mu.Lock()
	m.subs[channel] = struct{}{}
	m.mu.Unlock()
	return channel, func() {
		m.mu.Lock()
		if _, ok := m.subs[channel]; ok {
			delete(m.subs, channel)
			close(channel)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.lastError = err.Error()
	m.mu.Unlock()
}

func counterDelta(current, previous int64) int64 {
	if current < 0 {
		return 0
	}
	if current < previous {
		return current
	}
	return current - previous
}

func isOnline(lastSeen, now time.Time) bool {
	return !lastSeen.IsZero() && !lastSeen.After(now.Add(time.Minute)) && now.Sub(lastSeen) <= onlineWindow
}
