package stats

import (
	"context"
	"fmt"
	"sync"
	"time"

	"xray-easy/internal/store"
	"xray-easy/internal/xrayapi"
)

const defaultPollInterval = 30 * time.Second
const onlineWindow = 5 * time.Minute

// ClientStats is the UI-facing snapshot. Totals survive Xray restarts because
// Manager accumulates deltas in SQLite rather than exposing process-local
// counters directly.
type ClientStats struct {
	Online        bool       `json:"online"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	UploadBytes   int64      `json:"upload_bytes"`
	DownloadBytes int64      `json:"download_bytes"`
}

type Manager struct {
	store *store.Store
	api   *xrayapi.StatsClient

	mu        sync.RWMutex
	latest    map[string]ClientStats
	subs      map[chan struct{}]struct{}
	interval  time.Duration
	lastError string
}

func NewManager(db *store.Store, api *xrayapi.StatsClient) *Manager {
	return &Manager{store: db, api: api, latest: make(map[string]ClientStats), subs: make(map[chan struct{}]struct{}), interval: defaultPollInterval}
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
	observed, err := m.api.Poll(ctx)
	if err != nil {
		m.setError(err)
		return err
	}
	byEmail := make(map[string]xrayapi.UserStats, len(observed))
	for _, user := range observed {
		byEmail[user.Email] = user
	}
	previous, err := m.store.ListTrafficSnapshots(ctx)
	if err != nil {
		m.setError(err)
		return fmt.Errorf("list traffic snapshots: %w", err)
	}
	now := time.Now().UTC()
	next := make(map[string]ClientStats, len(clients))
	for _, client := range clients {
		snapshot := previous[client.ID]
		snapshot.ClientID = client.ID
		if user, ok := byEmail[client.Email]; ok {
			snapshot.TotalUpload += counterDelta(user.UploadBytes, snapshot.RawUpload)
			snapshot.TotalDownload += counterDelta(user.DownloadBytes, snapshot.RawDownload)
			snapshot.RawUpload, snapshot.RawDownload = user.UploadBytes, user.DownloadBytes
			if user.LastSeen.After(snapshot.LastSeenAt) {
				snapshot.LastSeenAt = user.LastSeen
			}
		}
		snapshot.LastPolledAt = now
		if err := m.store.UpsertTrafficSnapshot(ctx, snapshot); err != nil {
			m.setError(err)
			return fmt.Errorf("save traffic snapshot for %s: %w", client.ID, err)
		}
		var lastSeen *time.Time
		if !snapshot.LastSeenAt.IsZero() {
			value := snapshot.LastSeenAt
			lastSeen = &value
		}
		next[client.ID] = ClientStats{Online: isOnline(snapshot.LastSeenAt, now), LastSeen: lastSeen, UploadBytes: snapshot.TotalUpload, DownloadBytes: snapshot.TotalDownload}
	}
	m.mu.Lock()
	m.latest = next
	m.lastError = ""
	for subscriber := range m.subs {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	m.mu.Unlock()
	return nil
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
