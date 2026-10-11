// Package stats polls runtime telemetry, computes deltas and rates, and persists counters.
package stats

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	controllerv1 "xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/store"
	"xray-easy/internal/xrayapi"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// defaultPollInterval is an internal package constant.
const defaultPollInterval = 10 * time.Second

// onlineWindow is an internal package constant.
const onlineWindow = 15 * time.Second

// telemetryCallTimeout is an internal package constant.
const telemetryCallTimeout = 5 * time.Second

// telemetryStreamOpener is an internal type used by the package.
type telemetryStreamOpener interface {
	// WatchTelemetry defines part of the interface contract.
	WatchTelemetry(context.Context, time.Duration) (controllerv1.Controller_WatchTelemetryClient, error)
}

// ClientStats is the UI-facing snapshot. Totals survive Xray restarts because
// Manager accumulates deltas in SQLite rather than exposing process-local
// counters directly.
type ClientStats struct {
	// Online is whether the client is currently online.
	Online bool `json:"online"`
	// LastSeen is the last time the runtime observed traffic.
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// SourceIPs is the source IP observations associated with the client.
	SourceIPs []string `json:"source_ips,omitempty"`
	// UploadBytes is the observed upload byte count.
	UploadBytes int64 `json:"upload_bytes"`
	// DownloadBytes is the observed download byte count.
	DownloadBytes int64 `json:"download_bytes"`
	// UploadBytesPerSecond contains the UploadBytesPerSecond value for this object.
	UploadBytesPerSecond float64 `json:"upload_bytes_per_second"`
	// DownloadBytesPerSecond contains the DownloadBytesPerSecond value for this object.
	DownloadBytesPerSecond float64 `json:"download_bytes_per_second"`
}

// StatsAPI is the small Xray boundary needed by the polling manager.
type StatsAPI interface {
	// Poll polls the telemetry source.
	Poll(context.Context) ([]xrayapi.UserStats, error)
}

// AWGStatsAPI reads runtime counters for the optional AmneziaWG transport.
type AWGStatsAPI interface {
	// PeerStats defines part of the interface contract.
	PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error)
}

// Manager coordinates telemetry polling and the live statistics stream.
type Manager struct {
	store *store.Store
	api   StatsAPI
	awg   AWGStatsAPI

	mu               sync.RWMutex
	applyMu          sync.Mutex
	latest           map[string]ClientStats
	subs             map[chan struct{}]struct{}
	interval         time.Duration
	lastError        string
	now              func() time.Time
	stream           telemetryStreamOpener
	streamCancel     context.CancelFunc
	streamConnected  bool
	streamGeneration uint64
	rootContext      context.Context
	checkpoints      map[string]streamCheckpoint
	retryWait        func(context.Context, time.Duration) bool
}

// streamCheckpoint is an internal type used by the package.
type streamCheckpoint struct {
	generation string
	sequence   uint64
}

// NewManager constructs and returns the requested value.
func NewManager(db *store.Store, api StatsAPI, awg ...AWGStatsAPI) *Manager {
	manager := &Manager{store: db, api: api, latest: make(map[string]ClientStats), subs: make(map[chan struct{}]struct{}), interval: defaultPollInterval, now: time.Now, checkpoints: make(map[string]streamCheckpoint)}
	manager.stream, _ = api.(telemetryStreamOpener)
	if len(awg) > 0 {
		manager.awg = awg[0]
	}
	return manager
}

// Start starts the requested operation.
func (m *Manager) Start(ctx context.Context) <-chan struct{} {
	m.mu.Lock()
	m.rootContext = ctx
	m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Poll(ctx)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.pollIfStreamInactive(ctx)
			}
		}
	}()
	return done
}

// pollIfStreamInactive falls back to polling while the telemetry stream is disconnected.
func (m *Manager) pollIfStreamInactive(ctx context.Context) {
	m.mu.RLock()
	streamConnected := m.stream != nil && m.streamConnected
	m.mu.RUnlock()
	if !streamConnected {
		_ = m.Poll(ctx)
	}
}

// setStreamConnected updates the telemetry stream connection state.
func (m *Manager) setStreamConnected(connected bool) {
	m.setStreamConnectedForGeneration(0, connected)
}

// setStreamConnectedForGeneration ignores stale stream generations when updating connection state.
func (m *Manager) setStreamConnectedForGeneration(generation uint64, connected bool) {
	m.mu.Lock()
	if generation == 0 || generation == m.streamGeneration {
		m.streamConnected = connected
	}
	m.mu.Unlock()
}

// Poll polls the requested source.
func (m *Manager) Poll(ctx context.Context) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
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

// ApplyStreamUpdate folds the latest Controller snapshot into durable traffic
// totals and publishes it to SSE subscribers. Absolute counters make replayed
// or coalesced snapshots safe to process.
func (m *Manager) ApplyStreamUpdate(ctx context.Context, update *controllerv1.TelemetryUpdate) error {
	if update == nil {
		return fmt.Errorf("Controller telemetry update is nil")
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	clients, err := m.store.ListClients(ctx)
	if err != nil {
		return fmt.Errorf("list clients for streamed stats: %w", err)
	}
	previous, err := m.store.ListTrafficSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("list traffic snapshots: %w", err)
	}
	previousLatest := m.Snapshot()
	now := m.now().UTC()
	if update.GetSampledAt() != nil && update.GetSampledAt().CheckValid() == nil {
		now = update.GetSampledAt().AsTime().UTC()
	}
	fresh := make(map[string]bool, len(update.GetSources()))
	available := make(map[string]bool, len(update.GetSources()))
	for _, source := range update.GetSources() {
		if source == nil {
			continue
		}
		available[source.GetProtocol()] = source.GetAvailable()
		if !source.GetAvailable() || source.GetGeneration() == "" || source.GetSequence() == 0 {
			continue
		}
		prior := m.checkpoints[source.GetProtocol()]
		fresh[source.GetProtocol()] = prior.generation != source.GetGeneration() || source.GetSequence() > prior.sequence
		if fresh[source.GetProtocol()] {
			m.checkpoints[source.GetProtocol()] = streamCheckpoint{generation: source.GetGeneration(), sequence: source.GetSequence()}
		}
	}
	xrayRows := make([]xrayapi.UserStats, 0)
	awgRows := make([]domain.AmneziaWGPeerStats, 0)
	for _, client := range update.GetClients() {
		if client == nil || client.GetDeviceKey() == "" || client.GetUploadBytes() < 0 || client.GetDownloadBytes() < 0 {
			continue
		}
		protocol := client.GetProtocol()
		if protocol == "amneziawg" {
			if !fresh[protocol] || !strings.HasPrefix(client.GetDeviceKey(), "awg:") {
				continue
			}
			lastSeen := protobufTimestamp(client.GetLastActivity())
			address := ""
			if client.GetOnline() && len(client.GetSourceIps()) > 0 {
				address = client.GetSourceIps()[0]
			}
			awgRows = append(awgRows, domain.AmneziaWGPeerStats{Name: strings.TrimPrefix(client.GetDeviceKey(), "awg:"), SourceIP: address, LastSeen: lastSeen, UploadBytes: client.GetUploadBytes(), DownloadBytes: client.GetDownloadBytes()})
			continue
		}
		if !fresh["xray"] || (protocol != "vless" && protocol != "vmess" && protocol != "hysteria2" && protocol != "shadowsocks") {
			continue
		}
		lastSeen := protobufTimestamp(client.GetLastActivity())
		row := xrayapi.UserStats{Email: client.GetDeviceKey(), Protocol: protocol, UploadBytes: client.GetUploadBytes(), DownloadBytes: client.GetDownloadBytes(), LastSeen: lastSeen}
		if client.GetOnline() {
			for _, address := range client.GetSourceIps() {
				if address != "" {
					row.SourceIPs = append(row.SourceIPs, xrayapi.IPObservation{Address: address, LastSeen: now})
				}
			}
		}
		xrayRows = append(xrayRows, row)
	}
	next := make(map[string]ClientStats, len(clients))
	if fresh["xray"] {
		if err := m.updateXray(ctx, clients, previous, xrayRows, previousLatest, next, now); err != nil {
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
	if !fresh["amneziawg"] {
		preserveAWGStats(next, previousLatest, now)
	}
	if fresh["amneziawg"] {
		if err := m.updateAWGObserved(ctx, previousLatest, next, now, awgRows); err != nil {
			m.setError(err)
			return err
		}
	}
	applyStreamOnlineStatus(next, clients, update.GetClients(), available)
	m.mu.Lock()
	m.latest = next
	m.lastError = ""
	for _, source := range update.GetSources() {
		if source != nil && !source.GetAvailable() {
			if m.lastError != "" {
				m.lastError += "; "
			}
			m.lastError += source.GetProtocol() + " telemetry is unavailable"
		}
	}
	for subscriber := range m.subs {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	m.mu.Unlock()
	return nil
}

// protobufTimestamp performs the operation represented by its name.
func protobufTimestamp(value *timestamppb.Timestamp) time.Time {
	if value == nil || value.CheckValid() != nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

// updateXray performs the operation represented by its name.
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
		trafficObserved := false
		if user, ok := byEmail[client.Email]; ok {
			uploadDelta = counterDelta(user.UploadBytes, snapshot.RawUpload)
			downloadDelta = counterDelta(user.DownloadBytes, snapshot.RawDownload)
			snapshot.TotalUpload += uploadDelta
			snapshot.TotalDownload += downloadDelta
			snapshot.RawUpload, snapshot.RawDownload = user.UploadBytes, user.DownloadBytes
			trafficObserved = uploadDelta > 0 || downloadDelta > 0
			if user.LastSeen.After(snapshot.LastSeenAt) {
				snapshot.LastSeenAt = user.LastSeen
			}
			if trafficObserved && now.After(snapshot.LastSeenAt) {
				snapshot.LastSeenAt = now
			}
			for _, ip := range user.SourceIPs {
				if (isOnline(ip.LastSeen, now) || trafficObserved) && ip.Address != "" {
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

// updateAWG performs the operation represented by its name.
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
	return m.updateAWGObserved(ctx, previousLatest, next, now, observed)
}

// updateAWGObserved performs the operation represented by its name.
func (m *Manager) updateAWGObserved(ctx context.Context, previousLatest, next map[string]ClientStats, now time.Time, observed []domain.AmneziaWGPeerStats) error {
	previous, err := m.store.ListAWGTrafficSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("list AmneziaWG traffic snapshots: %w", err)
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
		trafficObserved := uploadDelta > 0 || downloadDelta > 0
		// A WireGuard handshake is not a reliable activity signal: it may be
		// older than the online window while an established tunnel continues to
		// carry traffic. Counter movement is direct evidence that this peer was
		// active during the current poll window.
		if trafficObserved && now.After(snapshot.LastSeenAt) {
			snapshot.LastSeenAt = now
		}
		if peer.SourceIP != "" && (!peer.LastSeen.IsZero() || trafficObserved) {
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

// preserveAWGStats performs the operation represented by its name.
func preserveAWGStats(next, previous map[string]ClientStats, now time.Time) {
	for key, current := range previous {
		if !strings.HasPrefix(key, "awg:") {
			continue
		}
		current.UploadBytesPerSecond, current.DownloadBytesPerSecond = 0, 0
		if current.LastSeen != nil {
			current.Online = isOnline(*current.LastSeen, now)
		}
		if !current.Online {
			current.SourceIPs = nil
		}
		next[key] = current
	}
}

// applyStreamOnlineStatus performs the operation represented by its name.
func applyStreamOnlineStatus(next map[string]ClientStats, managed []domain.Client, reported []*controllerv1.TelemetryClient, available map[string]bool) {
	clientIDsByEmail := make(map[string]string, len(managed))
	for _, client := range managed {
		clientIDsByEmail[client.Email] = client.ID
	}
	for _, item := range reported {
		if item == nil {
			continue
		}
		id := ""
		switch item.GetProtocol() {
		case "amneziawg":
			if available["amneziawg"] && strings.HasPrefix(item.GetDeviceKey(), "awg:") {
				id = item.GetDeviceKey()
			}
		case "vless", "vmess", "hysteria2":
			if available["xray"] {
				id = clientIDsByEmail[item.GetDeviceKey()]
			}
		}
		current, ok := next[id]
		if !ok {
			continue
		}
		current.Online = item.GetOnline()
		current.SourceIPs = nil
		if current.Online {
			for _, address := range item.GetSourceIps() {
				if address != "" {
					current.SourceIPs = appendUnique(current.SourceIPs, address)
				}
			}
		} else {
			current.UploadBytesPerSecond, current.DownloadBytesPerSecond = 0, 0
		}
		next[id] = current
	}
}

// appendUnique performs the operation represented by its name.
func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// optionalTime performs the operation represented by its name.
func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

// validRateWindow performs the operation represented by its name.
func validRateWindow(elapsed, interval time.Duration) bool {
	return elapsed > 0 && interval > 0 && elapsed <= 3*interval
}

// bytesPerSecond performs the operation represented by its name.
func bytesPerSecond(delta int64, elapsed time.Duration) float64 {
	if delta <= 0 || elapsed <= 0 {
		return 0
	}
	return float64(delta) / elapsed.Seconds()
}

// Snapshot returns a snapshot of the current state.
func (m *Manager) Snapshot() map[string]ClientStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copy := make(map[string]ClientStats, len(m.latest))
	for id, stats := range m.latest {
		copy[id] = stats
	}
	return copy
}

// LastError performs the operation represented by its name.
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
	wasEmpty := len(m.subs) == 0
	m.subs[channel] = struct{}{}
	if wasEmpty && m.stream != nil && m.streamCancel == nil {
		parent := m.rootContext
		if parent == nil {
			parent = context.Background()
		}
		streamContext, cancel := context.WithCancel(parent)
		m.streamCancel = cancel
		m.streamGeneration++
		generation := m.streamGeneration
		m.streamConnected = false
		go m.consumeTelemetryStreamGeneration(streamContext, generation)
	}
	m.mu.Unlock()
	return channel, func() {
		m.mu.Lock()
		if _, ok := m.subs[channel]; ok {
			delete(m.subs, channel)
			close(channel)
		}
		if len(m.subs) == 0 && m.streamCancel != nil {
			m.streamCancel()
			m.streamCancel = nil
			m.streamConnected = false
		}
		m.mu.Unlock()
	}
}

// consumeTelemetryStream performs the operation represented by its name.
func (m *Manager) consumeTelemetryStream(ctx context.Context) {
	m.consumeTelemetryStreamGeneration(ctx, 0)
}

// consumeTelemetryStreamGeneration applies stream updates and reconnects with backoff for its generation.
func (m *Manager) consumeTelemetryStreamGeneration(ctx context.Context, generation uint64) {
	defer m.setStreamConnectedForGeneration(generation, false)
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := m.stream.WatchTelemetry(ctx, time.Second)
		if err == nil && stream == nil {
			err = errors.New("Controller returned an empty telemetry stream")
		}
		if err == nil {
			m.setStreamConnectedForGeneration(generation, true)
			for ctx.Err() == nil {
				var update *controllerv1.TelemetryUpdate
				update, err = stream.Recv()
				if err != nil {
					if !errors.Is(err, io.EOF) && ctx.Err() == nil {
						m.markStreamError(err)
					}
					break
				}
				if applyErr := m.ApplyStreamUpdate(ctx, update); applyErr != nil {
					m.markStreamError(applyErr)
				} else {
					backoff = time.Second
				}
			}
			m.setStreamConnectedForGeneration(generation, false)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, io.EOF) {
			m.markStreamError(err)
		}
		if !m.waitForRetry(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// waitForRetry delegates a stream retry wait to the injected or standard timer implementation.
func (m *Manager) waitForRetry(ctx context.Context, delay time.Duration) bool {
	if m.retryWait != nil {
		return m.retryWait(ctx, delay)
	}
	return waitTelemetryRetry(ctx, delay)
}

// waitTelemetryRetry waits for delay unless the telemetry context is canceled first.
func waitTelemetryRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// markStreamError performs the operation represented by its name.
func (m *Manager) markStreamError(err error) {
	if err == nil {
		return
	}
	now := m.now().UTC()
	m.mu.Lock()
	m.lastError = "live telemetry stream is unavailable"
	for id, current := range m.latest {
		current.UploadBytesPerSecond, current.DownloadBytesPerSecond = 0, 0
		if current.LastSeen != nil {
			current.Online = isOnline(*current.LastSeen, now)
		}
		if !current.Online {
			current.SourceIPs = nil
		}
		m.latest[id] = current
	}
	for subscriber := range m.subs {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
	m.mu.Unlock()
}

// setError updates the requested value.
func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.lastError = err.Error()
	m.mu.Unlock()
}

// counterDelta performs the operation represented by its name.
func counterDelta(current, previous int64) int64 {
	if current < 0 {
		return 0
	}
	if current < previous {
		return current
	}
	return current - previous
}

// isOnline performs the operation represented by its name.
func isOnline(lastSeen, now time.Time) bool {
	return !lastSeen.IsZero() && !lastSeen.After(now.Add(time.Minute)) && now.Sub(lastSeen) <= onlineWindow
}
