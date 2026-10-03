package controller

import (
	"context"
	"strings"
	"sync"
	"time"

	controllerv1 "xray-easy/internal/controller/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// telemetryHubInterval is the cadence requested from telemetry sources.
const telemetryHubInterval = time.Second

// telemetryHub owns one upstream telemetry stream per configured protocol and
// fans out full, latest-wins snapshots to all Controller consumers.
type telemetryHub struct {
	service     *Service
	mu          sync.Mutex
	subscribers map[uint64]chan *controllerv1.TelemetryUpdate
	current     *controllerv1.TelemetryUpdate
	cancel      context.CancelFunc
	nextID      uint64
	runID       uint64
}

// newTelemetryHub initializes shared telemetry collection for one Controller.
func newTelemetryHub(service *Service) *telemetryHub {
	return &telemetryHub{service: service, subscribers: make(map[uint64]chan *controllerv1.TelemetryUpdate)}
}

// subscribe adds a latest-wins snapshot subscriber and starts collection if needed.
func (h *telemetryHub) subscribe() (<-chan *controllerv1.TelemetryUpdate, func()) {
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	channel := make(chan *controllerv1.TelemetryUpdate, 1)
	h.subscribers[id] = channel
	if h.current != nil {
		offerHubSnapshot(channel, cloneTelemetryUpdate(h.current))
	}
	if len(h.subscribers) == 1 {
		h.runID++
		runID := h.runID
		ctx, cancel := context.WithCancel(context.Background())
		h.cancel = cancel
		go h.collect(ctx, runID)
	}
	h.mu.Unlock()
	var once sync.Once
	return channel, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers, id)
			if len(h.subscribers) == 0 && h.cancel != nil {
				h.cancel()
				h.cancel = nil
				h.current = nil
				h.runID++
			}
			h.mu.Unlock()
		})
	}
}

// collect owns upstream telemetry streams while at least one consumer is attached.
func (h *telemetryHub) collect(ctx context.Context, runID uint64) {
	xrayEvents := make(chan telemetrySourceEvent, 1)
	awgEvents := make(chan telemetrySourceEvent, 1)
	clients := make(map[string]*controllerv1.TelemetryClient)
	sources := map[string]*controllerv1.TelemetrySourceStatus{"xray": {Protocol: "xray"}}
	if h.service.awg != nil {
		sources["amneziawg"] = &controllerv1.TelemetrySourceStatus{Protocol: "amneziawg"}
	}
	var sequence uint64
	publish := func() {
		sequence++
		update := &controllerv1.TelemetryUpdate{SampledAt: timestamppb.New(time.Now().UTC()), Sequence: sequence, FullSnapshot: true}
		for _, client := range clients {
			update.Clients = append(update.Clients, proto.Clone(client).(*controllerv1.TelemetryClient))
		}
		for _, source := range sources {
			update.Sources = append(update.Sources, proto.Clone(source).(*controllerv1.TelemetrySourceStatus))
		}
		h.publish(runID, update)
	}
	publish()
	// Publish the initial not-ready snapshot before starting pumps. Otherwise a
	// fast upstream failure can publish an unavailable status first, then be
	// overwritten by this stale initial snapshot.
	if watcher, ok := h.service.xray.(xrayTelemetryStreamer); ok {
		go pumpXrayTelemetry(ctx, watcher, telemetryHubInterval, xrayEvents)
	} else {
		offerTelemetryEvent(xrayEvents, telemetrySourceEvent{protocol: "xray", err: status.Error(codes.Unavailable, "stream is unsupported")})
	}
	if h.service.awg != nil {
		if watcher, ok := h.service.awg.(awgTelemetryStreamer); ok {
			go pumpAWGTelemetry(ctx, watcher, telemetryHubInterval, awgEvents)
		} else {
			offerTelemetryEvent(awgEvents, telemetrySourceEvent{protocol: "amneziawg", err: status.Error(codes.Unavailable, "stream is unsupported")})
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-xrayEvents:
			source := sources[event.protocol]
			if source == nil {
				continue
			}
			if event.err != nil {
				source.Available = false
				source.Error = "telemetry source is temporarily unavailable"
				publish()
				continue
			}
			source.Available = true
			source.Error = ""
			if event.xray != nil {
				source.Generation = event.xray.GetSourceGeneration()
				source.Sequence = event.xray.GetSequence()
				source.SampledAt = event.xray.GetSampledAt()
				removeProtocolClients(clients, "xray")
				for _, user := range event.xray.GetUsers() {
					if user == nil || strings.TrimSpace(user.GetEmail()) == "" {
						continue
					}
					protocol := xrayProtocolName(user.GetProtocol())
					if protocol == "" {
						continue
					}
					item := &controllerv1.TelemetryClient{DeviceKey: user.GetEmail(), Protocol: protocol, Online: user.GetOnline(), UploadBytes: user.GetUploadBytes(), DownloadBytes: user.GetDownloadBytes(), LastActivity: user.GetLastActivity()}
					for _, observation := range user.GetSourceIps() {
						if observation == nil || strings.TrimSpace(observation.GetAddress()) == "" {
							continue
						}
						item.SourceIps = append(item.SourceIps, observation.GetAddress())
						item.SourceObservations = append(item.SourceObservations, &controllerv1.TelemetrySourceObservation{Address: observation.GetAddress(), LastSeen: observation.GetLastSeen(), ConnectedAt: observation.GetConnectedAt()})
					}
					clients[item.GetDeviceKey()] = item
				}
			}
			publish()
		case event := <-awgEvents:
			source := sources[event.protocol]
			if source == nil {
				continue
			}
			if event.err != nil {
				source.Available = false
				source.Error = "telemetry source is temporarily unavailable"
				publish()
				continue
			}
			source.Available = true
			source.Error = ""
			if event.awg != nil {
				source.Generation = event.awg.GetSourceGeneration()
				source.Sequence = event.awg.GetSequence()
				source.SampledAt = event.awg.GetSampledAt()
				removeProtocolClients(clients, "amneziawg")
				for _, peer := range event.awg.GetPeers() {
					if peer == nil || strings.TrimSpace(peer.GetName()) == "" {
						continue
					}
					item := &controllerv1.TelemetryClient{DeviceKey: "awg:" + peer.GetName(), Protocol: "amneziawg", Online: peer.GetOnline(), UploadBytes: peer.GetUploadBytes(), DownloadBytes: peer.GetDownloadBytes(), LastActivity: peer.GetLastActivity()}
					if peer.GetSourceIp() != "" && peer.GetOnline() {
						item.SourceIps = []string{peer.GetSourceIp()}
						item.SourceObservations = []*controllerv1.TelemetrySourceObservation{{Address: peer.GetSourceIp(), LastSeen: peer.GetLastActivity()}}
					}
					clients[item.GetDeviceKey()] = item
				}
			}
			publish()
		}
	}
}

// publish replaces the cached snapshot and offers a copy to every current subscriber.
func (h *telemetryHub) publish(runID uint64, update *controllerv1.TelemetryUpdate) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if runID != h.runID || len(h.subscribers) == 0 {
		return
	}
	h.current = proto.Clone(update).(*controllerv1.TelemetryUpdate)
	for _, subscriber := range h.subscribers {
		offerHubSnapshot(subscriber, proto.Clone(update).(*controllerv1.TelemetryUpdate))
	}
}

// offerHubSnapshot keeps only the newest update when a subscriber is slow.
func offerHubSnapshot(channel chan *controllerv1.TelemetryUpdate, update *controllerv1.TelemetryUpdate) {
	select {
	case channel <- update:
	default:
		select {
		case <-channel:
		default:
		}
		select {
		case channel <- update:
		default:
		}
	}
}

// cloneTelemetryUpdate returns an independent protobuf snapshot for a subscriber.
func cloneTelemetryUpdate(update *controllerv1.TelemetryUpdate) *controllerv1.TelemetryUpdate {
	if update == nil {
		return nil
	}
	return proto.Clone(update).(*controllerv1.TelemetryUpdate)
}

// WatchLeaseSnapshots streams only Xray source-IP leases; it intentionally
// excludes AmneziaWG and profile credentials.
func (s *Service) WatchLeaseSnapshots(_ *controllerv1.EmptyRequest, stream controllerv1.Controller_WatchLeaseSnapshotsServer) error {
	if s == nil || s.telemetryHub == nil {
		return status.Error(codes.Unavailable, "telemetry collector is unavailable")
	}
	updates, unsubscribe := s.telemetryHub.subscribe()
	defer unsubscribe()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-updates:
			snapshot := leaseSnapshotFromTelemetry(update)
			if err := stream.Send(snapshot); err != nil {
				return err
			}
		}
	}
}

// leaseSnapshotFromTelemetry filters full telemetry down to supported active Xray leases.
func leaseSnapshotFromTelemetry(update *controllerv1.TelemetryUpdate) *controllerv1.LeaseSnapshot {
	snapshot := &controllerv1.LeaseSnapshot{SampledAt: update.GetSampledAt(), FullSnapshot: update.GetFullSnapshot()}
	for _, source := range update.GetSources() {
		if source.GetProtocol() != "xray" {
			continue
		}
		snapshot.SourceAvailable = source.GetAvailable()
		snapshot.SourceGeneration = source.GetGeneration()
		snapshot.SourceSequence = source.GetSequence()
		snapshot.SourceError = source.GetError()
		break
	}
	for _, client := range update.GetClients() {
		if client == nil || !client.GetOnline() || !leaseProtocolSupported(client.GetProtocol()) {
			continue
		}
		for _, observation := range client.GetSourceObservations() {
			if observation == nil || strings.TrimSpace(observation.GetAddress()) == "" {
				continue
			}
			if observation.GetConnectedAt() == nil {
				continue
			}
			snapshot.Observations = append(snapshot.Observations, &controllerv1.LeaseObservation{ProfileEmail: client.GetDeviceKey(), Protocol: client.GetProtocol(), SourceIp: observation.GetAddress(), LastActivity: observation.GetLastSeen(), ConnectedAt: observation.GetConnectedAt()})
		}
	}
	return snapshot
}

// leaseProtocolSupported reports whether the runtime can close this protocol's TCP lease.
func leaseProtocolSupported(protocol string) bool {
	switch protocol {
	case "vless", "vmess", "trojan":
		return true
	default:
		return false
	}
}
