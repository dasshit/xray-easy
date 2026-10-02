package controller

import (
	"context"
	"strings"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"
	controllerv1 "xray-easy/internal/controller/api/v1"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type xrayTelemetryStreamer interface {
	WatchTelemetry(context.Context, time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error)
}

type awgTelemetryStreamer interface {
	WatchPeerStats(context.Context, time.Duration) (awgapi.Control_WatchPeerStatsClient, error)
}

type telemetrySourceEvent struct {
	protocol string
	xray     *xrayruntimev1.TelemetryResponse
	awg      *awgapi.PeerStatsUpdate
	err      error
}

// WatchTelemetry fans in Xray and AmneziaWG snapshots. Upstream streams are
// opened only for the lifetime of this backend subscription.
func (s *Service) WatchTelemetry(request *controllerv1.WatchTelemetryRequest, stream controllerv1.Controller_WatchTelemetryServer) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "watch request is required")
	}
	interval := time.Duration(request.GetSampleIntervalMs()) * time.Millisecond
	if interval < 500*time.Millisecond {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	xrayEvents := make(chan telemetrySourceEvent, 1)
	awgEvents := make(chan telemetrySourceEvent, 1)
	if watcher, ok := s.xray.(xrayTelemetryStreamer); ok {
		go pumpXrayTelemetry(ctx, watcher, interval, xrayEvents)
	} else {
		offerTelemetryEvent(xrayEvents, telemetrySourceEvent{protocol: "xray", err: status.Error(codes.Unavailable, "stream is unsupported")})
	}
	if s.awg != nil {
		if watcher, ok := s.awg.(awgTelemetryStreamer); ok {
			go pumpAWGTelemetry(ctx, watcher, interval, awgEvents)
		} else {
			offerTelemetryEvent(awgEvents, telemetrySourceEvent{protocol: "amneziawg", err: status.Error(codes.Unavailable, "stream is unsupported")})
		}
	}

	clients := make(map[string]*controllerv1.TelemetryClient)
	sources := map[string]*controllerv1.TelemetrySourceStatus{
		"xray": {Protocol: "xray"},
	}
	if s.awg != nil {
		sources["amneziawg"] = &controllerv1.TelemetrySourceStatus{Protocol: "amneziawg"}
	}
	var sequence uint64
	send := func() error {
		sequence++
		update := &controllerv1.TelemetryUpdate{SampledAt: timestamppb.New(time.Now().UTC()), Sequence: sequence, FullSnapshot: true}
		for _, client := range clients {
			update.Clients = append(update.Clients, client)
		}
		for _, source := range sources {
			update.Sources = append(update.Sources, source)
		}
		return stream.Send(update)
	}
	if err := send(); err != nil {
		return err
	}
	handleEvent := func(event telemetrySourceEvent) error {
		source := sources[event.protocol]
		if source == nil {
			return nil
		}
		if event.err != nil {
			source.Available = false
			source.Error = "telemetry source is temporarily unavailable"
			return send()
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
					if observation != nil && strings.TrimSpace(observation.GetAddress()) != "" {
						item.SourceIps = append(item.SourceIps, observation.GetAddress())
					}
				}
				clients[item.GetDeviceKey()] = item
			}
		}
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
				}
				clients[item.GetDeviceKey()] = item
			}
		}
		return send()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event := <-xrayEvents:
			if err := handleEvent(event); err != nil {
				return err
			}
		case event := <-awgEvents:
			if err := handleEvent(event); err != nil {
				return err
			}
		}
	}
}

func pumpXrayTelemetry(ctx context.Context, watcher xrayTelemetryStreamer, interval time.Duration, events chan telemetrySourceEvent) {
	for backoff := time.Second; ctx.Err() == nil; {
		stream, err := watcher.WatchTelemetry(ctx, interval)
		if err != nil {
			offerTelemetryEvent(events, telemetrySourceEvent{protocol: "xray", err: err})
			if !waitTelemetryRetry(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		for ctx.Err() == nil {
			update, recvErr := stream.Recv()
			if recvErr != nil {
				offerTelemetryEvent(events, telemetrySourceEvent{protocol: "xray", err: recvErr})
				break
			}
			offerTelemetryEvent(events, telemetrySourceEvent{protocol: "xray", xray: update})
			backoff = time.Second
		}
		if !waitTelemetryRetry(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func pumpAWGTelemetry(ctx context.Context, watcher awgTelemetryStreamer, interval time.Duration, events chan telemetrySourceEvent) {
	for backoff := time.Second; ctx.Err() == nil; {
		stream, err := watcher.WatchPeerStats(ctx, interval)
		if err != nil {
			offerTelemetryEvent(events, telemetrySourceEvent{protocol: "amneziawg", err: err})
			if !waitTelemetryRetry(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		for ctx.Err() == nil {
			update, recvErr := stream.Recv()
			if recvErr != nil {
				offerTelemetryEvent(events, telemetrySourceEvent{protocol: "amneziawg", err: recvErr})
				break
			}
			offerTelemetryEvent(events, telemetrySourceEvent{protocol: "amneziawg", awg: update})
			backoff = time.Second
		}
		if !waitTelemetryRetry(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func offerTelemetryEvent(events chan telemetrySourceEvent, event telemetrySourceEvent) {
	select {
	case events <- event:
	default:
		// Each source has its own single-slot channel, so replace its stale
		// full snapshot with the newest one without blocking Recv.
		select {
		case <-events:
		default:
		}
		select {
		case events <- event:
		default:
		}
	}
}

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

func removeProtocolClients(clients map[string]*controllerv1.TelemetryClient, protocol string) {
	for key, client := range clients {
		clientProtocol := client.GetProtocol()
		if clientProtocol == protocol || (protocol == "xray" && clientProtocol != "amneziawg") {
			delete(clients, key)
		}
	}
}

func xrayProtocolName(protocol xrayruntimev1.Protocol) string {
	switch protocol {
	case xrayruntimev1.Protocol_PROTOCOL_VLESS:
		return "vless"
	case xrayruntimev1.Protocol_PROTOCOL_VMESS:
		return "vmess"
	case xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2:
		return "hysteria2"
	case xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS:
		return "shadowsocks"
	case xrayruntimev1.Protocol_PROTOCOL_TROJAN:
		return "trojan"
	default:
		return ""
	}
}
