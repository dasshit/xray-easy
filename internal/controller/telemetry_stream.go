package controller

import (
	"context"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"
	controllerv1 "xray-easy/internal/controller/api/v1"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// xrayTelemetryStreamer is an internal type used by the package.
type xrayTelemetryStreamer interface {
	// WatchTelemetry defines part of the interface contract.
	WatchTelemetry(context.Context, time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error)
}

// awgTelemetryStreamer is an internal type used by the package.
type awgTelemetryStreamer interface {
	// WatchPeerStats defines part of the interface contract.
	WatchPeerStats(context.Context, time.Duration) (awgapi.Control_WatchPeerStatsClient, error)
}

// telemetrySourceEvent is an internal type used by the package.
type telemetrySourceEvent struct {
	protocol string
	xray     *xrayruntimev1.TelemetryResponse
	awg      *awgapi.PeerStatsUpdate
	err      error
}

// WatchTelemetry streams full snapshots from the Controller-owned telemetry
// collector shared by every backend and lease-service subscriber.
func (s *Service) WatchTelemetry(request *controllerv1.WatchTelemetryRequest, stream controllerv1.Controller_WatchTelemetryServer) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "watch request is required")
	}
	updates, unsubscribe := s.telemetryHub.subscribe()
	defer unsubscribe()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-updates:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

// pumpXrayTelemetry performs the operation represented by its name.
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

// pumpAWGTelemetry performs the operation represented by its name.
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

// offerTelemetryEvent performs the operation represented by its name.
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

// waitTelemetryRetry performs the operation represented by its name.
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

// removeProtocolClients removes the supplied value.
func removeProtocolClients(clients map[string]*controllerv1.TelemetryClient, protocol string) {
	for key, client := range clients {
		clientProtocol := client.GetProtocol()
		if clientProtocol == protocol || (protocol == "xray" && clientProtocol != "amneziawg") {
			delete(clients, key)
		}
	}
}

// xrayProtocolName performs the operation represented by its name.
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
