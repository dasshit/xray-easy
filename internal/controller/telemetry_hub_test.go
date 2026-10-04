package controller

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	controllerv1 "xray-easy/internal/controller/api/v1"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stopOnLeaseSnapshot struct {
	ctx      context.Context
	stop     error
	snapshot *controllerv1.LeaseSnapshot
}

func (s *stopOnLeaseSnapshot) Send(snapshot *controllerv1.LeaseSnapshot) error {
	s.snapshot = snapshot
	if len(snapshot.GetObservations()) > 0 {
		return s.stop
	}
	return nil
}
func (s *stopOnLeaseSnapshot) SetHeader(metadata.MD) error  { return nil }
func (s *stopOnLeaseSnapshot) SendHeader(metadata.MD) error { return nil }
func (s *stopOnLeaseSnapshot) SetTrailer(metadata.MD)       {}
func (s *stopOnLeaseSnapshot) Context() context.Context     { return s.ctx }
func (s *stopOnLeaseSnapshot) SendMsg(any) error            { return nil }
func (s *stopOnLeaseSnapshot) RecvMsg(any) error            { return io.EOF }

func TestTelemetryHubSharesOneUpstreamAcrossSubscribers(t *testing.T) {
	seenAt := time.Now().UTC()
	runtime := &oneSnapshotRuntime{
		fakeRuntime: &fakeRuntime{}, ctx: make(chan context.Context, 2),
		update: &xrayruntimev1.TelemetryResponse{
			SourceGeneration: "runtime-generation", Sequence: 5, FullSnapshot: true, SampledAt: timestamppb.New(seenAt),
			Users: []*xrayruntimev1.UserTelemetry{{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "device@xray-easy", Online: true, LastActivity: timestamppb.New(seenAt), SourceIps: []*xrayruntimev1.IPObservation{{Address: "192.0.2.10", LastSeen: timestamppb.New(seenAt), ConnectedAt: timestamppb.New(seenAt.Add(-time.Minute))}}}},
		},
	}
	service := NewServiceWithAdapters(runtime, nil, nil, nil)
	first, unsubscribeFirst := service.telemetryHub.subscribe()
	defer unsubscribeFirst()
	var upstream context.Context
	select {
	case upstream = <-runtime.ctx:
	case <-time.After(time.Second):
		t.Fatal("Controller did not start the Xray upstream stream")
	}
	second, unsubscribeSecond := service.telemetryHub.subscribe()
	defer unsubscribeSecond()
	waitFor := func(updates <-chan *controllerv1.TelemetryUpdate) *controllerv1.TelemetryUpdate {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			select {
			case update := <-updates:
				for _, source := range update.GetSources() {
					if source.GetProtocol() == "xray" && source.GetAvailable() && source.GetSequence() == 5 {
						return update
					}
				}
			case <-deadline:
				t.Fatal("subscriber did not receive a complete Xray snapshot")
			}
		}
	}
	if update := waitFor(first); len(update.GetClients()) != 1 {
		t.Fatalf("first subscriber snapshot clients = %+v", update.GetClients())
	}
	if update := waitFor(second); len(update.GetClients()) != 1 {
		t.Fatalf("second subscriber snapshot clients = %+v", update.GetClients())
	}
	select {
	case duplicate := <-runtime.ctx:
		t.Fatalf("Controller opened a second upstream stream: %v", duplicate)
	default:
	}
	unsubscribeFirst()
	select {
	case <-upstream.Done():
		t.Fatal("upstream stream ended while one subscriber remained")
	case <-time.After(20 * time.Millisecond):
	}
	unsubscribeSecond()
	select {
	case <-upstream.Done():
	case <-time.After(time.Second):
		t.Fatal("Controller did not cancel upstream after last subscriber left")
	}
}

func TestTelemetryHubPublishIgnoresStaleRunsAndClonesUpdates(t *testing.T) {
	hub := newTelemetryHub(NewService(&fakeRuntime{}))
	update := &controllerv1.TelemetryUpdate{Sequence: 1}
	hub.publish(1, update) // No subscriber exists yet.
	channel := make(chan *controllerv1.TelemetryUpdate, 1)
	hub.runID = 1
	hub.subscribers[1] = channel
	hub.publish(0, &controllerv1.TelemetryUpdate{Sequence: 2})
	select {
	case <-channel:
		t.Fatal("stale telemetry run was published")
	default:
	}
	hub.publish(hub.runID, update)
	got := <-channel
	got.Sequence = 99
	if hub.current.GetSequence() != 1 {
		t.Fatalf("subscriber mutation changed cached update: %+v", hub.current)
	}
	if cloneTelemetryUpdate(nil) != nil {
		t.Fatal("cloneTelemetryUpdate(nil) did not return nil")
	}
}

func TestOfferHubSnapshotReplacesAQueuedUpdate(t *testing.T) {
	channel := make(chan *controllerv1.TelemetryUpdate, 1)
	channel <- &controllerv1.TelemetryUpdate{Sequence: 1}
	offerHubSnapshot(channel, &controllerv1.TelemetryUpdate{Sequence: 2})
	select {
	case update := <-channel:
		if update.GetSequence() != 2 {
			t.Fatalf("coalesced snapshot sequence = %d, want latest sequence 2", update.GetSequence())
		}
	default:
		t.Fatal("latest snapshot was dropped")
	}
}

func TestLeaseSnapshotIncludesOnlySupportedOnlineXraySourceObservations(t *testing.T) {
	connectedAt := timestamppb.New(time.Now().UTC().Add(-time.Minute))
	seenAt := timestamppb.New(time.Now().UTC())
	update := &controllerv1.TelemetryUpdate{
		FullSnapshot: true, SampledAt: seenAt,
		Sources: []*controllerv1.TelemetrySourceStatus{{Protocol: "xray", Available: true, Generation: "xray-generation", Sequence: 8}, {Protocol: "amneziawg", Available: true, Generation: "awg-generation", Sequence: 9}},
		Clients: []*controllerv1.TelemetryClient{
			{DeviceKey: "vless-device", Protocol: "vless", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{{Address: "192.0.2.1", LastSeen: seenAt, ConnectedAt: connectedAt}}},
			{DeviceKey: "trojan-device", Protocol: "trojan", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{{Address: "192.0.2.2", LastSeen: seenAt, ConnectedAt: connectedAt}}},
			{DeviceKey: "vmess-offline", Protocol: "vmess", Online: false, SourceObservations: []*controllerv1.TelemetrySourceObservation{{Address: "192.0.2.3", LastSeen: seenAt, ConnectedAt: connectedAt}}},
			{DeviceKey: "hysteria-device", Protocol: "hysteria2", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{{Address: "192.0.2.4", LastSeen: seenAt, ConnectedAt: connectedAt}}},
			{DeviceKey: "awg:phone", Protocol: "amneziawg", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{{Address: "192.0.2.5", LastSeen: seenAt, ConnectedAt: connectedAt}}},
		},
	}
	snapshot := leaseSnapshotFromTelemetry(update)
	if !snapshot.GetSourceAvailable() || snapshot.GetSourceGeneration() != "xray-generation" || snapshot.GetSourceSequence() != 8 || !snapshot.GetFullSnapshot() || len(snapshot.GetObservations()) != 2 {
		t.Fatalf("lease snapshot = %+v", snapshot)
	}
	if snapshot.GetObservations()[0].GetSourceIp() != "192.0.2.1" || snapshot.GetObservations()[1].GetSourceIp() != "192.0.2.2" {
		t.Fatalf("lease snapshot observations = %+v", snapshot.GetObservations())
	}
	if snapshot.GetObservations()[0].GetConnectedAt() == nil || snapshot.GetObservations()[1].GetConnectedAt() == nil {
		t.Fatal("lease snapshot omitted runtime connection chronology")
	}
}

func TestLeaseSnapshotSkipsMalformedAndUnusableObservations(t *testing.T) {
	seenAt := timestamppb.New(time.Now().UTC())
	update := &controllerv1.TelemetryUpdate{
		Sources: []*controllerv1.TelemetrySourceStatus{
			nil,
			{Protocol: "amneziawg", Available: true},
			{Protocol: "xray", Error: "temporarily unavailable", Generation: "runtime-b", Sequence: 12},
		},
		Clients: []*controllerv1.TelemetryClient{
			nil,
			{DeviceKey: "offline", Protocol: "vless", Online: false},
			{DeviceKey: "unsupported", Protocol: "hysteria2", Online: true},
			{DeviceKey: "no-address", Protocol: "vless", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{
				nil,
				{Address: "  ", ConnectedAt: seenAt},
				{Address: "192.0.2.1"},
			}},
			{DeviceKey: "valid", Protocol: "trojan", Online: true, SourceObservations: []*controllerv1.TelemetrySourceObservation{
				{Address: "  ", ConnectedAt: seenAt},
				{Address: "192.0.2.2", LastSeen: seenAt, ConnectedAt: seenAt},
			}},
		},
	}

	snapshot := leaseSnapshotFromTelemetry(update)
	if snapshot.GetSourceAvailable() || snapshot.GetSourceGeneration() != "runtime-b" || snapshot.GetSourceSequence() != 12 || snapshot.GetSourceError() != "temporarily unavailable" {
		t.Fatalf("lease source status = %+v", snapshot)
	}
	if len(snapshot.GetObservations()) != 1 {
		t.Fatalf("filtered lease observations = %+v; want only the usable connected observation", snapshot.GetObservations())
	}
	observation := snapshot.GetObservations()[0]
	if observation.GetProfileEmail() != "valid" || observation.GetProtocol() != "trojan" || observation.GetSourceIp() != "192.0.2.2" || observation.GetLastActivity() != seenAt || observation.GetConnectedAt() != seenAt {
		t.Fatalf("valid lease observation = %+v", observation)
	}
}

func TestWatchLeaseSnapshotsUsesHubAndRequiresAvailableHub(t *testing.T) {
	if err := (*Service)(nil).WatchLeaseSnapshots(nil, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("nil service lease stream error=%v", err)
	}
	if err := (&Service{}).WatchLeaseSnapshots(nil, nil); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing collector lease stream error=%v", err)
	}
	stop := errors.New("test completed after lease snapshot")
	seenAt := time.Now().UTC()
	runtime := &oneSnapshotRuntime{
		fakeRuntime: &fakeRuntime{}, ctx: make(chan context.Context, 1),
		update: &xrayruntimev1.TelemetryResponse{SourceGeneration: "runtime-a", Sequence: 3, FullSnapshot: true, SampledAt: timestamppb.New(seenAt), Users: []*xrayruntimev1.UserTelemetry{{Email: "device@xray-easy", Protocol: xrayruntimev1.Protocol_PROTOCOL_TROJAN, Online: true, SourceIps: []*xrayruntimev1.IPObservation{{Address: "203.0.113.20", LastSeen: timestamppb.New(seenAt), ConnectedAt: timestamppb.New(seenAt.Add(-time.Minute))}}}}},
	}
	service := NewServiceWithAdapters(runtime, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnLeaseSnapshot{ctx: ctx, stop: stop}
	if err := service.WatchLeaseSnapshots(&controllerv1.EmptyRequest{}, stream); !errors.Is(err, stop) {
		t.Fatalf("WatchLeaseSnapshots error=%v", err)
	}
	if !stream.snapshot.GetSourceAvailable() || !stream.snapshot.GetFullSnapshot() || stream.snapshot.GetSourceGeneration() != "runtime-a" || stream.snapshot.GetSourceSequence() != 3 || len(stream.snapshot.GetObservations()) != 1 || stream.snapshot.GetObservations()[0].GetSourceIp() != "203.0.113.20" {
		t.Fatalf("lease snapshot=%+v", stream.snapshot)
	}
}
