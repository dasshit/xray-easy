package controller

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	awgapi "xray-easy/awg-contract/api/v1"
	controllerv1 "xray-easy/internal/controller/api/v1"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

type oneSnapshotRuntime struct {
	*fakeRuntime
	update *xrayruntimev1.TelemetryResponse
	ctx    chan context.Context
}

func (r *oneSnapshotRuntime) WatchTelemetry(ctx context.Context, _ time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	r.ctx <- ctx
	return &oneSnapshotRuntimeStream{ctx: ctx, update: r.update}, nil
}

type oneSnapshotRuntimeStream struct {
	ctx    context.Context
	update *xrayruntimev1.TelemetryResponse
	sent   bool
}

func (s *oneSnapshotRuntimeStream) Recv() (*xrayruntimev1.TelemetryResponse, error) {
	if !s.sent {
		s.sent = true
		return s.update, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *oneSnapshotRuntimeStream) Header() (metadata.MD, error) { return nil, nil }
func (s *oneSnapshotRuntimeStream) Trailer() metadata.MD         { return nil }
func (s *oneSnapshotRuntimeStream) CloseSend() error             { return nil }
func (s *oneSnapshotRuntimeStream) Context() context.Context     { return s.ctx }
func (s *oneSnapshotRuntimeStream) SendMsg(any) error            { return nil }
func (s *oneSnapshotRuntimeStream) RecvMsg(any) error            { return io.EOF }

type oneSnapshotAWG struct {
	*fakeAWGRuntime
	update *awgapi.PeerStatsUpdate
	ctx    chan context.Context
}

func (a *oneSnapshotAWG) WatchPeerStats(ctx context.Context, _ time.Duration) (awgapi.Control_WatchPeerStatsClient, error) {
	a.ctx <- ctx
	return &oneSnapshotAWGStream{ctx: ctx, update: a.update}, nil
}

type oneSnapshotAWGStream struct {
	ctx    context.Context
	update *awgapi.PeerStatsUpdate
	sent   bool
}

func (s *oneSnapshotAWGStream) Recv() (*awgapi.PeerStatsUpdate, error) {
	if !s.sent {
		s.sent = true
		return s.update, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *oneSnapshotAWGStream) Header() (metadata.MD, error) { return nil, nil }
func (s *oneSnapshotAWGStream) Trailer() metadata.MD         { return nil }
func (s *oneSnapshotAWGStream) CloseSend() error             { return nil }
func (s *oneSnapshotAWGStream) Context() context.Context     { return s.ctx }
func (s *oneSnapshotAWGStream) SendMsg(any) error            { return nil }
func (s *oneSnapshotAWGStream) RecvMsg(any) error            { return io.EOF }

type stopAfterTwoControllerUpdates struct {
	ctx     context.Context
	updates []*controllerv1.TelemetryUpdate
	stop    error
}

func TestOfferTelemetryEventReplacesStaleSnapshot(t *testing.T) {
	events := make(chan telemetrySourceEvent, 1)
	offerTelemetryEvent(events, telemetrySourceEvent{protocol: "xray", xray: &xrayruntimev1.TelemetryResponse{Sequence: 1}})
	offerTelemetryEvent(events, telemetrySourceEvent{protocol: "xray", xray: &xrayruntimev1.TelemetryResponse{Sequence: 2}})

	select {
	case event := <-events:
		if event.xray.GetSequence() != 2 {
			t.Fatalf("coalesced sequence = %d, want latest sequence 2", event.xray.GetSequence())
		}
	default:
		t.Fatal("coalesced telemetry snapshot was dropped")
	}
}

func TestControllerTelemetryStreamRequiresRequest(t *testing.T) {
	if err := NewService(&fakeRuntime{}).WatchTelemetry(nil, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil telemetry request error = %v", err)
	}
}

func (s *stopAfterTwoControllerUpdates) Send(update *controllerv1.TelemetryUpdate) error {
	s.updates = append(s.updates, update)
	if len(s.updates) == 2 {
		return s.stop
	}
	return nil
}
func (s *stopAfterTwoControllerUpdates) SetHeader(metadata.MD) error  { return nil }
func (s *stopAfterTwoControllerUpdates) SendHeader(metadata.MD) error { return nil }
func (s *stopAfterTwoControllerUpdates) SetTrailer(metadata.MD)       {}
func (s *stopAfterTwoControllerUpdates) Context() context.Context     { return s.ctx }
func (s *stopAfterTwoControllerUpdates) SendMsg(any) error            { return nil }
func (s *stopAfterTwoControllerUpdates) RecvMsg(any) error            { return io.EOF }

func TestControllerTelemetryStreamFansInXrayAndCancelsUpstream(t *testing.T) {
	stop := errors.New("test stop")
	seenAt := time.Now().UTC()
	runtime := &oneSnapshotRuntime{
		fakeRuntime: &fakeRuntime{}, ctx: make(chan context.Context, 1),
		update: &xrayruntimev1.TelemetryResponse{
			SampledAt: timestamppb.New(seenAt), SourceGeneration: "runtime-a", Sequence: 9, FullSnapshot: true,
			Users: []*xrayruntimev1.UserTelemetry{
				nil,
				{},
				{Email: "unsupported@example.test", Protocol: xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED},
				{Email: "ios@example.test", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Online: true, UploadBytes: 100, DownloadBytes: 200, LastActivity: timestamppb.New(seenAt), SourceIps: []*xrayruntimev1.IPObservation{{Address: "2001:db8::9", LastSeen: timestamppb.New(seenAt)}}},
			},
		},
	}
	service := NewServiceWithAdapters(runtime, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopAfterTwoControllerUpdates{ctx: ctx, stop: stop}
	err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	if !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry error = %v", err)
	}
	if len(stream.updates) != 2 {
		t.Fatalf("Controller emitted %d messages, want initial plus Xray snapshot", len(stream.updates))
	}
	update := stream.updates[1]
	if !update.GetFullSnapshot() || update.GetSources()[0].GetProtocol() != "xray" || !update.GetSources()[0].GetAvailable() || update.GetSources()[0].GetSequence() != 9 {
		t.Fatalf("Controller source status = %+v", update.GetSources())
	}
	if len(update.GetClients()) != 1 {
		t.Fatalf("Controller clients = %+v", update.GetClients())
	}
	client := update.GetClients()[0]
	if client.GetDeviceKey() != "ios@example.test" || client.GetProtocol() != "vless" || !client.GetOnline() || client.GetUploadBytes() != 100 || len(client.GetSourceIps()) != 1 || client.GetSourceIps()[0] != "2001:db8::9" {
		t.Fatalf("normalized Controller client = %+v", client)
	}
	var upstream context.Context
	select {
	case upstream = <-runtime.ctx:
	case <-time.After(time.Second):
		t.Fatal("Controller did not open the Xray stream")
	}
	select {
	case <-upstream.Done():
	case <-time.After(time.Second):
		t.Fatal("Controller did not cancel upstream stream after Send failed")
	}
}

func TestControllerTelemetryStreamFansInAWGAndReportsXrayAvailability(t *testing.T) {
	stop := errors.New("stop after source events")
	seenAt := time.Now().UTC()
	awg := &oneSnapshotAWG{
		fakeAWGRuntime: &fakeAWGRuntime{}, ctx: make(chan context.Context, 1),
		update: &awgapi.PeerStatsUpdate{SampledAt: timestamppb.New(seenAt), SourceGeneration: "awg-a", Sequence: 5, FullSnapshot: true,
			Peers: []*awgapi.PeerStats{{Name: "iphone", Online: true, SourceIp: "203.0.113.7", UploadBytes: 11, DownloadBytes: 29, LastActivity: timestamppb.New(seenAt)}},
		},
	}
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, awg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopAfterThreeControllerUpdates{ctx: ctx, stop: stop}
	err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	if !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry error = %v", err)
	}
	var awgUpdate *controllerv1.TelemetryUpdate
	var unavailableXray bool
	for _, update := range stream.updates {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "amneziawg" && source.GetAvailable() && source.GetSequence() == 5 {
				awgUpdate = update
			}
			if source.GetProtocol() == "xray" && !source.GetAvailable() {
				unavailableXray = true
			}
		}
	}
	if awgUpdate == nil || len(awgUpdate.GetClients()) != 1 {
		t.Fatalf("AWG source update was not relayed: %+v", stream.updates)
	}
	peer := awgUpdate.GetClients()[0]
	if peer.GetDeviceKey() != "awg:iphone" || peer.GetProtocol() != "amneziawg" || !peer.GetOnline() || peer.GetSourceIps()[0] != "203.0.113.7" || peer.GetUploadBytes() != 11 {
		t.Fatalf("normalized AWG profile = %+v", peer)
	}
	if !unavailableXray {
		t.Fatalf("Xray source unavailability was not reported: %+v", stream.updates)
	}
	var upstream context.Context
	select {
	case upstream = <-awg.ctx:
	case <-time.After(time.Second):
		t.Fatal("Controller did not open the AWG stream")
	}
	select {
	case <-upstream.Done():
	case <-time.After(time.Second):
		t.Fatal("Controller did not cancel the AWG stream after downstream stopped")
	}
}

type stopAfterThreeControllerUpdates struct {
	ctx     context.Context
	updates []*controllerv1.TelemetryUpdate
	stop    error
}

func (s *stopAfterThreeControllerUpdates) Send(update *controllerv1.TelemetryUpdate) error {
	s.updates = append(s.updates, update)
	if len(s.updates) == 3 {
		return s.stop
	}
	return nil
}
func (s *stopAfterThreeControllerUpdates) SetHeader(metadata.MD) error  { return nil }
func (s *stopAfterThreeControllerUpdates) SendHeader(metadata.MD) error { return nil }
func (s *stopAfterThreeControllerUpdates) SetTrailer(metadata.MD)       {}
func (s *stopAfterThreeControllerUpdates) Context() context.Context     { return s.ctx }
func (s *stopAfterThreeControllerUpdates) SendMsg(any) error            { return nil }
func (s *stopAfterThreeControllerUpdates) RecvMsg(any) error            { return io.EOF }

func TestRemoveProtocolClientsAndXrayProtocolMapping(t *testing.T) {
	clients := map[string]*controllerv1.TelemetryClient{
		"vless": {Protocol: "vless"}, "vmess": {Protocol: "vmess"},
		"hysteria": {Protocol: "hysteria2"}, "awg": {Protocol: "amneziawg"},
		"unknown": {Protocol: "unknown"},
	}
	removeProtocolClients(clients, "xray")
	if len(clients) != 1 || clients["awg"] == nil {
		t.Fatalf("Xray clients after protocol removal = %+v", clients)
	}
	removeProtocolClients(clients, "amneziawg")
	if len(clients) != 0 {
		t.Fatalf("AWG clients after protocol removal = %+v", clients)
	}
	for protocol, want := range map[xrayruntimev1.Protocol]string{
		xrayruntimev1.Protocol_PROTOCOL_VLESS:       "vless",
		xrayruntimev1.Protocol_PROTOCOL_VMESS:       "vmess",
		xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2:   "hysteria2",
		xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED: "",
	} {
		if got := xrayProtocolName(protocol); got != want {
			t.Errorf("xrayProtocolName(%s) = %q, want %q", protocol, got, want)
		}
	}
}
