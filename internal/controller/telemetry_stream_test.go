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

type unavailableXrayTelemetry struct {
	*fakeRuntime
	openErr error
}

func (r *unavailableXrayTelemetry) WatchTelemetry(context.Context, time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	return nil, r.openErr
}

type unavailableAWGTelemetry struct {
	*fakeAWGRuntime
	openErr error
}

func (a *unavailableAWGTelemetry) WatchPeerStats(context.Context, time.Duration) (awgapi.Control_WatchPeerStatsClient, error) {
	return nil, a.openErr
}

type blockedXrayTelemetry struct {
	*fakeRuntime
	started  chan struct{}
	release  chan struct{}
	returned chan struct{}
}

func (r *blockedXrayTelemetry) WatchTelemetry(context.Context, time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	close(r.started)
	<-r.release
	close(r.returned)
	return nil, errors.New("stream stopped")
}

type retryingXrayTelemetry struct {
	calls  int
	cancel context.CancelFunc
}

func (r *retryingXrayTelemetry) WatchTelemetry(ctx context.Context, _ time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	r.calls++
	if r.calls == 1 {
		return nil, errors.New("temporary stream open failure")
	}
	return &terminatingXrayTelemetryStream{cancel: r.cancel}, nil
}

type terminatingXrayTelemetryStream struct {
	xrayruntimev1.Runtime_WatchTelemetryClient
	cancel context.CancelFunc
}

func (s *terminatingXrayTelemetryStream) Recv() (*xrayruntimev1.TelemetryResponse, error) {
	s.cancel()
	return nil, errors.New("temporary stream receive failure")
}

type retryingAWGTelemetry struct {
	calls  int
	cancel context.CancelFunc
}

func (a *retryingAWGTelemetry) WatchPeerStats(ctx context.Context, _ time.Duration) (awgapi.Control_WatchPeerStatsClient, error) {
	a.calls++
	if a.calls == 1 {
		return nil, errors.New("temporary stream open failure")
	}
	return &terminatingAWGTelemetryStream{cancel: a.cancel}, nil
}

type terminatingAWGTelemetryStream struct {
	awgapi.Control_WatchPeerStatsClient
	cancel context.CancelFunc
}

func (s *terminatingAWGTelemetryStream) Recv() (*awgapi.PeerStatsUpdate, error) {
	s.cancel()
	return nil, errors.New("temporary stream receive failure")
}

type retryAfterXrayStreamEnd struct {
	calls  int
	cancel context.CancelFunc
}

func (r *retryAfterXrayStreamEnd) WatchTelemetry(context.Context, time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	r.calls++
	if r.calls == 1 {
		return &endedXrayTelemetryStream{}, nil
	}
	r.cancel()
	return nil, errors.New("stream reopen failed")
}

type endedXrayTelemetryStream struct {
	xrayruntimev1.Runtime_WatchTelemetryClient
}

func (endedXrayTelemetryStream) Recv() (*xrayruntimev1.TelemetryResponse, error) { return nil, io.EOF }

type retryAfterAWGStreamEnd struct {
	calls  int
	cancel context.CancelFunc
}

func (r *retryAfterAWGStreamEnd) WatchPeerStats(context.Context, time.Duration) (awgapi.Control_WatchPeerStatsClient, error) {
	r.calls++
	if r.calls == 1 {
		return &endedAWGTelemetryStream{}, nil
	}
	r.cancel()
	return nil, errors.New("stream reopen failed")
}

type endedAWGTelemetryStream struct {
	awgapi.Control_WatchPeerStatsClient
}

func (endedAWGTelemetryStream) Recv() (*awgapi.PeerStatsUpdate, error) { return nil, io.EOF }

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

func TestWaitTelemetryRetryExpiresOrStopsOnCancellation(t *testing.T) {
	if !waitTelemetryRetry(context.Background(), time.Millisecond) {
		t.Fatal("retry wait did not report its timer firing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitTelemetryRetry(ctx, time.Hour) {
		t.Fatal("retry wait continued after cancellation")
	}
}

func TestTelemetryPumpsRetryOpenFailuresAndReportReceiveFailures(t *testing.T) {
	xrayCtx, cancelXray := context.WithCancel(context.Background())
	defer cancelXray()
	awgCtx, cancelAWG := context.WithCancel(context.Background())
	defer cancelAWG()
	xray := &retryingXrayTelemetry{cancel: cancelXray}
	awg := &retryingAWGTelemetry{cancel: cancelAWG}
	xrayEvents := make(chan telemetrySourceEvent, 1)
	awgEvents := make(chan telemetrySourceEvent, 1)
	done := make(chan struct{}, 2)
	go func() {
		pumpXrayTelemetry(xrayCtx, xray, time.Second, xrayEvents)
		done <- struct{}{}
	}()
	go func() {
		pumpAWGTelemetry(awgCtx, awg, time.Second, awgEvents)
		done <- struct{}{}
	}()

	for range 2 {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cancelXray()
			cancelAWG()
			t.Fatal("telemetry pump did not stop after its stream failed")
		}
	}
	if xray.calls != 2 || awg.calls != 2 {
		t.Fatalf("stream open attempts = xray %d, AWG %d; want initial failure followed by a stream", xray.calls, awg.calls)
	}
	for protocol, events := range map[string]<-chan telemetrySourceEvent{"xray": xrayEvents, "amneziawg": awgEvents} {
		select {
		case event := <-events:
			if event.protocol != protocol || event.err == nil {
				t.Errorf("%s telemetry failure event = %+v", protocol, event)
			}
		default:
			t.Errorf("%s telemetry stream failure was not reported", protocol)
		}
	}
}

func TestTelemetryPumpsRetryAfterEstablishedStreamsEnd(t *testing.T) {
	xrayCtx, cancelXray := context.WithCancel(context.Background())
	defer cancelXray()
	awgCtx, cancelAWG := context.WithCancel(context.Background())
	defer cancelAWG()
	xray := &retryAfterXrayStreamEnd{cancel: cancelXray}
	awg := &retryAfterAWGStreamEnd{cancel: cancelAWG}
	done := make(chan struct{}, 2)
	go func() {
		pumpXrayTelemetry(xrayCtx, xray, time.Second, make(chan telemetrySourceEvent, 1))
		done <- struct{}{}
	}()
	go func() {
		pumpAWGTelemetry(awgCtx, awg, time.Second, make(chan telemetrySourceEvent, 1))
		done <- struct{}{}
	}()
	for range 2 {
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			cancelXray()
			cancelAWG()
			t.Fatal("telemetry pumps did not retry an ended stream and then stop")
		}
	}
	if xray.calls != 2 || awg.calls != 2 {
		t.Fatalf("stream reopen attempts = xray %d, AWG %d; want two per protocol", xray.calls, awg.calls)
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
				{Email: "ios@example.test", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Online: true, UploadBytes: 100, DownloadBytes: 200, LastActivity: timestamppb.New(seenAt), SourceIps: []*xrayruntimev1.IPObservation{nil, {}, {Address: "  "}, {Address: "2001:db8::9", LastSeen: timestamppb.New(seenAt)}}},
			},
		},
	}
	service := NewServiceWithAdapters(runtime, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnTelemetrySnapshot{ctx: ctx, stop: stop, matched: func(update *controllerv1.TelemetryUpdate) bool {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "xray" && source.GetGeneration() == "runtime-a" {
				return true
			}
		}
		return false
	}}
	err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	if !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry error = %v", err)
	}
	update := stream.updates[len(stream.updates)-1]
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
			Peers: []*awgapi.PeerStats{nil, {}, {Name: "iphone", Online: true, SourceIp: "203.0.113.7", UploadBytes: 11, DownloadBytes: 29, LastActivity: timestamppb.New(seenAt)}},
		},
	}
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, awg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnTelemetrySnapshot{ctx: ctx, stop: stop, matched: func(update *controllerv1.TelemetryUpdate) bool {
		var availableAWG, unavailableXray bool
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "amneziawg" && source.GetAvailable() && source.GetSequence() == 5 {
				availableAWG = true
			}
			if source.GetProtocol() == "xray" && !source.GetAvailable() && source.GetError() != "" {
				unavailableXray = true
			}
		}
		return availableAWG && unavailableXray
	}}
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
			if source.GetProtocol() == "xray" && !source.GetAvailable() && source.GetError() != "" {
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

func TestControllerTelemetryReportsUnsupportedAWGStreamer(t *testing.T) {
	stop := errors.New("stop after unsupported AWG status")
	service := NewServiceWithAdapters(&fakeRuntime{}, nil, nil, &fakeAWGRuntime{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnTelemetrySnapshot{ctx: ctx, stop: stop, matched: func(update *controllerv1.TelemetryUpdate) bool {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "amneziawg" && !source.GetAvailable() && source.GetError() != "" {
				return true
			}
		}
		return false
	}}
	if err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream); !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry() error = %v", err)
	}
}

type cancelAfterFirstLeaseSnapshot struct {
	ctx     context.Context
	cancel  context.CancelFunc
	started <-chan struct{}
}

func (s cancelAfterFirstLeaseSnapshot) Send(*controllerv1.LeaseSnapshot) error {
	s.cancel()
	select {
	case <-s.started:
		return nil
	case <-time.After(time.Second):
		return errors.New("telemetry pump did not start")
	}
}
func (s cancelAfterFirstLeaseSnapshot) SetHeader(metadata.MD) error  { return nil }
func (s cancelAfterFirstLeaseSnapshot) SendHeader(metadata.MD) error { return nil }
func (s cancelAfterFirstLeaseSnapshot) SetTrailer(metadata.MD)       {}
func (s cancelAfterFirstLeaseSnapshot) Context() context.Context     { return s.ctx }
func (s cancelAfterFirstLeaseSnapshot) SendMsg(any) error            { return nil }
func (s cancelAfterFirstLeaseSnapshot) RecvMsg(any) error            { return io.EOF }

func TestWatchLeaseSnapshotsStopsWhenConsumerCancels(t *testing.T) {
	runtime := &blockedXrayTelemetry{
		fakeRuntime: &fakeRuntime{}, started: make(chan struct{}),
		release: make(chan struct{}), returned: make(chan struct{}),
	}
	service := NewServiceWithAdapters(runtime, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	err := service.WatchLeaseSnapshots(&controllerv1.EmptyRequest{}, cancelAfterFirstLeaseSnapshot{ctx: ctx, cancel: cancel, started: runtime.started})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchLeaseSnapshots() error = %v, want canceled context", err)
	}
	close(runtime.release)
	select {
	case <-runtime.returned:
	case <-time.After(time.Second):
		t.Fatal("upstream watcher did not exit after release")
	}
}

func TestControllerTelemetryStreamReportsUnavailableXray(t *testing.T) {
	stop := errors.New("stop after Xray source status")
	service := NewServiceWithAdapters(&unavailableXrayTelemetry{fakeRuntime: &fakeRuntime{}, openErr: errors.New("private upstream error")}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnTelemetrySnapshot{ctx: ctx, stop: stop, matched: func(update *controllerv1.TelemetryUpdate) bool {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "xray" && !source.GetAvailable() && source.GetError() != "" {
				return true
			}
		}
		return false
	}}
	err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	if !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry error = %v", err)
	}
	var source *controllerv1.TelemetrySourceStatus
	for _, item := range stream.updates[len(stream.updates)-1].GetSources() {
		if item.GetProtocol() == "xray" {
			source = item
		}
	}
	if source.GetAvailable() || source.GetError() != "telemetry source is temporarily unavailable" {
		t.Fatalf("Xray unavailable source = %+v", source)
	}
}

func TestControllerTelemetryStreamReportsUnavailableAWG(t *testing.T) {
	stop := errors.New("stop after both source statuses")
	service := NewServiceWithAdapters(
		&fakeRuntime{}, nil, nil,
		&unavailableAWGTelemetry{fakeAWGRuntime: &fakeAWGRuntime{}, openErr: errors.New("private upstream error")},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &stopOnTelemetrySnapshot{ctx: ctx, stop: stop, matched: func(update *controllerv1.TelemetryUpdate) bool {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "amneziawg" && !source.GetAvailable() && source.GetError() != "" {
				return true
			}
		}
		return false
	}}
	err := service.WatchTelemetry(&controllerv1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	if !errors.Is(err, stop) {
		t.Fatalf("WatchTelemetry error = %v", err)
	}
	var unavailableAWG bool
	for _, update := range stream.updates {
		for _, source := range update.GetSources() {
			if source.GetProtocol() == "amneziawg" && !source.GetAvailable() && source.GetError() == "telemetry source is temporarily unavailable" {
				unavailableAWG = true
			}
		}
	}
	if !unavailableAWG {
		t.Fatalf("AWG unavailable source was not reported: %+v", stream.updates)
	}
}

type stopAfterThreeControllerUpdates struct {
	ctx     context.Context
	updates []*controllerv1.TelemetryUpdate
	stop    error
}

type stopOnTelemetrySnapshot struct {
	ctx     context.Context
	updates []*controllerv1.TelemetryUpdate
	stop    error
	matched func(*controllerv1.TelemetryUpdate) bool
}

func (s *stopOnTelemetrySnapshot) Send(update *controllerv1.TelemetryUpdate) error {
	s.updates = append(s.updates, update)
	if s.matched(update) {
		return s.stop
	}
	return nil
}
func (s *stopOnTelemetrySnapshot) SetHeader(metadata.MD) error  { return nil }
func (s *stopOnTelemetrySnapshot) SendHeader(metadata.MD) error { return nil }
func (s *stopOnTelemetrySnapshot) SetTrailer(metadata.MD)       {}
func (s *stopOnTelemetrySnapshot) Context() context.Context     { return s.ctx }
func (s *stopOnTelemetrySnapshot) SendMsg(any) error            { return nil }
func (s *stopOnTelemetrySnapshot) RecvMsg(any) error            { return io.EOF }

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
		xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS: "shadowsocks",
		xrayruntimev1.Protocol_PROTOCOL_TROJAN:      "trojan",
		xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED: "",
	} {
		if got := xrayProtocolName(protocol); got != want {
			t.Errorf("xrayProtocolName(%s) = %q, want %q", protocol, got, want)
		}
	}
}
