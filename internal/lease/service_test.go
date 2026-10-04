package lease

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	controllerv1 "xray-easy/internal/controller/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeLeaseController struct {
	requests  []*controllerv1.DisconnectLeaseRequest
	responses []*controllerv1.DisconnectLeaseResponse
	errors    []error
	stream    controllerv1.Controller_WatchLeaseSnapshotsClient
	watchErr  error
	watchCall chan struct{}
	watchFn   func(context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error)
	closeCall chan *controllerv1.DisconnectLeaseRequest
}

func (f *fakeLeaseController) Health(context.Context) error { return nil }

func (f *fakeLeaseController) WatchLeaseSnapshots(ctx context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error) {
	if f.watchCall != nil {
		select {
		case f.watchCall <- struct{}{}:
		default:
		}
	}
	if f.watchFn != nil {
		return f.watchFn(ctx)
	}
	return f.stream, f.watchErr
}

func (f *fakeLeaseController) DisconnectLease(_ context.Context, request *controllerv1.DisconnectLeaseRequest) (*controllerv1.DisconnectLeaseResponse, error) {
	f.requests = append(f.requests, request)
	index := len(f.requests) - 1
	if index < len(f.errors) && f.errors[index] != nil {
		return nil, f.errors[index]
	}
	if index < len(f.responses) {
		return f.responses[index], nil
	}
	if f.closeCall != nil {
		select {
		case f.closeCall <- request:
		default:
		}
	}
	return &controllerv1.DisconnectLeaseResponse{ClosedConnections: 1}, nil
}

type fakeSnapshotStream struct {
	ctx       context.Context
	snapshots []*controllerv1.LeaseSnapshot
	index     int
	terminal  error
	hold      bool
}

func (s *fakeSnapshotStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeSnapshotStream) Trailer() metadata.MD         { return nil }
func (s *fakeSnapshotStream) CloseSend() error             { return nil }
func (s *fakeSnapshotStream) Context() context.Context     { return s.ctx }
func (s *fakeSnapshotStream) SendMsg(any) error            { return nil }
func (s *fakeSnapshotStream) RecvMsg(any) error            { return nil }
func (s *fakeSnapshotStream) Recv() (*controllerv1.LeaseSnapshot, error) {
	if s.index < len(s.snapshots) {
		value := s.snapshots[s.index]
		s.index++
		return value, nil
	}
	if s.hold {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if s.terminal != nil {
		return nil, s.terminal
	}
	return nil, io.EOF
}

func TestServiceReusesOperationIDAfterAmbiguousDisconnectFailure(t *testing.T) {
	controller := &fakeLeaseController{
		errors:    []error{status.Error(codes.Unavailable, "response lost"), nil},
		responses: []*controllerv1.DisconnectLeaseResponse{nil, {ClosedConnections: 1}},
	}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	current := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return current }
	service.newID = func() (string, error) { return "stable-operation-id", nil }
	first := service.tracker.Apply(leaseSnapshot("runtime-generation", 1, current, "192.0.2.1"), current)
	if len(first) != 0 {
		t.Fatalf("first lease decisions = %+v", first)
	}
	current = current.Add(time.Second)
	if got := service.tracker.Apply(leaseSnapshot("runtime-generation", 2, current, "192.0.2.1", "192.0.2.2"), current); len(got) != 0 {
		t.Fatalf("second lease decisions = %+v", got)
	}
	deadline, ok := service.tracker.NextDeadline()
	if !ok {
		t.Fatal("second lease grace deadline missing")
	}
	current = deadline
	decisions := service.tracker.Due(current)
	if len(decisions) != 1 {
		t.Fatalf("grace decisions = %+v", decisions)
	}
	service.enforce(context.Background(), "runtime-generation", decisions[0])
	if len(controller.requests) != 1 || controller.requests[0].GetOperationId() != "stable-operation-id" {
		t.Fatalf("first disconnect request = %+v", controller.requests)
	}
	retryAt, ok := service.tracker.NextDeadline()
	if !ok {
		t.Fatal("retry deadline missing")
	}
	current = retryAt
	decisions = service.tracker.Due(current)
	if len(decisions) != 1 {
		t.Fatalf("retry decisions = %+v", decisions)
	}
	service.enforce(context.Background(), "runtime-generation", decisions[0])
	if len(controller.requests) != 2 || controller.requests[1].GetOperationId() != controller.requests[0].GetOperationId() {
		t.Fatalf("ambiguous retry changed operation ID: %+v", controller.requests)
	}
	if len(service.operations) != 0 {
		t.Fatalf("successful operation remains pending: %+v", service.operations)
	}
}

func TestNewServiceValidatesControllerAndPolicy(t *testing.T) {
	if _, err := NewService(nil, DefaultConfig(), nil); err == nil {
		t.Fatal("NewService accepted a nil Controller")
	}
	config := DefaultConfig()
	config.MaxActiveLeases = 1
	if _, err := NewService(&fakeLeaseController{}, config, nil); err == nil {
		t.Fatal("NewService accepted an invalid policy")
	}
	service, err := NewService(&fakeLeaseController{}, DefaultConfig(), nil)
	if err != nil || service.Ready() || service.StreamConnected() {
		t.Fatalf("new worker status = ready:%t connected:%t error:%v", service.Ready(), service.StreamConnected(), err)
	}
}

func TestServiceRunRequiresInitializedStateAndAdvancesRetryBackoff(t *testing.T) {
	if err := (*Service)(nil).Run(context.Background()); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("nil Service Run() error = %v", err)
	}

	controller := &fakeLeaseController{watchErr: status.Error(codes.Unavailable, "controller unavailable")}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	service.retryJitter = func(delay time.Duration) time.Duration { return delay }
	var delays []time.Duration
	service.retryWait = func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return len(delays) == 1
	}
	if err := service.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(delays) != 2 || delays[0] != time.Second || delays[1] != 2*time.Second {
		t.Fatalf("retry delays = %v, want 1s then 2s", delays)
	}
}

func TestServiceRunStopsAfterEndedStreamWhenRetryIsCanceled(t *testing.T) {
	controller := &fakeLeaseController{}
	controller.watchFn = func(ctx context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error) {
		return &fakeSnapshotStream{ctx: ctx, terminal: io.EOF}, nil
	}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	service.retryJitter = func(delay time.Duration) time.Duration { return delay }
	service.retryWait = func(context.Context, time.Duration) bool { return false }
	if err := service.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestServiceRunRetriesUnavailableControllerAndStopsOnCancellation(t *testing.T) {
	controller := &fakeLeaseController{watchErr: status.Error(codes.Unavailable, "controller offline"), watchCall: make(chan struct{}, 1)}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-controller.watchCall:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("worker did not attempt to connect to Controller")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
	if service.Ready() || service.StreamConnected() || service.tracker.Available() {
		t.Fatal("worker retained ready state after Controller loss")
	}
}

func TestServiceRunReconnectsAfterStreamFailure(t *testing.T) {
	controller := &fakeLeaseController{watchCall: make(chan struct{}, 2)}
	attempt := 0
	controller.watchFn = func(ctx context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error) {
		attempt++
		if attempt == 1 {
			return &fakeSnapshotStream{ctx: ctx, terminal: status.Error(codes.Unavailable, "runtime stream reset")}, nil
		}
		return &fakeSnapshotStream{ctx: ctx, hold: true}, nil
	}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	for index := 0; index < 2; index++ {
		select {
		case <-controller.watchCall:
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatalf("Controller reconnect attempt %d did not occur", index+1)
		}
	}
	deadline := time.Now().Add(time.Second)
	for !service.StreamConnected() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !service.StreamConnected() {
		cancel()
		t.Fatal("worker did not reconnect to Controller")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnected worker did not stop after cancellation")
	}
}

func TestServiceRunEnforcesGraceDeadlineFromControllerStream(t *testing.T) {
	config := DefaultConfig()
	config.GracePeriod = 20 * time.Millisecond
	config.RetryDelay = 10 * time.Millisecond
	controller := &fakeLeaseController{closeCall: make(chan *controllerv1.DisconnectLeaseRequest, 1)}
	controller.watchFn = func(ctx context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error) {
		now := time.Now().UTC()
		return &fakeSnapshotStream{ctx: ctx, hold: true, snapshots: []*controllerv1.LeaseSnapshot{
			{SourceAvailable: true, FullSnapshot: true, SourceGeneration: "runtime-a", SourceSequence: 1, SampledAt: timestamppb.New(now), Observations: []*controllerv1.LeaseObservation{{Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.1", LastActivity: timestamppb.New(now), ConnectedAt: timestamppb.New(now.Add(-time.Minute))}}},
			{SourceAvailable: true, FullSnapshot: true, SourceGeneration: "runtime-a", SourceSequence: 2, SampledAt: timestamppb.New(now.Add(time.Millisecond)), Observations: []*controllerv1.LeaseObservation{{Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.1", LastActivity: timestamppb.New(now), ConnectedAt: timestamppb.New(now.Add(-time.Minute))}, {Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.2", LastActivity: timestamppb.New(now), ConnectedAt: timestamppb.New(now)}}},
		}}, nil
	}
	service, err := NewService(controller, config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	service.newID = func() (string, error) { return "stable-operation-id", nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case request := <-controller.closeCall:
		if request.GetSourceIp() != "192.0.2.1" || request.GetOperationId() != "stable-operation-id" {
			t.Fatalf("disconnect request=%+v", request)
		}
	case <-time.After(time.Second):
		cancel()
		t.Fatal("worker did not enforce the expired grace period")
	}
	if !service.Ready() || !service.StreamConnected() {
		t.Fatal("worker did not report the connected, ready stream")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error=%v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}

func TestServiceConsumeAcceptsCompleteSnapshotAndEndsOnEOF(t *testing.T) {
	now := time.Now().UTC()
	controller := &fakeLeaseController{}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	stream := &fakeSnapshotStream{ctx: context.Background(), snapshots: []*controllerv1.LeaseSnapshot{
		{SourceAvailable: true, FullSnapshot: true, SourceGeneration: "runtime-a", SourceSequence: 1, SampledAt: timestamppb.New(now), Observations: []*controllerv1.LeaseObservation{{Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.12", LastActivity: timestamppb.New(now), ConnectedAt: timestamppb.New(now)}}},
	}}
	if err := service.consume(context.Background(), stream); err == nil || !strings.Contains(err.Error(), "closed the lease snapshot stream") {
		t.Fatalf("consume error = %v", err)
	}
	if !service.sourceReady.Load() || !service.tracker.Available() || len(service.tracker.ActiveLeases()) != 1 {
		t.Fatalf("snapshot state = ready:%t available:%t leases:%+v", service.sourceReady.Load(), service.tracker.Available(), service.tracker.ActiveLeases())
	}
}

func TestServiceConsumeRemovesCompletedOperationsWhenLeaseDisappears(t *testing.T) {
	now := time.Now().UTC()
	service, err := NewService(&fakeLeaseController{}, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	key := LeaseKey{Protocol: "vless", Email: "profile", SourceIP: "192.0.2.13"}
	service.tracker.Apply(leaseSnapshot("runtime-a", 1, now, key.SourceIP), now)
	service.operations[key] = pendingOperation{id: "operation", generation: "runtime-a"}
	stream := &fakeSnapshotStream{ctx: context.Background(), snapshots: []*controllerv1.LeaseSnapshot{{
		SourceAvailable: true, FullSnapshot: true, SourceGeneration: "runtime-a", SourceSequence: 2, SampledAt: timestamppb.New(now.Add(time.Second)),
	}}}
	if err := service.consume(context.Background(), stream); err == nil {
		t.Fatal("consume() unexpectedly returned without stream termination")
	}
	if _, exists := service.operations[key]; exists {
		t.Fatal("operation for a disappeared lease was retained")
	}
}

func TestServiceConsumeEnforcesDecisionsFromIncomingSnapshotsAndStopsOnCancel(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	controller := &fakeLeaseController{}
	service, err := NewService(controller, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	clockCall := 0
	service.now = func() time.Time {
		clockCall++
		if clockCall == 1 {
			return base
		}
		return base.Add(31 * time.Second)
	}
	service.newID = func() (string, error) { return "snapshot-enforcement", nil }
	toProtoSnapshot := func(sequence uint64, sampledAt time.Time) *controllerv1.LeaseSnapshot {
		return &controllerv1.LeaseSnapshot{
			SourceAvailable: true, FullSnapshot: true, SourceGeneration: "runtime-a", SourceSequence: sequence, SampledAt: timestamppb.New(sampledAt),
			Observations: []*controllerv1.LeaseObservation{
				{Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.1", LastActivity: timestamppb.New(sampledAt), ConnectedAt: timestamppb.New(base.Add(-time.Minute))},
				{Protocol: "vless", ProfileEmail: "profile", SourceIp: "192.0.2.2", LastActivity: timestamppb.New(sampledAt), ConnectedAt: timestamppb.New(sampledAt)},
			},
		}
	}
	stream := &fakeSnapshotStream{ctx: context.Background(), snapshots: []*controllerv1.LeaseSnapshot{
		toProtoSnapshot(1, base), toProtoSnapshot(2, base.Add(31*time.Second)),
	}}
	if err := service.consume(context.Background(), stream); err == nil {
		t.Fatal("consume() unexpectedly returned without stream termination")
	}
	if len(controller.requests) != 1 || controller.requests[0].GetSourceIp() != "192.0.2.1" {
		t.Fatalf("snapshot-triggered disconnect requests = %+v", controller.requests)
	}

	ctx, cancel := context.WithCancel(context.Background())
	holdingStream := &fakeSnapshotStream{ctx: ctx, hold: true}
	done := make(chan error, 1)
	go func() { done <- service.consume(ctx, holdingStream) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("consume() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("consume() did not stop after context cancellation")
	}
}

func TestQueueSnapshotResultUnblocksOnCancellationWhenBufferIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan leaseSnapshotResult, 1)
	updates <- leaseSnapshotResult{}
	cancel()
	if queueSnapshotResult(ctx, updates, leaseSnapshotResult{err: io.EOF}) {
		t.Fatal("queueSnapshotResult() did not abandon a blocked send after cancellation")
	}
	pumpLeaseSnapshots(ctx, &fakeSnapshotStream{ctx: ctx, snapshots: []*controllerv1.LeaseSnapshot{{SourceGeneration: "blocked"}}}, updates)
	if len(updates) != 1 {
		t.Fatal("snapshot pump replaced the pending buffered update after cancellation")
	}
}

func TestServiceEnforceHandlesIDGenerationDefiniteRPCAndEmptyResponseFailures(t *testing.T) {
	key := LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: "192.0.2.1"}
	decision := func(t *testing.T, service *Service, now time.Time) Decision {
		t.Helper()
		service.tracker.Apply(leaseSnapshot("runtime-a", 1, now, "192.0.2.1"), now)
		second := now.Add(time.Second)
		service.tracker.Apply(leaseSnapshot("runtime-a", 2, second, "192.0.2.1", "192.0.2.2"), second)
		deadline, ok := service.tracker.NextDeadline()
		if !ok {
			t.Fatal("grace deadline missing")
		}
		decisions := service.tracker.Due(deadline)
		if len(decisions) != 1 || decisions[0].Lease != key {
			t.Fatalf("decision = %+v", decisions)
		}
		return decisions[0]
	}
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	idFailure, err := NewService(&fakeLeaseController{}, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	idFailure.now = func() time.Time { return base }
	idFailure.newID = func() (string, error) { return "", errors.New("entropy unavailable") }
	idFailure.enforce(context.Background(), "runtime-a", decision(t, idFailure, base))
	if _, ok := idFailure.tracker.NextDeadline(); !ok {
		t.Fatal("operation ID failure did not schedule retry")
	}

	definiteController := &fakeLeaseController{errors: []error{status.Error(codes.PermissionDenied, "denied")}}
	definite, err := NewService(definiteController, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	definite.now = func() time.Time { return base }
	definite.newID = func() (string, error) { return "operation", nil }
	definite.enforce(context.Background(), "runtime-a", decision(t, definite, base))
	if len(definite.operations) != 0 || len(definiteController.requests) != 1 {
		t.Fatalf("definite error state operations=%+v requests=%d", definite.operations, len(definiteController.requests))
	}

	emptyController := &fakeLeaseController{responses: []*controllerv1.DisconnectLeaseResponse{nil}}
	empty, err := NewService(emptyController, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	empty.now = func() time.Time { return base }
	empty.newID = func() (string, error) { return "operation", nil }
	empty.enforce(context.Background(), "runtime-a", decision(t, empty, base))
	if len(empty.operations) != 0 || len(emptyController.requests) != 1 {
		t.Fatalf("empty response state operations=%+v requests=%d", empty.operations, len(emptyController.requests))
	}
}

type fakeLeaseTimer struct {
	channel    chan time.Time
	stopResult bool
	resetDelay time.Duration
}

func (t *fakeLeaseTimer) Stop() bool                     { return t.stopResult }
func (t *fakeLeaseTimer) Reset(delay time.Duration) bool { t.resetDelay = delay; return false }
func (t *fakeLeaseTimer) Channel() <-chan time.Time      { return t.channel }

func TestServiceTimerAndUtilityEdgeCases(t *testing.T) {
	service, err := NewService(&fakeLeaseController{}, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var timer leaseTimer
	var channel <-chan time.Time
	service.resetTimer(&timer, &channel)
	if channel != nil {
		t.Fatal("unavailable tracker unexpectedly armed a timer")
	}
	firedWithoutDeadline := &fakeLeaseTimer{channel: make(chan time.Time, 1)}
	firedWithoutDeadline.channel <- time.Now()
	firedWithoutDeadline.stopResult = false
	timer = firedWithoutDeadline
	service.resetTimer(&timer, &channel)
	if channel != nil || len(firedWithoutDeadline.channel) != 0 {
		t.Fatal("unavailable tracker did not drain an expired timer")
	}

	now := time.Now().UTC()
	service.tracker.Apply(leaseSnapshot("runtime-a", 1, now, "192.0.2.1"), now)
	service.tracker.Apply(leaseSnapshot("runtime-a", 2, now.Add(time.Second), "192.0.2.1", "192.0.2.2"), now.Add(time.Second))
	activeTimer := &fakeLeaseTimer{channel: make(chan time.Time, 1)}
	service.makeTimer = func(time.Duration) leaseTimer { return activeTimer }
	timer = nil
	service.resetTimer(&timer, &channel)
	if timer == nil || channel == nil {
		t.Fatal("active conflict did not arm its grace timer")
	}
	activeTimer.channel <- time.Now()
	service.resetTimer(&timer, &channel)
	if len(activeTimer.channel) != 0 {
		t.Fatal("resetTimer did not drain a fired timer")
	}
	service.resetTimer(&timer, &channel)
	if activeTimer.resetDelay < 0 {
		t.Fatal("reset timer received a negative duration")
	}
	standardTimerService, err := NewService(&fakeLeaseController{}, DefaultConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	standardTimerService.tracker.Apply(leaseSnapshot("runtime-a", 1, now, "192.0.2.6"), now)
	standardTimerService.tracker.Apply(leaseSnapshot("runtime-a", 2, now.Add(time.Second), "192.0.2.6", "192.0.2.7"), now.Add(time.Second))
	var standardTimer leaseTimer
	var standardChannel <-chan time.Time
	standardTimerService.resetTimer(&standardTimer, &standardChannel)
	standardTimerService.resetTimer(&standardTimer, &standardChannel)
	standardTimer.Stop()
	if !waitRetry(context.Background(), time.Millisecond) {
		t.Fatal("waitRetry did not return after its timer fired")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if waitRetry(canceled, time.Hour) {
		t.Fatal("waitRetry returned true after context cancellation")
	}

	service.tracker.SetUnavailable()
	var pastDeadlineTimer leaseTimer
	var pastDeadlineChannel <-chan time.Time
	service.tracker.Apply(leaseSnapshot("runtime-a", 3, now.Add(2*time.Second), "192.0.2.1", "192.0.2.2"), now.Add(2*time.Second))
	service.tracker.grace[profileFor(LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: "192.0.2.1"})] = time.Now().Add(-time.Second)
	pastTimer := &fakeLeaseTimer{channel: make(chan time.Time, 1)}
	service.makeTimer = func(delay time.Duration) leaseTimer {
		pastTimer.resetDelay = delay
		return pastTimer
	}
	pastDeadlineTimer = nil
	service.resetTimer(&pastDeadlineTimer, &pastDeadlineChannel)
	if pastDeadlineTimer == nil || pastTimer.resetDelay != 0 {
		t.Fatalf("past deadline timer = %v, delay=%s; want immediate timer", pastDeadlineTimer, pastTimer.resetDelay)
	}
	if safeError(nil) != "" || safeError(errors.New(strings.Repeat("x", 200))) == "" || len(safeError(errors.New(strings.Repeat("x", 200)))) != 160 {
		t.Fatal("safeError did not handle nil and oversized errors")
	}
	if got := jitter(0); got != time.Second {
		t.Fatalf("jitter of non-positive duration = %s", got)
	}
	if got := jitter(time.Nanosecond); got != time.Nanosecond {
		t.Fatalf("jitter with no spread = %s", got)
	}
	if _, err := randomOperationID(); err != nil {
		t.Fatalf("randomOperationID: %v", err)
	}
	if _, err := randomOperationIDFrom(strings.NewReader("short")); err == nil {
		t.Fatal("randomOperationIDFrom accepted insufficient entropy")
	}
	if profileLogID("profile") == profileLogID("other") {
		t.Fatal("profile log identifiers collided in the test")
	}
}

func TestNormalizeLeaseSnapshotValidatesReadinessAndObservations(t *testing.T) {
	if got := normalizeLeaseSnapshot(nil); got.Available || got.Full || got.Leases != nil {
		t.Fatalf("nil lease snapshot normalized to %+v", got)
	}
	valid := &controllerv1.LeaseSnapshot{
		SourceAvailable: true, FullSnapshot: true, SourceGeneration: "generation-a", SourceSequence: 7,
		SampledAt: timestamppb.New(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)),
		Observations: []*controllerv1.LeaseObservation{
			nil,
			{Protocol: "VLESS", ProfileEmail: "device-1@xray-easy", SourceIp: "::ffff:192.0.2.8", LastActivity: timestamppb.New(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)), ConnectedAt: timestamppb.New(time.Date(2026, 10, 3, 11, 59, 0, 0, time.UTC))},
			{Protocol: "hysteria2", ProfileEmail: "device-2@xray-easy", SourceIp: "192.0.2.9", LastActivity: timestamppb.New(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))},
			{Protocol: "trojan", ProfileEmail: "device-3@xray-easy", SourceIp: "fe80::1%en0", LastActivity: timestamppb.New(time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))},
			{Protocol: "vmess", ProfileEmail: "device-4@xray-easy", SourceIp: "192.0.2.10", ConnectedAt: timestamppb.New(time.Date(2026, 10, 3, 11, 59, 0, 0, time.UTC))},
		},
	}
	got := normalizeLeaseSnapshot(valid)
	if !got.Available || !got.Full || got.Generation != "generation-a" || got.Sequence != 7 || len(got.Leases) != 1 {
		t.Fatalf("normalized snapshot = %+v", got)
	}
	if got.Leases[0].Key.Protocol != "vless" || got.Leases[0].Key.SourceIP != "192.0.2.8" {
		t.Fatalf("normalized lease = %+v", got.Leases[0])
	}
	if !got.Leases[0].FirstSeen.Equal(time.Date(2026, 10, 3, 11, 59, 0, 0, time.UTC)) {
		t.Fatalf("normalized connection start = %v", got.Leases[0].FirstSeen)
	}
	if got := normalizeLeaseSnapshot(&controllerv1.LeaseSnapshot{SourceAvailable: true, FullSnapshot: true}); got.Available || got.Full || got.Generation != "" {
		t.Fatalf("invalid ready snapshot was accepted: %+v", got)
	}
}

func TestJitterStaysWithinTwentyPercent(t *testing.T) {
	const delay = 10 * time.Second
	for range 100 {
		got := jitter(delay)
		if got < 8*time.Second || got > 12*time.Second {
			t.Fatalf("jitter(%s) = %s, outside 80–120%%", delay, got)
		}
	}
}

func TestDisconnectErrorClassificationPreservesAmbiguousOperationIDs(t *testing.T) {
	for code, want := range map[codes.Code]bool{
		codes.InvalidArgument: true, codes.PermissionDenied: true, codes.Unauthenticated: true,
		codes.Unimplemented: true, codes.Aborted: true, codes.FailedPrecondition: true, codes.Internal: true,
		codes.Unavailable: false, codes.DeadlineExceeded: false, codes.Canceled: false, codes.Unknown: false,
	} {
		if got := leaseDisconnectErrorIsDefinite(code); got != want {
			t.Errorf("leaseDisconnectErrorIsDefinite(%s) = %t, want %t", code, got, want)
		}
	}
}
