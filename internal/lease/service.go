package lease

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	controllerv1 "xray-easy/internal/controller/api/v1"
)

// disconnectTimeout bounds one RPC that closes an Xray source lease.
const disconnectTimeout = 5 * time.Second

// Controller is the restricted Controller API used by the lease service.
type Controller interface {
	// Health verifies that Controller and its Xray adapter are responding.
	Health(context.Context) error
	// WatchLeaseSnapshots opens the authenticated source-lease snapshot stream.
	WatchLeaseSnapshots(context.Context) (controllerv1.Controller_WatchLeaseSnapshotsClient, error)
	// DisconnectLease closes one exact source-IP lease in the embedded runtime.
	DisconnectLease(context.Context, *controllerv1.DisconnectLeaseRequest) (*controllerv1.DisconnectLeaseResponse, error)
}

// Service consumes Controller snapshots and applies lease enforcement.
type Service struct {
	controller  Controller
	tracker     *Tracker
	logger      *slog.Logger
	now         func() time.Time
	newID       func() (string, error)
	retryWait   func(context.Context, time.Duration) bool
	retryJitter func(time.Duration) time.Duration
	makeTimer   func(time.Duration) leaseTimer
	operations  map[LeaseKey]pendingOperation
	connected   atomic.Bool
	sourceReady atomic.Bool
}

// pendingOperation keeps a retry's idempotency key within one runtime generation.
type pendingOperation struct {
	id         string
	generation string
}

// leaseSnapshotResult transports one received snapshot or stream error to the service loop.
type leaseSnapshotResult struct {
	snapshot *controllerv1.LeaseSnapshot
	err      error
}

// leaseTimer is the timer contract used to schedule the next lease enforcement deadline.
type leaseTimer interface {
	// Stop prevents the timer from firing and reports whether it stopped it.
	Stop() bool
	// Reset schedules the timer to fire after the supplied delay.
	Reset(time.Duration) bool
	// Channel returns the timer's event channel.
	Channel() <-chan time.Time
}

// standardLeaseTimer adapts time.Timer to the service's injectable timer contract.
type standardLeaseTimer struct{ timer *time.Timer }

// Stop stops the underlying timer.
func (t standardLeaseTimer) Stop() bool { return t.timer.Stop() }

// Reset schedules the underlying timer to fire after delay.
func (t standardLeaseTimer) Reset(delay time.Duration) bool { return t.timer.Reset(delay) }

// Channel returns the underlying timer's event channel.
func (t standardLeaseTimer) Channel() <-chan time.Time { return t.timer.C }

// NewService creates a lease policy worker using the supplied restricted Controller client.
func NewService(controller Controller, config Config, logger *slog.Logger) (*Service, error) {
	if controller == nil {
		return nil, errors.New("Controller client is required")
	}
	tracker, err := NewTracker(config)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{controller: controller, tracker: tracker, logger: logger, now: time.Now, newID: randomOperationID, operations: make(map[LeaseKey]pendingOperation)}, nil
}

// Run continuously reconnects to Controller and applies complete Xray snapshots.
func (s *Service) Run(ctx context.Context) error {
	if s == nil || s.controller == nil || s.tracker == nil {
		return errors.New("lease service is not initialized")
	}
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := s.controller.WatchLeaseSnapshots(ctx)
		if err != nil {
			s.tracker.SetUnavailable()
			s.setStatus(false, false)
			s.logger.Warn("lease snapshot stream unavailable; enforcement is fail-open", "component", "controller", "result", "failure", "error", safeError(err))
			if !s.waitForRetry(ctx, s.retryDelay(backoff)) {
				break
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		s.setStatus(true, false)
		s.logger.Info("lease snapshot stream connected", "component", "controller", "result", "success")
		err = s.consume(ctx, stream)
		s.tracker.SetUnavailable()
		s.setStatus(false, false)
		if ctx.Err() != nil {
			break
		}
		s.logger.Warn("lease snapshot stream ended; enforcement is fail-open", "component", "controller", "result", "failure", "error", safeError(err))
		if !s.waitForRetry(ctx, s.retryDelay(backoff)) {
			break
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return ctx.Err()
}

// waitForRetry waits for a retry delay through the injected or standard timer implementation.
func (s *Service) waitForRetry(ctx context.Context, delay time.Duration) bool {
	if s.retryWait != nil {
		return s.retryWait(ctx, delay)
	}
	return waitRetry(ctx, delay)
}

// retryDelay applies injected or standard jitter to a retry backoff.
func (s *Service) retryDelay(delay time.Duration) time.Duration {
	if s.retryJitter != nil {
		return s.retryJitter(delay)
	}
	return jitter(delay)
}

// Ready reports whether the stream is connected and a usable Xray snapshot has arrived.
func (s *Service) Ready() bool {
	return s != nil && s.connected.Load() && s.sourceReady.Load()
}

// StreamConnected reports whether the lease service currently has an upstream Controller stream.
func (s *Service) StreamConnected() bool { return s != nil && s.connected.Load() }

// setStatus publishes the Controller stream and telemetry readiness state.
func (s *Service) setStatus(connected, sourceReady bool) {
	s.connected.Store(connected)
	s.sourceReady.Store(sourceReady)
}

// consume reconciles snapshots and runs grace/retry deadlines until the stream ends.
func (s *Service) consume(ctx context.Context, stream controllerv1.Controller_WatchLeaseSnapshotsClient) error {
	updates := make(chan leaseSnapshotResult, 1)
	go pumpLeaseSnapshots(ctx, stream, updates)
	var timer leaseTimer
	var timerChannel <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.resetTimer(&timer, &timerChannel)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update := <-updates:
			if update.err != nil {
				if errors.Is(update.err, io.EOF) {
					return errors.New("Controller closed the lease snapshot stream")
				}
				return update.err
			}
			snapshot := normalizeLeaseSnapshot(update.snapshot)
			now := s.now().UTC()
			s.sourceReady.Store(snapshot.Available && snapshot.Full && snapshot.Generation != "" && snapshot.Sequence > 0)
			if snapshot.Available && snapshot.Generation != s.tracker.generation {
				s.operations = make(map[LeaseKey]pendingOperation)
			}
			for _, decision := range s.tracker.Apply(snapshot, now) {
				s.enforce(ctx, snapshot.Generation, decision)
			}
			active := make(map[LeaseKey]struct{})
			for _, key := range s.tracker.ActiveLeases() {
				active[key] = struct{}{}
			}
			for key := range s.operations {
				if _, ok := active[key]; !ok {
					delete(s.operations, key)
				}
			}
		case <-timerChannel:
			for _, decision := range s.tracker.Due(s.now().UTC()) {
				s.enforce(ctx, s.tracker.generation, decision)
			}
		}
	}
}

// pumpLeaseSnapshots forwards stream snapshots and errors until the stream or context ends.
func pumpLeaseSnapshots(ctx context.Context, stream controllerv1.Controller_WatchLeaseSnapshotsClient, updates chan<- leaseSnapshotResult) {
	for {
		snapshot, err := stream.Recv()
		if !queueSnapshotResult(ctx, updates, leaseSnapshotResult{snapshot: snapshot, err: err}) {
			return
		}
		if err != nil {
			return
		}
	}
}

// resetTimer arms the worker timer for the tracker's next enforcement deadline.
func (s *Service) resetTimer(timer *leaseTimer, channel *<-chan time.Time) {
	deadline, ok := s.tracker.NextDeadline()
	if !ok {
		if *timer != nil && !(*timer).Stop() {
			select {
			case <-(*timer).Channel():
			default:
			}
		}
		*channel = nil
		return
	}
	delay := time.Until(deadline)
	if delay < 0 {
		delay = 0
	}
	if *timer == nil {
		if s.makeTimer == nil {
			*timer = standardLeaseTimer{timer: time.NewTimer(delay)}
		} else {
			*timer = s.makeTimer(delay)
		}
	} else {
		if !(*timer).Stop() {
			select {
			case <-(*timer).Channel():
			default:
			}
		}
		(*timer).Reset(delay)
	}
	*channel = (*timer).Channel()
}

// queueSnapshotResult sends one stream result unless the receiving service has stopped.
func queueSnapshotResult(ctx context.Context, updates chan<- leaseSnapshotResult, result leaseSnapshotResult) bool {
	select {
	case updates <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

// enforce executes one idempotent disconnect decision and records its outcome.
func (s *Service) enforce(parent context.Context, generation string, decision Decision) {
	operation, exists := s.operations[decision.Lease]
	var err error
	if !exists || operation.generation != generation {
		operation.id, err = s.newID()
		operation.generation = generation
	}
	if err != nil {
		s.tracker.Complete(decision.Lease, false, s.now().UTC())
		s.logger.Error("could not create lease operation ID", "component", "lease-policy", "result", "failure")
		return
	}
	s.operations[decision.Lease] = operation
	operationID := operation.id
	profileHash := profileLogID(decision.Lease.Email)
	s.logger.Warn("Xray profile lease conflict detected", "component", "lease-policy", "protocol", decision.Lease.Protocol, "profile_id", profileHash, "source_ip", decision.Lease.SourceIP, "action", decision.Reason)
	ctx, cancel := context.WithTimeout(parent, disconnectTimeout)
	defer cancel()
	response, callErr := s.controller.DisconnectLease(ctx, &controllerv1.DisconnectLeaseRequest{
		Protocol: decision.Lease.Protocol, ProfileEmail: decision.Lease.Email, SourceIp: decision.Lease.SourceIP,
		OperationId: operationID, SourceGeneration: generation,
	})
	completedAt := s.now().UTC()
	if callErr != nil {
		s.tracker.Complete(decision.Lease, false, completedAt)
		if leaseDisconnectErrorIsDefinite(status.Code(callErr)) {
			delete(s.operations, decision.Lease)
		}
		s.logger.Error("could not disconnect oldest Xray lease; retry scheduled", "component", "runtime", "protocol", decision.Lease.Protocol, "profile_id", profileHash, "source_ip", decision.Lease.SourceIP, "operation_id", operationID, "error", safeError(callErr))
		return
	}
	if response == nil {
		s.tracker.Complete(decision.Lease, false, completedAt)
		delete(s.operations, decision.Lease)
		s.logger.Error("Controller returned an empty lease disconnect response", "component", "runtime", "protocol", decision.Lease.Protocol, "profile_id", profileHash, "source_ip", decision.Lease.SourceIP, "operation_id", operationID)
		return
	}
	s.tracker.Complete(decision.Lease, true, completedAt)
	delete(s.operations, decision.Lease)
	s.logger.Info("oldest Xray lease disconnected", "component", "runtime", "protocol", decision.Lease.Protocol, "profile_id", profileHash, "source_ip", decision.Lease.SourceIP, "operation_id", operationID, "closed_connections", response.GetClosedConnections(), "already_applied", response.GetAlreadyApplied())
}

// leaseDisconnectErrorIsDefinite reports RPC errors that should not be retried.
func leaseDisconnectErrorIsDefinite(code codes.Code) bool {
	switch code {
	case codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented, codes.Aborted, codes.FailedPrecondition:
		return true
	case codes.Internal:
		// A runtime close failure can be cached under the operation ID. Start a
		// new operation on retry so a transient close error is not replayed forever.
		return true
	default:
		return false
	}
}

// normalizeLeaseSnapshot validates and converts a protobuf snapshot for the tracker.
func normalizeLeaseSnapshot(value *controllerv1.LeaseSnapshot) Snapshot {
	if value == nil {
		return Snapshot{}
	}
	snapshot := Snapshot{
		Available: value.GetSourceAvailable(), Full: value.GetFullSnapshot(), Generation: strings.TrimSpace(value.GetSourceGeneration()),
		Sequence: value.GetSourceSequence(), SampledAt: protobufTime(value.GetSampledAt()),
	}
	if !snapshot.Available || !snapshot.Full || snapshot.Generation == "" || snapshot.Sequence == 0 {
		snapshot.Available = false
		snapshot.Full = false
		return snapshot
	}
	for _, observation := range value.GetObservations() {
		if observation == nil {
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(observation.GetProtocol()))
		if protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
			continue
		}
		address, err := netip.ParseAddr(strings.TrimSpace(observation.GetSourceIp()))
		if err != nil || address.Zone() != "" {
			continue
		}
		lastActivity := protobufTime(observation.GetLastActivity())
		firstSeen := protobufTime(observation.GetConnectedAt())
		if lastActivity.IsZero() || firstSeen.IsZero() {
			continue
		}
		snapshot.Leases = append(snapshot.Leases, Observation{Key: LeaseKey{
			Protocol: protocol,
			Email:    strings.TrimSpace(observation.GetProfileEmail()), SourceIP: address.Unmap().String(),
		}, LastActivity: lastActivity, FirstSeen: firstSeen})
	}
	return snapshot
}

// protobufTime returns a validated protobuf timestamp in UTC, or zero on failure.
func protobufTime(value *timestamppb.Timestamp) time.Time {
	if value == nil || value.CheckValid() != nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

// randomOperationID creates an opaque idempotency key for a disconnect operation.
func randomOperationID() (string, error) {
	return randomOperationIDFrom(rand.Reader)
}

// randomOperationIDFrom reads 16 bytes of entropy and encodes them as a lease-operation ID.
func randomOperationIDFrom(source io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", fmt.Errorf("generate operation id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

// profileLogID returns a short non-reversible identifier for safe policy logs.
func profileLogID(email string) string {
	digest := sha256.Sum256([]byte(email))
	return hex.EncodeToString(digest[:8])
}

// safeError bounds an error string before it is written to the lease log.
func safeError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToValidUTF8(err.Error(), "�")
	if len(message) > 160 {
		return message[:160]
	}
	return message
}

// waitRetry waits for the retry delay unless the worker context is cancelled.
func waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// jitter applies bounded randomness to a reconnect or enforcement retry delay.
func jitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Second
	}
	spread := delay / 5
	if spread <= 0 {
		return delay
	}
	return delay - spread + time.Duration(mathrand.Int63n(int64(2*spread)+1))
}
