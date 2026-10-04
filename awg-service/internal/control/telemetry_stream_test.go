package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	awgapi "xray-easy/awg-contract/api/v1"
)

type telemetryTestDevice struct {
	mu            sync.Mutex
	snapshot      string
	snapshots     []string
	snapshotErr   error
	snapshotCalls int
}

type telemetryTestFactory struct{ device Device }

func (f telemetryTestFactory) Open(string, int) (Device, error) { return f.device, nil }

func (d *telemetryTestDevice) Set(string) error { return nil }
func (d *telemetryTestDevice) Up() error        { return nil }
func (d *telemetryTestDevice) Close()           {}
func (d *telemetryTestDevice) Snapshot() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.snapshotCalls++
	if len(d.snapshots) > 0 {
		index := d.snapshotCalls - 1
		if index >= len(d.snapshots) {
			index = len(d.snapshots) - 1
		}
		return d.snapshots[index], d.snapshotErr
	}
	return d.snapshot, d.snapshotErr
}
func (d *telemetryTestDevice) snapshotCallCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snapshotCalls
}
func (d *telemetryTestDevice) setSnapshot(value string) {
	d.mu.Lock()
	d.snapshot = value
	d.snapshots = nil
	d.snapshotErr = nil
	d.mu.Unlock()
}
func (d *telemetryTestDevice) setSnapshotSequence(values ...string) {
	d.mu.Lock()
	d.snapshots = append([]string(nil), values...)
	d.snapshotErr = nil
	d.mu.Unlock()
}
func (d *telemetryTestDevice) setSnapshotError(err error) {
	d.mu.Lock()
	d.snapshotErr = err
	d.mu.Unlock()
}

type capturePeerStatsStream struct {
	ctx     context.Context
	updates chan *awgapi.PeerStatsUpdate
	sendErr error
}

func (s *capturePeerStatsStream) Send(update *awgapi.PeerStatsUpdate) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.updates <- update
	return nil
}
func (s *capturePeerStatsStream) SetHeader(metadata.MD) error  { return nil }
func (s *capturePeerStatsStream) SendHeader(metadata.MD) error { return nil }
func (s *capturePeerStatsStream) SetTrailer(metadata.MD)       {}
func (s *capturePeerStatsStream) Context() context.Context     { return s.ctx }
func (s *capturePeerStatsStream) SendMsg(any) error            { return nil }
func (s *capturePeerStatsStream) RecvMsg(any) error            { return io.EOF }

var _ grpc.ServerStream = (*capturePeerStatsStream)(nil)

func TestWatchPeerStatsReportsCounterGrowthAndStopsWhenCanceled(t *testing.T) {
	options := testOptions(t)
	publicDevice := &telemetryTestDevice{}
	manager, err := Open(options, telemetryTestFactory{device: publicDevice})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios-device", publicKey); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicHex := hex.EncodeToString(decoded)
	publicDevice.setSnapshot("public_key=" + publicHex + "\nendpoint=198.51.100.7:44500\nrx_bytes=10\ntx_bytes=20\n")
	service := NewService(manager, options)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturePeerStatsStream{ctx: ctx, updates: make(chan *awgapi.PeerStatsUpdate, 4)}
	done := make(chan error, 1)
	go func() { done <- service.WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 500}, stream) }()
	var initial *awgapi.PeerStatsUpdate
	select {
	case initial = <-stream.updates:
	case <-time.After(time.Second):
		t.Fatal("AWG did not send the initial snapshot")
	}
	if !initial.GetFullSnapshot() || initial.GetSequence() != 1 || initial.GetSourceGeneration() == "" || len(initial.GetPeers()) != 1 || initial.GetPeers()[0].GetOnline() {
		t.Fatalf("initial AWG snapshot = %+v", initial)
	}
	publicDevice.setSnapshot("public_key=" + publicHex + "\nendpoint=198.51.100.7:44500\nrx_bytes=35\ntx_bytes=60\n")
	var active *awgapi.PeerStatsUpdate
	select {
	case active = <-stream.updates:
	case <-time.After(2 * time.Second):
		t.Fatal("AWG did not publish changed counters")
	}
	peer := active.GetPeers()[0]
	if !peer.GetOnline() || peer.GetUploadBytes() != 35 || peer.GetDownloadBytes() != 60 || peer.GetLastActivity() == nil || peer.GetSourceIp() != "198.51.100.7" {
		t.Fatalf("active AWG peer snapshot = %+v", peer)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("WatchPeerStats cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AWG telemetry stream did not stop after cancellation")
	}
	if strings.Contains(initial.String(), "private") {
		t.Fatalf("stream unexpectedly included private key material: %s", initial)
	}
}

func TestWatchPeerStatsMarksPeerOfflineAfterTrafficTTL(t *testing.T) {
	options := testOptions(t)
	device := &telemetryTestDevice{}
	manager, err := Open(options, telemetryTestFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios-device", publicKey); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicHex := hex.EncodeToString(decoded)
	activity := time.Now().UTC().Truncate(time.Second)
	device.setSnapshot(fmt.Sprintf("public_key=%s\nendpoint=198.51.100.7:44500\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\nrx_bytes=10\ntx_bytes=20\n", publicHex, activity.Unix(), activity.Nanosecond()))

	service := NewService(manager, options)
	sample := 0
	service.telemetryNow = func() time.Time {
		sample++
		if sample == 1 {
			return activity
		}
		return activity.Add(16 * time.Second)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturePeerStatsStream{ctx: ctx, updates: make(chan *awgapi.PeerStatsUpdate, 3)}
	done := make(chan error, 1)
	go func() {
		done <- service.WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 500}, stream)
	}()
	var active, offline *awgapi.PeerStatsUpdate
	select {
	case active = <-stream.updates:
	case <-time.After(time.Second):
		t.Fatal("AWG did not send its initial peer snapshot")
	}
	if len(active.GetPeers()) != 1 || !active.GetPeers()[0].GetOnline() {
		t.Fatalf("initial peer status = %+v, want online", active.GetPeers())
	}
	select {
	case offline = <-stream.updates:
	case <-time.After(2 * time.Second):
		t.Fatal("AWG did not send the idle peer snapshot")
	}
	peer := offline.GetPeers()[0]
	if peer.GetOnline() || peer.GetSourceIp() != "" {
		t.Fatalf("peer after traffic TTL = %+v, want offline without source IP", peer)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("WatchPeerStats cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AWG telemetry stream did not stop after cancellation")
	}
}

type lockedLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedLogBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(value)
}

func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestRunConnectionMonitorLogsTransitionsWithoutTelemetryStream(t *testing.T) {
	logs := &lockedLogBuffer{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	options := testOptions(t)
	device := &telemetryTestDevice{}
	manager, err := Open(options, telemetryTestFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios-device", publicKey); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicHex := hex.EncodeToString(decoded)
	activity := time.Now().UTC().Truncate(time.Second)
	device.setSnapshot(fmt.Sprintf("public_key=%s\nendpoint=198.51.100.7:44500\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=%d\nrx_bytes=10\ntx_bytes=20\n", publicHex, activity.Unix(), activity.Nanosecond()))
	service := NewService(manager, options)
	sample := 0
	service.telemetryNow = func() time.Time {
		sample++
		if sample == 1 {
			return activity
		}
		return activity.Add(16 * time.Second)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runConnectionMonitor(ctx, 10*time.Millisecond)
	}()
	deadline := time.After(time.Second)
	for {
		output := logs.String()
		if strings.Contains(output, `"event":"peer_online"`) && strings.Contains(output, `"event":"peer_offline"`) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("background monitor did not log both transitions; logs=%s", output)
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("background connection monitor did not stop after cancellation")
	}
	output := logs.String()
	if got := strings.Count(output, `"event":"peer_online"`); got != 1 {
		t.Fatalf("online event count = %d, want one; logs=%s", got, output)
	}
	if got := strings.Count(output, `"event":"peer_offline"`); got != 1 {
		t.Fatalf("offline event count = %d, want one; logs=%s", got, output)
	}
	if !strings.Contains(output, `"peer_name":"ios-device"`) || !strings.Contains(output, `"source_ip":"198.51.100.7"`) {
		t.Fatalf("connection logs omitted peer identity/source: %s", output)
	}
}

func TestRunConnectionMonitorRecoversFromSnapshotFailureAndIgnoresNilInputs(t *testing.T) {
	logs := &lockedLogBuffer{}
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	var nilService *Service
	nilService.RunConnectionMonitor(context.Background())
	serviceWithoutManager := &Service{}
	serviceWithoutManager.RunConnectionMonitor(context.Background())
	serviceWithoutManager.runConnectionMonitor(context.Background(), time.Millisecond)
	serviceWithoutManager.runConnectionMonitor(nil, time.Millisecond)
	serviceWithoutManager.runConnectionMonitor(context.Background(), 0)

	options := testOptions(t)
	device := &telemetryTestDevice{}
	manager, err := Open(options, telemetryTestFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	canceled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	service.RunConnectionMonitor(canceled)
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("tablet", publicKey); err != nil {
		t.Fatal(err)
	}
	device.setSnapshotError(errors.New("temporary kernel snapshot error"))
	now := time.Now().UTC().Truncate(time.Second)
	service.telemetryNow = func() time.Time { return now }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runConnectionMonitor(ctx, 10*time.Millisecond)
	}()
	waitFor := func(predicate func(string) bool, label string) {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			output := logs.String()
			if predicate(output) {
				return
			}
			select {
			case <-deadline:
				t.Fatalf("connection monitor did not log %s; logs=%s", label, output)
			case <-time.After(time.Millisecond):
			}
		}
	}
	waitFor(func(output string) bool { return strings.Contains(output, `"event":"snapshot_failed"`) }, "snapshot failure")

	decoded, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	device.setSnapshot(fmt.Sprintf("public_key=%s\nendpoint=198.51.100.9:12345\nlast_handshake_time_sec=%d\nlast_handshake_time_nsec=0\nrx_bytes=10\ntx_bytes=20\n", hex.EncodeToString(decoded), now.Unix()))
	waitFor(func(output string) bool {
		return strings.Contains(output, `"event":"snapshot_recovered"`) && strings.Contains(output, `"event":"peer_online"`)
	}, "snapshot recovery and peer online transition")
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection monitor did not stop after context cancellation")
	}
	output := logs.String()
	if got := strings.Count(output, `"event":"snapshot_failed"`); got != 1 {
		t.Fatalf("snapshot failure log count = %d, want one; logs=%s", got, output)
	}
	if got := strings.Count(output, `"event":"snapshot_recovered"`); got != 1 {
		t.Fatalf("snapshot recovery log count = %d, want one; logs=%s", got, output)
	}
	if !strings.Contains(output, `"source_ip":"198.51.100.9"`) {
		t.Fatalf("online event omitted observed source IP: %s", output)
	}
}

func TestWatchPeerStatsClampsSampleInterval(t *testing.T) {
	for _, interval := range []uint32{1, 10_000} {
		t.Run(time.Duration(interval).String(), func(t *testing.T) {
			options := testOptions(t)
			manager, err := Open(options, telemetryTestFactory{device: &telemetryTestDevice{}})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			ctx, cancel := context.WithCancel(context.Background())
			stream := &capturePeerStatsStream{ctx: ctx, updates: make(chan *awgapi.PeerStatsUpdate, 1)}
			done := make(chan error, 1)
			go func() {
				done <- NewService(manager, options).WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: interval}, stream)
			}()
			select {
			case update := <-stream.updates:
				if !update.GetFullSnapshot() {
					t.Fatalf("first clamped stream update is not a full snapshot: %+v", update)
				}
			case <-time.After(time.Second):
				t.Fatal("AWG did not immediately send a snapshot")
			}
			cancel()
			select {
			case err := <-done:
				if err != context.Canceled {
					t.Fatalf("WatchPeerStats cancellation error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("AWG telemetry stream did not stop after cancellation")
			}
		})
	}
}

func TestWatchPeerStatsRejectsNilRequestAndPropagatesSendFailure(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, telemetryTestFactory{device: &telemetryTestDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, options)
	if err := service.WatchPeerStats(nil, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil stream request error = %v", err)
	}
	sendErr := errors.New("downstream closed")
	stream := &capturePeerStatsStream{ctx: context.Background(), updates: make(chan *awgapi.PeerStatsUpdate, 1), sendErr: sendErr}
	if err := service.WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 1000}, stream); !errors.Is(err, sendErr) {
		t.Fatalf("downstream send error = %v, want %v", err, sendErr)
	}
}
