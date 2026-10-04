package control

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
	awgapi "xray-easy/awg-contract/api/v1"
)

type callbackPeerStatsStream struct {
	ctx   context.Context
	send  func(*awgapi.PeerStatsUpdate) error
	sends int
}

func (s *callbackPeerStatsStream) Send(update *awgapi.PeerStatsUpdate) error {
	s.sends++
	return s.send(update)
}
func (*callbackPeerStatsStream) SetHeader(metadata.MD) error  { return nil }
func (*callbackPeerStatsStream) SendHeader(metadata.MD) error { return nil }
func (*callbackPeerStatsStream) SetTrailer(metadata.MD)       {}
func (s *callbackPeerStatsStream) Context() context.Context   { return s.ctx }
func (*callbackPeerStatsStream) SendMsg(any) error            { return nil }
func (*callbackPeerStatsStream) RecvMsg(any) error            { return io.EOF }

func TestWatchPeerStatsHandlesSnapshotFailureAndPrunesRemovedPeer(t *testing.T) {
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
	peer, err := manager.AddPeer("phone", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	device.setSnapshot(fmt.Sprintf("public_key=%s\nrx_bytes=1\ntx_bytes=1\n", hex.EncodeToString(decoded)))
	service := NewService(manager, options)

	device.setSnapshotError(errors.New("temporary UAPI error"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stream *callbackPeerStatsStream
	stream = &callbackPeerStatsStream{ctx: ctx, send: func(*awgapi.PeerStatsUpdate) error {
		return errors.New("send must not be reached after snapshot failure")
	}}
	if err := service.WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 500}, stream); err == nil {
		t.Fatal("WatchPeerStats() succeeded after the device snapshot failed")
	}

	device.setSnapshot(fmt.Sprintf("public_key=%s\nrx_bytes=1\ntx_bytes=1\n", hex.EncodeToString(decoded)))
	sends := 0
	stream.send = func(update *awgapi.PeerStatsUpdate) error {
		sends++
		if sends == 1 {
			if len(update.GetPeers()) != 1 {
				t.Fatalf("initial snapshot peers = %d, want 1", len(update.GetPeers()))
			}
			if err := manager.RemovePeer(peer.Name); err != nil {
				t.Fatalf("remove peer after initial snapshot: %v", err)
			}
			return nil
		}
		if len(update.GetPeers()) != 0 {
			t.Errorf("snapshot after peer removal still has %d peers", len(update.GetPeers()))
		}
		cancel()
		return nil
	}
	if err := service.WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 500}, stream); !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchPeerStats() after cancellation = %v, want context.Canceled", err)
	}
	if sends < 2 {
		t.Fatalf("WatchPeerStats() sent %d updates, want initial and post-removal snapshots", sends)
	}
}

func TestWatchPeerStatsReturnsSubsequentSendFailure(t *testing.T) {
	options := testOptions(t)
	manager, err := Open(options, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sendFailure := errors.New("stream send failed")
	var stream *callbackPeerStatsStream
	stream = &callbackPeerStatsStream{ctx: ctx, send: func(*awgapi.PeerStatsUpdate) error {
		if stream.sends == 2 {
			return sendFailure
		}
		return nil
	}}
	err = NewService(manager, options).WatchPeerStats(&awgapi.WatchPeerStatsRequest{SampleIntervalMs: 500}, stream)
	if !errors.Is(err, sendFailure) {
		t.Fatalf("WatchPeerStats() = %v, want the second-send error", err)
	}
}

func TestRunConnectionMonitorPrunesRemovedPeers(t *testing.T) {
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
	peer, err := manager.AddPeer("phone", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	device.setSnapshot(fmt.Sprintf("public_key=%s\nrx_bytes=1\ntx_bytes=1\n", hex.EncodeToString(decoded)))
	service := NewService(manager, options)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		service.runConnectionMonitor(ctx, 5*time.Millisecond)
	}()
	deadline := time.After(time.Second)
	for device.snapshotCallCount() == 0 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("connection monitor did not take its initial sample")
		case <-time.After(time.Millisecond):
		}
	}
	if err := manager.RemovePeer(peer.Name); err != nil {
		cancel()
		<-done
		t.Fatal(err)
	}
	for device.snapshotCallCount() < 2 {
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("connection monitor did not take its initial sample")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection monitor did not stop")
	}
}
