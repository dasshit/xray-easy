package runtime

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

type captureTelemetryServerStream struct {
	ctx     context.Context
	updates chan *xrayruntimev1.TelemetryResponse
}

func (s *captureTelemetryServerStream) Send(update *xrayruntimev1.TelemetryResponse) error {
	s.updates <- update
	return nil
}
func (s *captureTelemetryServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *captureTelemetryServerStream) SendHeader(metadata.MD) error { return nil }
func (s *captureTelemetryServerStream) SetTrailer(metadata.MD)       {}
func (s *captureTelemetryServerStream) Context() context.Context     { return s.ctx }
func (s *captureTelemetryServerStream) SendMsg(any) error            { return nil }
func (s *captureTelemetryServerStream) RecvMsg(any) error            { return io.EOF }

var _ grpc.ServerStream = (*captureTelemetryServerStream)(nil)

func TestWatchTelemetrySendsFullSnapshotAndStopsOnCancellation(t *testing.T) {
	configuration := []byte(`{"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}}},"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	now := time.Now().UTC()
	engine := &fakeEngine{stats: true, telemetry: []RuntimeUserTelemetry{{
		Email: "device@xray-easy", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS,
		UploadBytes: 50, DownloadBytes: 75, LastSeen: now,
		SourceIPs: []RuntimeIPObservation{{Address: "192.0.2.8", LastSeen: now}},
	}}}
	service, err := NewService(&fakeLoader{engine: engine}, "test", configuration, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	stream := &captureTelemetryServerStream{ctx: ctx, updates: make(chan *xrayruntimev1.TelemetryResponse, 2)}
	done := make(chan error, 1)
	go func() {
		done <- service.WatchTelemetry(&xrayruntimev1.WatchTelemetryRequest{SampleIntervalMs: 1000}, stream)
	}()
	var first *xrayruntimev1.TelemetryResponse
	select {
	case first = <-stream.updates:
	case <-time.After(time.Second):
		t.Fatal("runtime did not send the initial telemetry snapshot")
	}
	if !first.GetFullSnapshot() || first.GetSequence() != 1 || first.GetSourceGeneration() == "" || len(first.GetUsers()) != 1 {
		t.Fatalf("initial runtime snapshot = %+v", first)
	}
	user := first.GetUsers()[0]
	if user.GetProtocol() != xrayruntimev1.Protocol_PROTOCOL_VLESS || user.GetUploadBytes() != 50 || user.GetDownloadBytes() != 75 || !user.GetOnline() || len(user.GetSourceIps()) != 1 {
		t.Fatalf("runtime user snapshot = %+v", user)
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("WatchTelemetry cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime telemetry stream did not stop after cancellation")
	}
}

func TestWatchTelemetryMarksUserOnlineAfterObservedCounterIncrease(t *testing.T) {
	configuration := []byte(`{"stats":{},"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true,"statsUserOnline":true}}},"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	engine := &fakeEngine{stats: true, telemetrySequence: [][]RuntimeUserTelemetry{
		{{Email: "device@xray-easy", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, UploadBytes: 10}},
		{{Email: "device@xray-easy", Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, UploadBytes: 15, SourceIPs: []RuntimeIPObservation{{Address: "198.51.100.88"}}}},
	}}
	service, err := NewService(&fakeLoader{engine: engine}, "test", configuration, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	stream := &captureTelemetryServerStream{ctx: ctx, updates: make(chan *xrayruntimev1.TelemetryResponse, 3)}
	done := make(chan error, 1)
	go func() {
		done <- service.WatchTelemetry(&xrayruntimev1.WatchTelemetryRequest{SampleIntervalMs: 500}, stream)
	}()
	select {
	case initial := <-stream.updates:
		if initial.GetUsers()[0].GetOnline() {
			t.Fatalf("user without fresh traffic was online: %+v", initial.GetUsers()[0])
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not send the initial snapshot")
	}
	select {
	case active := <-stream.updates:
		user := active.GetUsers()[0]
		if !user.GetOnline() || user.GetUploadBytes() != 15 || user.GetLastActivity() == nil {
			t.Fatalf("user did not become online after counter increase: %+v", user)
		}
		logs, err := service.GetRecentLogs(context.Background(), new(xrayruntimev1.EmptyRequest))
		if err != nil {
			t.Fatalf("read runtime logs: %v", err)
		}
		found := false
		for _, entry := range logs.GetEntries() {
			if strings.Contains(entry.GetMessage(), "user_online") && strings.Contains(entry.GetMessage(), "device@xray-easy") && strings.Contains(entry.GetMessage(), "[REDACTED-IP]") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("online transition was not written to runtime logs: %+v", logs.GetEntries())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime did not publish a second telemetry sample")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("WatchTelemetry cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime stream did not stop after cancellation")
	}
}

func TestWatchTelemetryClampsSampleIntervalBounds(t *testing.T) {
	for _, test := range []struct {
		name     string
		interval uint32
	}{{name: "below minimum", interval: 1}, {name: "above maximum", interval: 6000}} {
		t.Run(test.name, func(t *testing.T) {
			configuration := []byte(`{"stats":{},"inbounds":[]}`)
			service, err := NewService(&fakeLoader{engine: &fakeEngine{stats: true}}, "test", configuration, 1)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			stream := &captureTelemetryServerStream{ctx: ctx, updates: make(chan *xrayruntimev1.TelemetryResponse, 1)}
			done := make(chan error, 1)
			go func() {
				done <- service.WatchTelemetry(&xrayruntimev1.WatchTelemetryRequest{SampleIntervalMs: test.interval}, stream)
			}()
			select {
			case update := <-stream.updates:
				if !update.GetFullSnapshot() {
					t.Fatalf("initial snapshot = %+v", update)
				}
			case <-time.After(time.Second):
				t.Fatal("runtime did not send the initial telemetry snapshot")
			}
			cancel()
			select {
			case err := <-done:
				if err != context.Canceled {
					t.Fatalf("WatchTelemetry() cancellation = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("runtime telemetry stream did not stop after cancellation")
			}
		})
	}
}
