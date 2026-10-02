package runtime

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

type captureRuntimeEventStream struct {
	ctx      context.Context
	events   chan *xrayruntimev1.RuntimeEvent
	failAt   int
	sendErr  error
	sendCall int
}

func (s *captureRuntimeEventStream) Send(event *xrayruntimev1.RuntimeEvent) error {
	s.sendCall++
	if s.sendCall == s.failAt {
		return s.sendErr
	}
	s.events <- event
	return nil
}
func (*captureRuntimeEventStream) SetHeader(metadata.MD) error  { return nil }
func (*captureRuntimeEventStream) SendHeader(metadata.MD) error { return nil }
func (*captureRuntimeEventStream) SetTrailer(metadata.MD)       {}
func (s *captureRuntimeEventStream) Context() context.Context   { return s.ctx }
func (*captureRuntimeEventStream) SendMsg(any) error            { return nil }
func (*captureRuntimeEventStream) RecvMsg(any) error            { return io.EOF }

var _ grpc.ServerStream = (*captureRuntimeEventStream)(nil)

func TestSetLogLevelValidatesUpdatesAndFiltersXrayLogs(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetLogLevel(context.Background(), nil); err == nil {
		t.Fatal("nil log level request was accepted")
	}
	if _, err := service.SetLogLevel(context.Background(), &xrayruntimev1.SetLogLevelRequest{Level: "trace"}); err == nil {
		t.Fatal("unsupported log level was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.SetLogLevel(canceled, &xrayruntimev1.SetLogLevelRequest{Level: "debug"}); err == nil {
		t.Fatal("canceled log level request was accepted")
	}

	response, err := service.SetLogLevel(context.Background(), &xrayruntimev1.SetLogLevelRequest{Level: " DEBUG "})
	if err != nil || response.GetAlreadyApplied() || service.logLevel != "debug" {
		t.Fatalf("SetLogLevel(debug) = %+v, level=%q, err=%v", response, service.logLevel, err)
	}
	response, err = service.SetLogLevel(context.Background(), &xrayruntimev1.SetLogLevelRequest{Level: "debug"})
	if err != nil || !response.GetAlreadyApplied() {
		t.Fatalf("idempotent SetLogLevel = %+v, %v", response, err)
	}

	for _, test := range []struct {
		configured string
		level      string
		want       bool
	}{
		{"debug", "debug", true}, {"debug", "info", true}, {"debug", "unknown", true},
		{"info", "debug", false}, {"info", "warn", true}, {"warning", "info", false},
		{"warning", "error", true}, {"none", "error", false}, {"invalid", "error", true},
	} {
		service.logLevel = test.configured
		if got := service.allowXrayLog(test.level); got != test.want {
			t.Errorf("allowXrayLog(%q, %q) = %v, want %v", test.configured, test.level, got, test.want)
		}
	}
	if supportedLogLevel(" WARNING ") != true || supportedLogLevel("trace") {
		t.Fatal("supportedLogLevel did not normalize accepted levels or reject trace")
	}
}

func TestWatchEventsStreamsRedactedEventsAndCleansSubscribers(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WatchEvents(nil, nil); err == nil {
		t.Fatal("nil event request and stream were accepted")
	}
	if err := service.WatchEvents(&xrayruntimev1.WatchEventsRequest{}, nil); err == nil {
		t.Fatal("nil event stream was accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream := &captureRuntimeEventStream{ctx: ctx, events: make(chan *xrayruntimev1.RuntimeEvent, 3)}
	done := make(chan error, 1)
	go func() {
		done <- service.WatchEvents(&xrayruntimev1.WatchEventsRequest{HeartbeatIntervalMs: 1}, stream)
	}()
	select {
	case ready := <-stream.events:
		if ready.GetEvent() != "event_stream_ready" || ready.GetTimestamp() == nil {
			t.Fatalf("initial event-stream notification = %+v", ready)
		}
	case <-time.After(time.Second):
		t.Fatal("event stream did not announce readiness")
	}
	service.emitEvent("warn", "connection", "user_offline", xrayruntimev1.Protocol_PROTOCOL_VLESS, "device@xray-easy", "192.0.2.20", `failed password="hidden"`)
	select {
	case event := <-stream.events:
		if event.GetEvent() != "user_offline" || event.GetSourceIp() != "192.0.2.20" || strings.Contains(event.GetDetail(), "hidden") {
			t.Fatalf("stream event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("event stream did not forward a published event")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WatchEvents cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("event stream did not stop after cancellation")
	}
	service.eventMu.Lock()
	defer service.eventMu.Unlock()
	if len(service.eventSubscribers) != 0 {
		t.Fatalf("event subscribers leaked after cancellation: %d", len(service.eventSubscribers))
	}
}

func TestWatchEventsReturnsReadyAndEventSendFailures(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sendFailure := errors.New("stream send failed")
	readyFailure := &captureRuntimeEventStream{ctx: context.Background(), events: make(chan *xrayruntimev1.RuntimeEvent, 1), failAt: 1, sendErr: sendFailure}
	if err := service.WatchEvents(&xrayruntimev1.WatchEventsRequest{}, readyFailure); !errors.Is(err, sendFailure) {
		t.Fatalf("ready send failure = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	eventFailure := &captureRuntimeEventStream{ctx: ctx, events: make(chan *xrayruntimev1.RuntimeEvent, 1), failAt: 2, sendErr: sendFailure}
	done := make(chan error, 1)
	go func() {
		done <- service.WatchEvents(&xrayruntimev1.WatchEventsRequest{}, eventFailure)
	}()
	select {
	case <-eventFailure.events:
	case <-time.After(time.Second):
		t.Fatal("event stream did not become ready")
	}
	service.emitEvent("info", "user", "user_added", xrayruntimev1.Protocol_PROTOCOL_VLESS, "device", "", "added")
	select {
	case err := <-done:
		if !errors.Is(err, sendFailure) {
			t.Fatalf("event send failure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("event send failure did not stop the stream")
	}
	cancel()
	service.eventMu.Lock()
	defer service.eventMu.Unlock()
	if len(service.eventSubscribers) != 0 {
		t.Fatalf("event subscribers leaked after send failure: %d", len(service.eventSubscribers))
	}
}
