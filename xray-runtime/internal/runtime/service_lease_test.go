package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

func TestServiceDisconnectLeaseAndCapabilities(t *testing.T) {
	engine := &fakeEngine{
		stats: true,
		leaseProtocols: map[xrayruntimev1.Protocol]bool{
			xrayruntimev1.Protocol_PROTOCOL_VLESS: true,
		},
		leaseDisconnectClosed: 2,
	}
	service, err := NewService(&fakeLoader{engine: engine}, "v", []byte(`{"inbounds":[{"protocol":"vless","tag":"vless"},{"protocol":"trojan","tag":"trojan"}]}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	capabilities, err := service.GetCapabilities(context.Background(), new(xrayruntimev1.EmptyRequest))
	if err != nil || len(capabilities.GetProtocols()) != 2 {
		t.Fatalf("capabilities = %+v, %v", capabilities, err)
	}
	if !capabilities.GetProtocols()[0].GetLeaseDisconnect() || capabilities.GetProtocols()[1].GetLeaseDisconnect() {
		t.Fatalf("lease disconnect capabilities = %+v", capabilities.GetProtocols())
	}
	request := &xrayruntimev1.DisconnectLeaseRequest{
		Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "profile", SourceIp: "::ffff:192.0.2.1",
		OperationId: "close-profile-1", SourceGeneration: runtimeGeneration(service.startedAt),
	}
	response, err := service.DisconnectLease(context.Background(), request)
	if err != nil || response.GetOperationId() != request.GetOperationId() || response.GetClosedConnections() != 2 || response.GetAlreadyApplied() {
		t.Fatalf("disconnect response = %+v, %v", response, err)
	}
	if engine.leaseDisconnectCalls != 1 || engine.leaseDisconnectInput.GetSourceIp() != "192.0.2.1" || engine.leaseDisconnectInput.GetEmail() != "profile" {
		t.Fatalf("engine disconnect input = %+v calls=%d", engine.leaseDisconnectInput, engine.leaseDisconnectCalls)
	}
	engine.leaseDisconnectAlready = true
	response, err = service.DisconnectLease(context.Background(), request)
	if err != nil || !response.GetAlreadyApplied() {
		t.Fatalf("idempotent response = %+v, %v", response, err)
	}
}

func TestServiceDisconnectLeaseRejectsInvalidRequests(t *testing.T) {
	engine := &fakeEngine{leaseProtocols: map[xrayruntimev1.Protocol]bool{xrayruntimev1.Protocol_PROTOCOL_VLESS: true}}
	service, err := NewService(&fakeLoader{engine: engine}, "v", []byte(`{"inbounds":[{"protocol":"vless","tag":"vless"}]}`), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	valid := &xrayruntimev1.DisconnectLeaseRequest{
		Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "profile", SourceIp: "192.0.2.1",
		OperationId: "close", SourceGeneration: runtimeGeneration(service.startedAt),
	}
	tests := []struct {
		name    string
		request *xrayruntimev1.DisconnectLeaseRequest
		want    codes.Code
	}{
		{name: "missing request", want: codes.InvalidArgument},
		{name: "unknown protocol", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) {
			r.Protocol = xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED
		}), want: codes.InvalidArgument},
		{name: "empty operation ID", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.OperationId = " " }), want: codes.InvalidArgument},
		{name: "oversize operation ID", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) {
			r.OperationId = strings.Repeat("x", maxOperationIDBytes+1)
		}), want: codes.InvalidArgument},
		{name: "empty email", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.Email = " " }), want: codes.InvalidArgument},
		{name: "oversize email", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.Email = strings.Repeat("x", maxUserEmailBytes+1) }), want: codes.InvalidArgument},
		{name: "invalid IP", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.SourceIp = "client.example" }), want: codes.InvalidArgument},
		{name: "zoned IP", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.SourceIp = "fe80::1%eth0" }), want: codes.InvalidArgument},
		{name: "missing generation", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.SourceGeneration = "" }), want: codes.Aborted},
		{name: "stale generation", request: copyLeaseRequest(valid, func(r *xrayruntimev1.DisconnectLeaseRequest) { r.SourceGeneration = "old" }), want: codes.Aborted},
	}
	for _, testcase := range tests {
		t.Run(testcase.name, func(t *testing.T) {
			_, err := service.DisconnectLease(context.Background(), testcase.request)
			if status.Code(err) != testcase.want {
				t.Fatalf("DisconnectLease error = %v (%s), want %s", err, status.Code(err), testcase.want)
			}
		})
	}
	if engine.leaseDisconnectCalls != 0 {
		t.Fatalf("invalid requests reached engine %d times", engine.leaseDisconnectCalls)
	}
}

func TestServiceDisconnectLeaseAvailabilityAndErrors(t *testing.T) {
	config := []byte(`{"inbounds":[{"protocol":"vless","tag":"vless"}]}`)
	makeRequest := func(service *Service) *xrayruntimev1.DisconnectLeaseRequest {
		return &xrayruntimev1.DisconnectLeaseRequest{
			Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "profile", SourceIp: "192.0.2.1",
			OperationId: "close", SourceGeneration: runtimeGeneration(service.startedAt),
		}
	}
	t.Run("no active config", func(t *testing.T) {
		service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "v", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		_, err = service.DisconnectLease(context.Background(), makeRequest(service))
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("disconnect without active config = %v", err)
		}
	})
	t.Run("protocol unsupported", func(t *testing.T) {
		engine := &fakeEngine{leaseProtocols: map[xrayruntimev1.Protocol]bool{}}
		service, err := NewService(&fakeLoader{engine: engine}, "v", config, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		_, err = service.DisconnectLease(context.Background(), makeRequest(service))
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("unsupported disconnect = %v", err)
		}
	})
	for _, testcase := range []struct {
		name  string
		cause error
		want  codes.Code
	}{
		{name: "canceled", cause: context.Canceled, want: codes.Canceled},
		{name: "deadline", cause: context.DeadlineExceeded, want: codes.DeadlineExceeded},
		{name: "internal", cause: errors.New("private detail"), want: codes.Internal},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			engine := &fakeEngine{leaseProtocols: map[xrayruntimev1.Protocol]bool{xrayruntimev1.Protocol_PROTOCOL_VLESS: true}, leaseDisconnectErr: testcase.cause}
			service, err := NewService(&fakeLoader{engine: engine}, "v", config, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			_, err = service.DisconnectLease(context.Background(), makeRequest(service))
			if status.Code(err) != testcase.want {
				t.Fatalf("disconnect error = %v (%s), want %s", err, status.Code(err), testcase.want)
			}
			if testcase.want == codes.Internal && strings.Contains(err.Error(), "private detail") {
				t.Fatalf("internal error leaked details: %v", err)
			}
		})
	}
}

func copyLeaseRequest(source *xrayruntimev1.DisconnectLeaseRequest, mutate func(*xrayruntimev1.DisconnectLeaseRequest)) *xrayruntimev1.DisconnectLeaseRequest {
	if source == nil {
		return nil
	}
	copy := *source
	mutate(&copy)
	return &copy
}
