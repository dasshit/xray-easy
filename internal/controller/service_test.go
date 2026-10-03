package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRuntime struct {
	status           domain.XrayRuntimeStatus
	logs             []string
	err              error
	called           string
	args             []string
	requestID        string
	operationID      string
	attempt          int
	stateRevision    int64
	leaseRequest     *xrayruntimev1.DisconnectLeaseRequest
	leaseResponse    *xrayruntimev1.DisconnectLeaseResponse
	leaseResponseSet bool
}

func (f *fakeRuntime) Health(ctx context.Context) error {
	f.called = "Health"
	f.requestID = interaction.IncomingRequestID(ctx)
	f.operationID = interaction.OperationID(ctx)
	f.attempt = interaction.Attempt(ctx)
	f.stateRevision = interaction.StateRevision(ctx)
	return f.err
}
func (f *fakeRuntime) Status(context.Context) (domain.XrayRuntimeStatus, error) {
	f.called = "Status"
	return f.status, f.err
}
func (f *fakeRuntime) Logs(context.Context) ([]string, error) {
	f.called = "Logs"
	return f.logs, f.err
}
func (f *fakeRuntime) Validate(ctx context.Context, path, operation string) error {
	f.called = "Validate"
	f.args = []string{path, operation}
	f.operationID = interaction.OperationID(ctx)
	f.stateRevision = interaction.StateRevision(ctx)
	return f.err
}
func (f *fakeRuntime) Apply(ctx context.Context, path, operation string) error {
	f.called = "Apply"
	f.args = []string{path, operation}
	f.operationID = interaction.OperationID(ctx)
	f.stateRevision = interaction.StateRevision(ctx)
	return f.err
}
func (f *fakeRuntime) ReplaceInbound(ctx context.Context, candidate, previous, tag, operation string) error {
	f.called = "ReplaceInbound"
	f.args = []string{candidate, previous, tag, operation}
	f.operationID = interaction.OperationID(ctx)
	f.stateRevision = interaction.StateRevision(ctx)
	return f.err
}
func (f *fakeRuntime) ProbeTarget(_ context.Context, target, sni string) error {
	f.called = "ProbeTarget"
	f.args = []string{target, sni}
	return f.err
}
func (f *fakeRuntime) ProbeIPv6(context.Context) error { f.called = "ProbeIPv6"; return f.err }
func (f *fakeRuntime) SetLogLevel(context.Context, string) error {
	f.called = "SetLogLevel"
	return f.err
}

func (f *fakeRuntime) DisconnectLease(_ context.Context, request *xrayruntimev1.DisconnectLeaseRequest) (*xrayruntimev1.DisconnectLeaseResponse, error) {
	f.called = "DisconnectLease"
	f.leaseRequest = request
	if f.leaseResponseSet {
		return f.leaseResponse, f.err
	}
	return &xrayruntimev1.DisconnectLeaseResponse{OperationId: request.GetOperationId(), ClosedConnections: 1}, f.err
}

type runtimeWithoutLease struct{ XrayRuntime }

func TestServiceHealthStatusAndLogs(t *testing.T) {
	runtime := &fakeRuntime{
		status: domain.XrayRuntimeStatus{Protocol: "embedded-core", XrayVersion: "26.7.28", State: "running", StartedAt: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), ActiveRevision: 17, InboundTags: []string{"vless-reality", "vmess-tls"}, StatsAvailable: true},
		logs:   []string{"warn: sanitized"},
	}
	service := NewService(runtime)
	health, err := service.Health(context.Background(), &controllerv1.EmptyRequest{})
	if err != nil || !health.GetOk() || health.GetControllerVersion() == "" {
		t.Fatalf("Health() = %v, %v", health, err)
	}
	result, err := service.GetStatus(context.Background(), &controllerv1.EmptyRequest{})
	if err != nil || result.GetXrayVersion() != "26.7.28" || result.GetStartedAt().AsTime() != runtime.status.StartedAt || result.GetActiveRevision() != 17 || len(result.GetInboundTags()) != 2 || !result.GetStatsAvailable() {
		t.Fatalf("GetStatus() = %v, %v", result, err)
	}
	logs, err := service.GetLogs(context.Background(), &controllerv1.EmptyRequest{})
	if err != nil || len(logs.GetLines()) != 1 || logs.GetLines()[0] != "warn: sanitized" {
		t.Fatalf("GetLogs() = %v, %v", logs, err)
	}
	if response, err := service.GetCapabilities(context.Background(), &controllerv1.EmptyRequest{}); err != nil || !response.Xray.Configured || response.Amneziawg.Configured {
		t.Fatalf("GetCapabilities() = %v, %v", response, err)
	}
}

func TestServiceDisconnectLeaseValidationAndNormalization(t *testing.T) {
	runtime := &fakeRuntime{}
	service := NewService(runtime)
	request := &controllerv1.DisconnectLeaseRequest{
		Protocol: "vless", ProfileEmail: "ios@xray-easy", SourceIp: "::ffff:192.0.2.10",
		OperationId: "0123456789abcdef0123456789abcdef", SourceGeneration: "runtime-generation-1",
	}
	response, err := service.DisconnectLease(context.Background(), request)
	if err != nil || response.GetClosedConnections() != 1 || runtime.leaseRequest.GetSourceIp() != "192.0.2.10" || runtime.leaseRequest.GetProtocol() != xrayruntimev1.Protocol_PROTOCOL_VLESS {
		t.Fatalf("DisconnectLease() = %+v, runtime request=%+v, err=%v", response, runtime.leaseRequest, err)
	}
	invalid := *request
	invalid.OperationId = "bad"
	if _, err := service.DisconnectLease(context.Background(), &invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid lease operation error = %v", err)
	}
	unsupported := *request
	unsupported.Protocol = "hysteria2"
	if _, err := service.DisconnectLease(context.Background(), &unsupported); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unsupported lease protocol error = %v", err)
	}
}

func TestServiceDisconnectLeaseRejectsInvalidIdentityAndUnsupportedRuntime(t *testing.T) {
	valid := &controllerv1.DisconnectLeaseRequest{Protocol: "trojan", ProfileEmail: "device@xray-easy", SourceIp: "2001:db8::8", OperationId: "0123456789abcdef0123456789abcdef", SourceGeneration: "runtime-generation"}
	service := NewService(&fakeRuntime{})
	if _, err := service.DisconnectLease(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request error=%v", err)
	}
	tests := []struct {
		name   string
		change func(*controllerv1.DisconnectLeaseRequest)
	}{
		{"empty profile", func(request *controllerv1.DisconnectLeaseRequest) { request.ProfileEmail = " " }},
		{"oversized profile", func(request *controllerv1.DisconnectLeaseRequest) { request.ProfileEmail = strings.Repeat("x", 257) }},
		{"control character profile", func(request *controllerv1.DisconnectLeaseRequest) { request.ProfileEmail = "profile\nname" }},
		{"invalid hex operation", func(request *controllerv1.DisconnectLeaseRequest) { request.OperationId = strings.Repeat("g", 32) }},
		{"missing generation", func(request *controllerv1.DisconnectLeaseRequest) { request.SourceGeneration = " " }},
		{"oversized generation", func(request *controllerv1.DisconnectLeaseRequest) {
			request.SourceGeneration = strings.Repeat("g", 129)
		}},
		{"invalid source address", func(request *controllerv1.DisconnectLeaseRequest) { request.SourceIp = "not-an-ip" }},
		{"zoned source address", func(request *controllerv1.DisconnectLeaseRequest) { request.SourceIp = "fe80::1%en0" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := *valid
			test.change(&request)
			if _, err := service.DisconnectLease(context.Background(), &request); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("invalid lease identity error=%v", err)
			}
		})
	}
	if _, err := NewService(runtimeWithoutLease{XrayRuntime: &fakeRuntime{}}).DisconnectLease(context.Background(), valid); status.Code(err) != codes.Unimplemented {
		t.Fatalf("runtime without disconnect support error=%v", err)
	}
}

func TestServiceDisconnectLeaseMapsRuntimeErrorsAndInvalidResults(t *testing.T) {
	request := &controllerv1.DisconnectLeaseRequest{Protocol: "vless", ProfileEmail: "device", SourceIp: "192.0.2.2", OperationId: "0123456789abcdef0123456789abcdef", SourceGeneration: "runtime-generation"}
	for _, test := range []struct {
		name string
		err  error
		want codes.Code
	}{
		{"retryable runtime status", status.Error(codes.Unavailable, "offline"), codes.Unavailable},
		{"unexpected runtime error", errors.New("private runtime detail"), codes.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewService(&fakeRuntime{err: test.err}).DisconnectLease(context.Background(), request)
			if status.Code(err) != test.want || strings.Contains(err.Error(), "private runtime detail") {
				t.Fatalf("runtime error mapping=%v, want %s", err, test.want)
			}
		})
	}
	for _, result := range []*xrayruntimev1.DisconnectLeaseResponse{nil, {OperationId: "different-operation"}} {
		runtime := &fakeRuntime{leaseResponse: result, leaseResponseSet: true}
		if _, err := NewService(runtime).DisconnectLease(context.Background(), request); status.Code(err) != codes.Internal {
			t.Fatalf("invalid runtime response=%+v error=%v", result, err)
		}
	}
}

func TestServiceDelegatesRuntimeOperations(t *testing.T) {
	tests := []struct {
		name       string
		call       func(*Service) error
		wantMethod string
		wantArgs   []string
	}{
		{"validate", func(s *Service) error {
			_, err := s.ValidateConfig(context.Background(), &controllerv1.ValidateConfigRequest{Path: "/tmp/candidate", OperationId: "11111111111111111111111111111111", StateRevision: 21})
			return err
		}, "Validate", []string{"/tmp/candidate", "11111111111111111111111111111111"}},
		{"apply", func(s *Service) error {
			_, err := s.ApplyConfig(context.Background(), &controllerv1.ApplyConfigRequest{Path: "/tmp/candidate", OperationId: "22222222222222222222222222222222", StateRevision: 22})
			return err
		}, "Apply", []string{"/tmp/candidate", "22222222222222222222222222222222"}},
		{"replace", func(s *Service) error {
			_, err := s.ReplaceInbound(context.Background(), &controllerv1.ReplaceInboundRequest{CandidatePath: "new", PreviousPath: "old", Tag: "vless", OperationId: "33333333333333333333333333333333", StateRevision: 23})
			return err
		}, "ReplaceInbound", []string{"new", "old", "vless", "33333333333333333333333333333333"}},
		{"target", func(s *Service) error {
			_, err := s.ProbeTarget(context.Background(), &controllerv1.ProbeTargetRequest{Target: "example.com:443", Sni: "example.com"})
			return err
		}, "ProbeTarget", []string{"example.com:443", "example.com"}},
		{"ipv6", func(s *Service) error {
			_, err := s.ProbeIPv6(context.Background(), &controllerv1.EmptyRequest{})
			return err
		}, "ProbeIPv6", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			if err := test.call(NewService(runtime)); err != nil {
				t.Fatal(err)
			}
			if runtime.called != test.wantMethod || len(runtime.args) != len(test.wantArgs) {
				t.Fatalf("runtime call = %q %v, want %q %v", runtime.called, runtime.args, test.wantMethod, test.wantArgs)
			}
			for i := range test.wantArgs {
				if runtime.args[i] != test.wantArgs[i] {
					t.Fatalf("runtime args = %v, want %v", runtime.args, test.wantArgs)
				}
			}
			if test.name != "target" && test.name != "ipv6" && (runtime.operationID == "" || runtime.stateRevision == 0) {
				t.Fatalf("config operation trace was not attached: operation=%q revision=%d", runtime.operationID, runtime.stateRevision)
			}
		})
	}
}

func TestConfigOperationContextBindsOperationAndRevision(t *testing.T) {
	operationID := "abcdef0123456789abcdef0123456789"
	ctx, err := configOperationContext(context.Background(), operationID, 42)
	if err != nil || interaction.OperationID(ctx) != operationID || interaction.StateRevision(ctx) != 42 {
		t.Fatalf("config operation trace = %q/%d, %v", interaction.OperationID(ctx), interaction.StateRevision(ctx), err)
	}
	for _, test := range []struct {
		name      string
		ctx       context.Context
		operation string
		revision  int64
	}{
		{name: "missing revision", operation: operationID},
		{name: "malformed operation", operation: "apply-1", revision: 42},
		{name: "operation metadata conflict", ctx: interaction.WithOperationID(context.Background(), "0123456789abcdef0123456789abcdef"), operation: operationID, revision: 42},
		{name: "revision metadata conflict", ctx: interaction.WithStateRevision(context.Background(), 43), operation: operationID, revision: 42},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := configOperationContext(test.ctx, test.operation, test.revision); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("configOperationContext error = %v, want InvalidArgument", err)
			}
		})
	}
}

func TestServiceRejectsMissingFieldsAndUnavailableRuntime(t *testing.T) {
	service := NewService(&fakeRuntime{})
	cases := []func() error{
		func() error { _, err := service.ValidateConfig(context.Background(), nil); return err },
		func() error {
			_, err := service.ValidateConfig(context.Background(), &controllerv1.ValidateConfigRequest{})
			return err
		},
		func() error {
			_, err := service.ApplyConfig(context.Background(), &controllerv1.ApplyConfigRequest{Path: "candidate"})
			return err
		},
		func() error {
			_, err := service.ReplaceInbound(context.Background(), &controllerv1.ReplaceInboundRequest{CandidatePath: "new"})
			return err
		},
		func() error {
			_, err := service.ProbeTarget(context.Background(), &controllerv1.ProbeTargetRequest{})
			return err
		},
	}
	for _, call := range cases {
		if status.Code(call()) != codes.InvalidArgument {
			t.Errorf("invalid request error = %v", call())
		}
	}
	if _, err := NewService(nil).Health(context.Background(), &controllerv1.EmptyRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("missing adapter error = %v", err)
	}
	if _, err := NewService(&fakeRuntime{err: errors.New("private failure")}).Health(context.Background(), &controllerv1.EmptyRequest{}); status.Code(err) != codes.Unavailable || status.Convert(err).Message() == "private failure" {
		t.Fatalf("health error = %v", err)
	}
	failed := NewService(&fakeRuntime{err: status.Error(codes.Unavailable, "adapter failure")})
	for _, call := range []func() error{
		func() error {
			_, err := failed.GetStatus(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
		func() error { _, err := failed.GetLogs(context.Background(), &controllerv1.EmptyRequest{}); return err },
		func() error {
			_, err := failed.ValidateConfig(context.Background(), &controllerv1.ValidateConfigRequest{Path: "candidate", OperationId: "44444444444444444444444444444444", StateRevision: 1})
			return err
		},
		func() error {
			_, err := failed.ApplyConfig(context.Background(), &controllerv1.ApplyConfigRequest{Path: "candidate", OperationId: "55555555555555555555555555555555", StateRevision: 1})
			return err
		},
		func() error {
			_, err := failed.ReplaceInbound(context.Background(), &controllerv1.ReplaceInboundRequest{CandidatePath: "new", PreviousPath: "old", Tag: "vless", OperationId: "66666666666666666666666666666666", StateRevision: 1})
			return err
		},
		func() error {
			_, err := failed.ProbeTarget(context.Background(), &controllerv1.ProbeTargetRequest{Target: "host:443"})
			return err
		},
		func() error {
			_, err := failed.ProbeIPv6(context.Background(), &controllerv1.EmptyRequest{})
			return err
		},
	} {
		if status.Code(call()) != codes.Unavailable {
			t.Errorf("runtime failure code = %v", call())
		}
	}
}

func TestXrayDeviceMutationsAreIdempotentForOneOperationID(t *testing.T) {
	handler := &fakeXrayHandler{}
	service := NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil)
	operationID := "abcdef0123456789abcdef0123456789"
	ctx := interaction.WithOperationID(context.Background(), operationID)
	addRequest := &controllerv1.AddDeviceUserRequest{Protocol: "vless", Email: "device-1-vless@xray-easy", Id: "stable-uuid", Flow: "vision"}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := service.AddDeviceUser(ctx, addRequest)
		if err != nil || (attempt == 1 && !result.GetAlreadyApplied()) {
			t.Fatalf("AddDeviceUser retry %d = %v, %v", attempt, result, err)
		}
	}
	if handler.adds != 1 || len(handler.users) != 1 {
		t.Fatalf("duplicate add changed runtime more than once: adds=%d users=%v", handler.adds, handler.users)
	}
	removeCtx := interaction.WithOperationID(context.Background(), "0123456789abcdef0123456789abcdef")
	removeRequest := &controllerv1.RemoveDeviceUserRequest{Protocol: "vless", Email: "device-1-vless@xray-easy"}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := service.RemoveDeviceUser(removeCtx, removeRequest)
		if err != nil || (attempt == 1 && !result.GetAlreadyApplied()) {
			t.Fatalf("RemoveDeviceUser retry %d = %v, %v", attempt, result, err)
		}
	}
	if handler.removes != 1 || len(handler.users) != 0 {
		t.Fatalf("duplicate remove changed runtime more than once: removes=%d users=%v", handler.removes, handler.users)
	}
}
