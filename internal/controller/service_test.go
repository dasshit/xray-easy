package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"xray-easy/internal/interaction"
	"xray-easy/internal/supervisor"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type fakeRuntime struct {
	status        supervisor.Status
	logs          []string
	err           error
	called        string
	args          []string
	requestID     string
	operationID   string
	attempt       int
	stateRevision int64
}

func (f *fakeRuntime) Health(ctx context.Context) error {
	f.called = "Health"
	f.requestID = interaction.IncomingRequestID(ctx)
	f.operationID = interaction.OperationID(ctx)
	f.attempt = interaction.Attempt(ctx)
	f.stateRevision = interaction.StateRevision(ctx)
	return f.err
}
func (f *fakeRuntime) Status(context.Context) (supervisor.Status, error) {
	f.called = "Status"
	return f.status, f.err
}
func (f *fakeRuntime) Logs(context.Context) ([]string, error) {
	f.called = "Logs"
	return f.logs, f.err
}
func (f *fakeRuntime) Validate(_ context.Context, path, operation string) error {
	f.called = "Validate"
	f.args = []string{path, operation}
	return f.err
}
func (f *fakeRuntime) Apply(_ context.Context, path, operation string) error {
	f.called = "Apply"
	f.args = []string{path, operation}
	return f.err
}
func (f *fakeRuntime) ReplaceInbound(_ context.Context, candidate, previous, tag, operation string) error {
	f.called = "ReplaceInbound"
	f.args = []string{candidate, previous, tag, operation}
	return f.err
}
func (f *fakeRuntime) ProbeTarget(_ context.Context, target, sni string) error {
	f.called = "ProbeTarget"
	f.args = []string{target, sni}
	return f.err
}
func (f *fakeRuntime) ProbeIPv6(context.Context) error { f.called = "ProbeIPv6"; return f.err }

func TestServiceHealthStatusAndLogs(t *testing.T) {
	runtime := &fakeRuntime{
		status: supervisor.Status{Protocol: "v1", XrayVersion: "26.7.28", State: "running", PID: 33, ConfigPath: "/etc/xray/active.json", RestartCount: 2, StartedAt: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)},
		logs:   []string{"warn: sanitized"},
	}
	service := NewService(runtime)
	result, err := service.Health(context.Background(), emptyRequest())
	if err != nil || result.GetFields()["ok"].GetBoolValue() != true {
		t.Fatalf("Health() = %v, %v", result, err)
	}
	result, err = service.GetStatus(context.Background(), emptyRequest())
	if err != nil || result.GetFields()["xray_version"].GetStringValue() != "26.7.28" || result.GetFields()["restart_count"].GetNumberValue() != 2 {
		t.Fatalf("GetStatus() = %v, %v", result, err)
	}
	result, err = service.GetLogs(context.Background(), emptyRequest())
	if err != nil || result.GetFields()["lines"].GetListValue().GetValues()[0].GetStringValue() != "warn: sanitized" {
		t.Fatalf("GetLogs() = %v, %v", result, err)
	}
}

func TestServiceDelegatesRuntimeOperations(t *testing.T) {
	tests := []struct {
		name       string
		request    *structpb.Struct
		call       func(*Service, *structpb.Struct) error
		wantMethod string
		wantArgs   []string
	}{
		{"validate", request(map[string]any{"path": "/tmp/candidate", "operation_id": "op-1"}), func(s *Service, r *structpb.Struct) error {
			_, err := s.ValidateConfig(context.Background(), r)
			return err
		}, "Validate", []string{"/tmp/candidate", "op-1"}},
		{"apply", request(map[string]any{"path": "/tmp/candidate", "operation_id": "op-2"}), func(s *Service, r *structpb.Struct) error {
			_, err := s.ApplyConfig(context.Background(), r)
			return err
		}, "Apply", []string{"/tmp/candidate", "op-2"}},
		{"replace", request(map[string]any{"candidate_path": "new", "previous_path": "old", "tag": "vless", "operation_id": "op-3"}), func(s *Service, r *structpb.Struct) error {
			_, err := s.ReplaceInbound(context.Background(), r)
			return err
		}, "ReplaceInbound", []string{"new", "old", "vless", "op-3"}},
		{"target", request(map[string]any{"target": "example.com:443", "sni": "example.com"}), func(s *Service, r *structpb.Struct) error {
			_, err := s.ProbeTarget(context.Background(), r)
			return err
		}, "ProbeTarget", []string{"example.com:443", "example.com"}},
		{"ipv6", emptyRequest(), func(s *Service, r *structpb.Struct) error { _, err := s.ProbeIPv6(context.Background(), r); return err }, "ProbeIPv6", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{}
			if err := test.call(NewService(runtime), test.request); err != nil {
				t.Fatal(err)
			}
			if runtime.called != test.wantMethod {
				t.Fatalf("called %q, want %q", runtime.called, test.wantMethod)
			}
			if len(runtime.args) != len(test.wantArgs) {
				t.Fatalf("args = %v, want %v", runtime.args, test.wantArgs)
			}
			for i := range test.wantArgs {
				if runtime.args[i] != test.wantArgs[i] {
					t.Fatalf("args = %v, want %v", runtime.args, test.wantArgs)
				}
			}
		})
	}
}

func TestServiceRejectsMalformedRequestsAndUnavailableAdapter(t *testing.T) {
	service := NewService(&fakeRuntime{})
	_, err := service.GetStatus(context.Background(), request(map[string]any{"unexpected": true}))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected field error = %v", err)
	}
	_, err = service.ValidateConfig(context.Background(), request(map[string]any{"operation_id": "op"}))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing path error = %v", err)
	}
	_, err = service.ApplyConfig(context.Background(), request(map[string]any{"path": "x"}))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing operation error = %v", err)
	}
	_, err = service.ProbeTarget(context.Background(), request(map[string]any{"target": 12}))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong target type error = %v", err)
	}
	_, err = NewService(nil).Health(context.Background(), emptyRequest())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("missing adapter error = %v", err)
	}
	_, err = NewService(&fakeRuntime{err: errors.New("private failure")}).Health(context.Background(), emptyRequest())
	if status.Code(err) != codes.Unavailable || status.Convert(err).Message() == "private failure" {
		t.Fatalf("health error = %v", err)
	}
	failed := NewService(&fakeRuntime{err: status.Error(codes.Unavailable, "adapter failure")})
	if _, err = failed.GetStatus(context.Background(), emptyRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("status adapter error = %v", err)
	}
	if _, err = failed.GetLogs(context.Background(), emptyRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("logs adapter error = %v", err)
	}
	if _, err = failed.ValidateConfig(context.Background(), request(map[string]any{"path": "candidate"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("validate adapter error = %v", err)
	}
	if _, err = failed.ApplyConfig(context.Background(), request(map[string]any{"path": "candidate", "operation_id": "apply"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("apply adapter error = %v", err)
	}
	if _, err = failed.ReplaceInbound(context.Background(), request(map[string]any{"candidate_path": "new", "previous_path": "old", "tag": "vless", "operation_id": "replace"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("replace adapter error = %v", err)
	}
	if _, err = failed.ProbeTarget(context.Background(), request(map[string]any{"target": "host:443"})); status.Code(err) != codes.Unavailable {
		t.Fatalf("target adapter error = %v", err)
	}
	if _, err = failed.ProbeIPv6(context.Background(), emptyRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("IPv6 adapter error = %v", err)
	}
	if _, err = service.ValidateConfig(context.Background(), request(map[string]any{"path": true})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong path type = %v", err)
	}
	if _, err = service.ApplyConfig(context.Background(), request(map[string]any{"path": "candidate", "operation_id": false})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong operation type = %v", err)
	}
	if _, err = service.ReplaceInbound(context.Background(), request(map[string]any{"candidate_path": "new", "previous_path": "old", "tag": "vless"})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing replacement operation = %v", err)
	}
	if _, err = service.ProbeTarget(context.Background(), request(map[string]any{"target": "host:443", "sni": false})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong SNI type = %v", err)
	}
	if err = fields(nil); err != nil {
		t.Fatalf("nil empty request rejected: %v", err)
	}
	if err = fields(request(map[string]any{"unexpected": true})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected empty-request field = %v", err)
	}
	if _, err = requireFields(nil, "path"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil operation request = %v", err)
	}
	if _, err = requireFields(request(map[string]any{"other": "x"}), "path"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected operation field = %v", err)
	}
	if _, err = response(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("response accepted unsupported value")
	}
}

func TestXrayDeviceMutationsAreIdempotentForOneOperationID(t *testing.T) {
	handler := &fakeXrayHandler{}
	service := NewServiceWithAdapters(&fakeRuntime{}, handler, nil, nil)
	operationID := "abcdef0123456789abcdef0123456789"
	ctx := interaction.WithOperationID(context.Background(), operationID)
	addRequest := request(map[string]any{"protocol": "vless", "email": "device-1-vless@xray-easy", "id": "stable-uuid", "flow": "vision"})
	for attempt := 0; attempt < 2; attempt++ {
		result, err := service.AddDeviceUser(ctx, addRequest)
		if err != nil {
			t.Fatalf("AddDeviceUser retry %d = %v", attempt, err)
		}
		if attempt == 1 && !result.GetFields()["already_applied"].GetBoolValue() {
			t.Fatalf("duplicate add response = %v", result.AsMap())
		}
	}
	if handler.adds != 1 || len(handler.users) != 1 {
		t.Fatalf("duplicate add changed runtime more than once: adds=%d users=%v", handler.adds, handler.users)
	}

	removeCtx := interaction.WithOperationID(context.Background(), "0123456789abcdef0123456789abcdef")
	removeRequest := request(map[string]any{"protocol": "vless", "email": "device-1-vless@xray-easy"})
	for attempt := 0; attempt < 2; attempt++ {
		result, err := service.RemoveDeviceUser(removeCtx, removeRequest)
		if err != nil {
			t.Fatalf("RemoveDeviceUser retry %d = %v", attempt, err)
		}
		if attempt == 1 && !result.GetFields()["already_applied"].GetBoolValue() {
			t.Fatalf("duplicate remove response = %v", result.AsMap())
		}
	}
	if handler.removes != 1 || len(handler.users) != 0 {
		t.Fatalf("duplicate remove changed runtime more than once: removes=%d users=%v", handler.removes, handler.users)
	}
}

func TestServiceReturnsUnavailableWhenAdapterIsMissingForEveryOperation(t *testing.T) {
	service := NewService(nil)
	requests := []struct {
		name string
		call func() error
	}{
		{"health", func() error { _, err := service.Health(context.Background(), emptyRequest()); return err }},
		{"status", func() error { _, err := service.GetStatus(context.Background(), emptyRequest()); return err }},
		{"logs", func() error { _, err := service.GetLogs(context.Background(), emptyRequest()); return err }},
		{"validate", func() error {
			_, err := service.ValidateConfig(context.Background(), request(map[string]any{"path": "candidate"}))
			return err
		}},
		{"apply", func() error {
			_, err := service.ApplyConfig(context.Background(), request(map[string]any{"path": "candidate", "operation_id": "apply"}))
			return err
		}},
		{"replace", func() error {
			_, err := service.ReplaceInbound(context.Background(), request(map[string]any{"candidate_path": "new", "previous_path": "old", "tag": "vless", "operation_id": "replace"}))
			return err
		}},
		{"target", func() error {
			_, err := service.ProbeTarget(context.Background(), request(map[string]any{"target": "host:443"}))
			return err
		}},
		{"ipv6", func() error { _, err := service.ProbeIPv6(context.Background(), emptyRequest()); return err }},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			if code := status.Code(test.call()); code != codes.Unavailable {
				t.Fatalf("error code = %s", code)
			}
		})
	}
	if _, err := service.Health(context.Background(), request(map[string]any{"unexpected": true})); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected health field = %v", err)
	}
}

func emptyRequest() *structpb.Struct { return &structpb.Struct{} }

func request(fields map[string]any) *structpb.Struct {
	value, err := structpb.NewStruct(fields)
	if err != nil {
		panic(err)
	}
	return value
}
