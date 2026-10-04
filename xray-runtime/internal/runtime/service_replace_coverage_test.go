package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

const replaceCoverageConfig = `{"inbounds":[{"tag":"vless","protocol":"vless"}],"outbounds":[]}`

// replaceCoverageRequest creates a replacement request for the runtime service tests.
func replaceCoverageRequest(configuration []byte) *xrayruntimev1.ReplaceInboundRequest {
	return &xrayruntimev1.ReplaceInboundRequest{
		InboundTag: "vless", CandidateConfigurationJson: configuration,
		OperationId: "replace-coverage", Revision: 1,
	}
}

// replaceCoverageConfigRequest creates a valid replacement request with a caller-selected identity.
func replaceCoverageConfigRequest(operationID string, revision int64) *xrayruntimev1.ReplaceInboundRequest {
	request := replaceCoverageRequest([]byte(replaceCoverageConfig))
	request.OperationId = operationID
	request.Revision = revision
	return request
}

// basicEngine exposes only the required engine contract, omitting optional lifecycle capabilities.
type basicEngine struct{ EngineHandle }

// basicEngineLoader returns an engine that implements only the mandatory contract.
type basicEngineLoader struct{ engine EngineHandle }

// Load returns the engine configured for a service test.
func (l basicEngineLoader) Load([]byte) (EngineHandle, error) { return l.engine, nil }

// Validate accepts the candidate snapshot in these service-level tests.
func (basicEngineLoader) Validate(context.Context, []byte) error { return nil }

func TestReplaceInboundRejectsMalformedRequestsAndCanceledContext(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	for _, request := range []*xrayruntimev1.ReplaceInboundRequest{
		nil,
		{},
		replaceCoverageRequest(make([]byte, maxConfigurationBytes+1)),
	} {
		if _, err := service.ReplaceInbound(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Errorf("ReplaceInbound(%v) error = %v, want InvalidArgument", request, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ReplaceInbound(canceled, replaceCoverageRequest([]byte(replaceCoverageConfig))); status.Code(err) != codes.Canceled {
		t.Fatalf("ReplaceInbound() with canceled context error = %v", err)
	}
}

func TestReplaceInboundMapsValidationErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		validation error
		want       codes.Code
	}{
		{name: "deadline", validation: context.DeadlineExceeded, want: codes.DeadlineExceeded},
		{name: "canceled", validation: context.Canceled, want: codes.Canceled},
		{name: "invalid candidate", validation: errors.New("bad configuration"), want: codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			loader := &fakeLoader{engine: &fakeEngine{}, validateErr: test.validation}
			service, err := NewService(loader, "test", nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			if _, err := service.ReplaceInbound(context.Background(), replaceCoverageRequest([]byte(replaceCoverageConfig))); status.Code(err) != test.want {
				t.Fatalf("ReplaceInbound() error = %v, want %s", err, test.want)
			}
			if loader.validations != 1 {
				t.Fatalf("validation calls = %d, want 1", loader.validations)
			}
		})
	}
}

// cancelAfterValidationLoader cancels a context after candidate validation succeeds.
type cancelAfterValidationLoader struct {
	*fakeLoader
	cancel context.CancelFunc
}

// Validate cancels the caller's context immediately after the base fake validates the snapshot.
func (l *cancelAfterValidationLoader) Validate(ctx context.Context, data []byte) error {
	err := l.fakeLoader.Validate(ctx, data)
	l.cancel()
	return err
}

func TestAddUserRejectsInvalidCanceledUnconfiguredAndConflictingRequests(t *testing.T) {
	engine := &fakeEngine{}
	service, err := NewService(&fakeLoader{engine: engine}, "test", []byte(replaceCoverageConfig), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if _, err := service.AddUser(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AddUser(nil) error = %v", err)
	}
	valid := &xrayruntimev1.AddUserRequest{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "device", Credential: "credential", OperationId: "add-coverage", Revision: 1}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.AddUser(canceled, valid); status.Code(err) != codes.Canceled {
		t.Fatalf("AddUser() with canceled context error = %v", err)
	}
	unconfigured := proto.Clone(valid).(*xrayruntimev1.AddUserRequest)
	unconfigured.Protocol = xrayruntimev1.Protocol_PROTOCOL_VMESS
	if _, err := service.AddUser(context.Background(), unconfigured); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AddUser() for an unconfigured protocol error = %v", err)
	}
	if _, err := service.AddUser(context.Background(), valid); err != nil {
		t.Fatalf("AddUser() initial call: %v", err)
	}
	conflict := proto.Clone(valid).(*xrayruntimev1.AddUserRequest)
	conflict.Credential = "different-credential"
	if _, err := service.AddUser(context.Background(), conflict); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("AddUser() reused operation with changed payload error = %v", err)
	}
}

func TestRemoveUserRejectsInvalidCanceledUnconfiguredAndConflictingRequests(t *testing.T) {
	engine := &fakeEngine{users: map[string]string{"device": "credential"}}
	service, err := NewService(&fakeLoader{engine: engine}, "test", []byte(replaceCoverageConfig), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if _, err := service.RemoveUser(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("RemoveUser(nil) error = %v", err)
	}
	valid := &xrayruntimev1.RemoveUserRequest{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "device", OperationId: "remove-coverage", Revision: 1}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.RemoveUser(canceled, valid); status.Code(err) != codes.Canceled {
		t.Fatalf("RemoveUser() with canceled context error = %v", err)
	}
	unconfigured := proto.Clone(valid).(*xrayruntimev1.RemoveUserRequest)
	unconfigured.Protocol = xrayruntimev1.Protocol_PROTOCOL_VMESS
	if _, err := service.RemoveUser(context.Background(), unconfigured); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RemoveUser() for an unconfigured protocol error = %v", err)
	}
	if _, err := service.RemoveUser(context.Background(), valid); err != nil {
		t.Fatalf("RemoveUser() initial call: %v", err)
	}
	conflict := proto.Clone(valid).(*xrayruntimev1.RemoveUserRequest)
	conflict.OperationId = "remove-other-operation"
	if _, err := service.RemoveUser(context.Background(), conflict); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RemoveUser() reused revision for another operation error = %v", err)
	}
}

func TestRemoveUserUsesEngineFallbackWithoutOptionalSessionInterfaces(t *testing.T) {
	engine := &fakeEngine{users: map[string]string{"device": "credential"}}
	service, err := NewService(basicEngineLoader{engine: basicEngine{EngineHandle: engine}}, "test", []byte(replaceCoverageConfig), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	request := &xrayruntimev1.RemoveUserRequest{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "device", OperationId: "remove-fallback"}
	if _, err := service.RemoveUser(context.Background(), request); err != nil {
		t.Fatalf("RemoveUser() without optional session interfaces: %v", err)
	}
	if _, exists := engine.users["device"]; exists {
		t.Fatal("fallback did not remove the user")
	}
}

func TestReplaceInboundRevisionCommitFailureRequestsRestart(t *testing.T) {
	statePath := t.TempDir() + "/revision.json"
	engine := &fakeEngine{}
	service, err := NewService(&fakeLoader{engine: engine}, "test", []byte(replaceCoverageConfig), 0, statePath)
	if err != nil {
		t.Fatal(err)
	}
	service.fence.fileSystem = &failNthRevisionTempCreate{revisionFileSystem: osRevisionFileSystem{}, failAt: 2}
	if _, err := service.ReplaceInbound(context.Background(), replaceCoverageConfigRequest("replace-commit-failure", 1)); status.Code(err) != codes.Unavailable {
		t.Fatalf("ReplaceInbound() commit error = %v, want Unavailable", err)
	}
	select {
	case <-service.Fatal():
	case <-time.After(time.Second):
		t.Fatal("revision commit failure did not request a runtime restart")
	}
	_ = service.Close()
}

// failNthRevisionTempCreate fails one selected durable journal write.
type failNthRevisionTempCreate struct {
	revisionFileSystem
	failAt int
	calls  int
}

// CreateTemp delegates journal writes except for the selected injected failure.
func (fs *failNthRevisionTempCreate) CreateTemp(directory, pattern string) (revisionTempFile, error) {
	fs.calls++
	if fs.calls == fs.failAt {
		return nil, errors.New("injected revision commit persistence failure")
	}
	return fs.revisionFileSystem.CreateTemp(directory, pattern)
}

func TestReplaceInboundRechecksContextAfterValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	loader := &cancelAfterValidationLoader{fakeLoader: &fakeLoader{engine: &fakeEngine{}}, cancel: cancel}
	service, err := NewService(loader, "test", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if _, err := service.ReplaceInbound(ctx, replaceCoverageRequest([]byte(replaceCoverageConfig))); status.Code(err) != codes.Canceled {
		t.Fatalf("ReplaceInbound() after validation canceled context error = %v", err)
	}
}

func TestReplaceInboundRejectsInvalidTagsAndMissingActiveEngine(t *testing.T) {
	for _, test := range []struct {
		name        string
		initial     []byte
		candidate   []byte
		wantMessage string
	}{
		{
			name:        "supported inbound has no tag",
			candidate:   []byte(`{"inbounds":[{"protocol":"vless"}]}`),
			wantMessage: "candidate Xray configuration is invalid",
		},
		{
			name:        "active engine missing",
			candidate:   []byte(replaceCoverageConfig),
			wantMessage: "Xray runtime has no active configuration",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := &fakeEngine{}
			loader := &fakeLoader{engine: engine}
			service, err := NewService(loader, "test", test.initial, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			_, replaceErr := service.ReplaceInbound(context.Background(), replaceCoverageRequest(test.candidate))
			if test.wantMessage == "Xray runtime has no active configuration" && status.Code(replaceErr) != codes.FailedPrecondition {
				t.Fatalf("ReplaceInbound() error = %v, want FailedPrecondition", replaceErr)
			} else if test.wantMessage != "Xray runtime has no active configuration" && status.Code(replaceErr) != codes.InvalidArgument {
				t.Fatalf("ReplaceInbound() error = %v, want InvalidArgument", replaceErr)
			}
			if test.wantMessage != "" && (replaceErr == nil || !strings.Contains(replaceErr.Error(), test.wantMessage)) {
				t.Fatalf("ReplaceInbound() error = %v, want message containing %q", replaceErr, test.wantMessage)
			}
		})
	}
}

func TestReplaceInboundMapsEngineFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		want    codes.Code
	}{
		{name: "replacement failure", failure: errors.New("injected replace failure"), want: codes.FailedPrecondition},
		{name: "rollback failure", failure: ErrInboundRollbackFailed, want: codes.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := &fakeEngine{replaceErr: test.failure}
			service, err := NewService(&fakeLoader{engine: engine}, "test", []byte(replaceCoverageConfig), 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.ReplaceInbound(context.Background(), replaceCoverageRequest([]byte(replaceCoverageConfig))); status.Code(err) != test.want {
				t.Fatalf("ReplaceInbound() error = %v, want %s", err, test.want)
			}
			if test.want == codes.Unavailable {
				select {
				case <-service.Fatal():
				case <-time.After(time.Second):
					t.Fatal("rollback failure did not request a runtime restart")
				}
			}
			_ = service.Close()
		})
	}
}
