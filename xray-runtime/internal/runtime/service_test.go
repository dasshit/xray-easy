package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	corelog "github.com/xtls/xray-core/common/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"xray-easy/internal/diagnostics"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

type fakeLoader struct {
	engine      *fakeEngine
	err         error
	validateErr error
	loads       int
	validations int
	input       []byte
	failLoadAt  int
}

func (l *fakeLoader) Load(data []byte) (EngineHandle, error) {
	l.loads++
	l.input = append([]byte(nil), data...)
	if l.err != nil || (l.failLoadAt > 0 && l.loads == l.failLoadAt) {
		if l.err != nil {
			return nil, l.err
		}
		return nil, errors.New("injected load failure")
	}
	return l.engine, nil
}

func (l *fakeLoader) Validate(_ context.Context, data []byte) error {
	l.validations++
	l.input = append([]byte(nil), data...)
	return l.validateErr
}

type fakeEngine struct {
	startErr     error
	closeErr     error
	replaceErr   error
	addErr       error
	removeErr    error
	starts       int
	closes       int
	replacements int
	users        map[string]string
}

func (e *fakeEngine) Start() error    { e.starts++; return e.startErr }
func (e *fakeEngine) Close() error    { e.closes++; return e.closeErr }
func (e *fakeEngine) Version() string { return "Xray test" }
func (e *fakeEngine) ReplaceInbound(_ context.Context, _ string, _ []byte) (bool, error) {
	e.replacements++
	return false, e.replaceErr
}
func (e *fakeEngine) AddUser(_ context.Context, _ xrayruntimev1.Protocol, _ string, email, credential, _ string) (bool, error) {
	if e.addErr != nil {
		return false, e.addErr
	}
	if e.users == nil {
		e.users = make(map[string]string)
	}
	if current, ok := e.users[email]; ok {
		if current == credential {
			return true, nil
		}
		return false, errors.New("conflicting user credential")
	}
	e.users[email] = credential
	return false, nil
}
func (e *fakeEngine) RemoveUser(_ context.Context, _ string, email string) (bool, error) {
	if e.removeErr != nil {
		return false, e.removeErr
	}
	if _, ok := e.users[email]; !ok {
		return true, nil
	}
	delete(e.users, email)
	return false, nil
}
func (e *fakeEngine) ListUsers(_ context.Context, _ string) ([]string, error) {
	users := make([]string, 0, len(e.users))
	for email := range e.users {
		users = append(users, email)
	}
	return users, nil
}

func TestNewServiceStartsActiveSnapshotAndReportsState(t *testing.T) {
	engine := &fakeEngine{}
	loader := &fakeLoader{engine: engine}
	configuration := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"},{"tag":"hysteria2","protocol":"hysteria"},{"tag":"vmess-tls","protocol":"vmess"},{"tag":"ignored","protocol":"ignored"}]}`)
	service, err := NewService(loader, "test-build", configuration, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if engine.starts != 1 || loader.loads != 1 {
		t.Fatalf("startup calls: loads=%d starts=%d", loader.loads, engine.starts)
	}
	status, err := service.GetStatus(context.Background(), new(xrayruntimev1.EmptyRequest))
	if err != nil {
		t.Fatal(err)
	}
	if status.GetState() != xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING || status.GetActiveRevision() != 7 || status.GetXrayCoreVersion() != "Xray test" {
		t.Fatalf("runtime status = %+v", status)
	}
	capabilities, err := service.GetCapabilities(context.Background(), new(xrayruntimev1.EmptyRequest))
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilities.GetProtocols()) != 3 {
		t.Fatalf("configured protocol capabilities = %d, want 3", len(capabilities.GetProtocols()))
	}
	if got := capabilities.GetProtocols()[0].GetProtocol(); got != xrayruntimev1.Protocol_PROTOCOL_VLESS {
		t.Fatalf("first protocol = %v, want VLESS", got)
	}
	health, err := service.Health(context.Background(), &xrayruntimev1.HealthRequest{})
	if err != nil || !health.GetReady() || health.GetXrayCoreVersion() != "Xray test" {
		t.Fatalf("health = %+v, %v", health, err)
	}
}

func TestNewServiceNoConfigAndCloseActive(t *testing.T) {
	loader := &fakeLoader{engine: &fakeEngine{}}
	service, err := NewService(loader, "", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.GetStatus(context.Background(), new(xrayruntimev1.EmptyRequest))
	if err != nil || status.GetState() != xrayruntimev1.RuntimeState_RUNTIME_STATE_NO_CONFIGURATION || status.GetServiceVersion() != "dev" {
		t.Fatalf("no-config status = %+v, %v", status, err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if loader.loads != 0 {
		t.Fatalf("loader called %d times without active config", loader.loads)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("closing empty service: %v", err)
	}
}

func TestNewServiceReturnsLoadAndStartFailures(t *testing.T) {
	loader := &fakeLoader{err: errors.New("bad config")}
	if _, err := NewService(loader, "v", []byte("{}"), 1); err == nil || !strings.Contains(err.Error(), "load active") {
		t.Fatalf("load failure = %v", err)
	}
	engine := &fakeEngine{startErr: errors.New("bind failed")}
	loader = &fakeLoader{engine: engine}
	if _, err := NewService(loader, "v", []byte(`{"inbounds":[]}`), 1); err == nil || !strings.Contains(err.Error(), "start active") {
		t.Fatalf("start failure = %v", err)
	}
	if engine.closes != 1 {
		t.Fatalf("failed engine close count = %d, want 1", engine.closes)
	}
}

func TestValidateConfigurationChecksSnapshotWithoutConstructingCoreAndRedactsFailures(t *testing.T) {
	loader := &fakeLoader{engine: &fakeEngine{}}
	service, err := NewService(loader, "v", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := &xrayruntimev1.ConfigurationRequest{
		ConfigurationJson: []byte(`{"privateKey":"sensitive"}`), OperationId: "operation-1", Revision: 3,
	}
	response, err := service.ValidateConfiguration(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !response.GetValid() || response.GetRevision() != 3 || len(response.GetConfigurationDigest()) != 64 {
		t.Fatalf("configuration response = %+v", response)
	}
	if loader.loads != 0 || loader.validations != 1 {
		t.Fatalf("candidate validation called load=%d validate=%d; it must not construct a core instance", loader.loads, loader.validations)
	}
	if !strings.Contains(string(loader.input), "sensitive") {
		t.Fatal("loader did not receive the submitted snapshot")
	}

	for _, invalid := range []*xrayruntimev1.ConfigurationRequest{
		{},
		{ConfigurationJson: []byte(`{}`), OperationId: "", Revision: 1},
		{ConfigurationJson: []byte(`{}`), OperationId: "operation", Revision: 0},
	} {
		if _, err := service.ValidateConfiguration(context.Background(), invalid); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid request error = %v, want InvalidArgument", err)
		}
	}

	loader.validateErr = errors.New(`invalid privateKey="secret-value"`)
	if _, err := service.ValidateConfiguration(context.Background(), request); status.Code(err) != codes.InvalidArgument || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("invalid snapshot error leaks details: %v", err)
	}
}

func TestTelemetryAndProbeMethodsRemainForNextStage(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "v", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		call func() error
	}{
		{"telemetry", func() error {
			_, err := service.GetTelemetry(context.Background(), &xrayruntimev1.EmptyRequest{})
			return err
		}},
		{"reality probe", func() error {
			_, err := service.ProbeRealityTarget(context.Background(), &xrayruntimev1.ProbeRealityTargetRequest{})
			return err
		}},
		{"ipv6 probe", func() error {
			_, err := service.ProbeIPv6Egress(context.Background(), &xrayruntimev1.EmptyRequest{})
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); status.Code(err) != codes.Unimplemented {
				t.Fatalf("error = %v, want Unimplemented", err)
			}
		})
	}
}

func TestApplyConfigurationReplacesEngineAndReplaysIdempotently(t *testing.T) {
	initial := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	candidate := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}],"outbounds":[{"protocol":"freedom"}]}`)
	engine := &fakeEngine{}
	loader := &fakeLoader{engine: engine}
	service, err := NewService(loader, "v", initial, 1, filepath.Join(t.TempDir(), "revision.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: candidate, OperationId: "apply-2", Revision: 2}
	response, err := service.ApplyConfiguration(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if response.GetAlreadyApplied() || engine.closes != 1 || engine.starts != 2 || loader.loads != 2 {
		t.Fatalf("apply result=%+v engine=%+v loads=%d", response, engine, loader.loads)
	}
	statusResponse, err := service.GetStatus(context.Background(), new(xrayruntimev1.EmptyRequest))
	if err != nil || statusResponse.GetActiveRevision() != 2 || statusResponse.GetState() != xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING {
		t.Fatalf("status after apply=%+v error=%v", statusResponse, err)
	}
	response, err = service.ApplyConfiguration(context.Background(), request)
	if err != nil || !response.GetAlreadyApplied() || engine.closes != 1 || engine.starts != 2 {
		t.Fatalf("idempotent apply=%+v engine=%+v error=%v", response, engine, err)
	}
	rollback := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: initial, OperationId: "apply-2-rollback", Revision: 2}
	if response, err := service.ApplyConfiguration(context.Background(), rollback); err != nil || response.GetAlreadyApplied() || engine.closes != 2 || engine.starts != 3 {
		t.Fatalf("rollback apply=%+v engine=%+v error=%v", response, engine, err)
	}
	if response, err := service.ApplyConfiguration(context.Background(), request); err != nil || response.GetAlreadyApplied() || engine.closes != 3 || engine.starts != 4 {
		t.Fatalf("original replay after rollback=%+v engine=%+v error=%v", response, engine, err)
	}
}

func TestApplyConfigurationReconcilesPendingOperationAfterServiceRestart(t *testing.T) {
	initial := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	candidate := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}],"outbounds":[{"protocol":"freedom"}]}`)
	path := filepath.Join(t.TempDir(), "revision.json")
	firstEngine := &fakeEngine{}
	first, err := NewService(&fakeLoader{engine: firstEngine}, "v", initial, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: candidate, OperationId: "restart-safe-op", Revision: 5}
	if _, err := first.ApplyConfiguration(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	secondEngine := &fakeEngine{}
	second, err := NewService(&fakeLoader{engine: secondEngine}, "v", initial, 0, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	response, err := second.ApplyConfiguration(context.Background(), request)
	if err != nil || response.GetAlreadyApplied() || secondEngine.starts != 2 || secondEngine.closes != 1 {
		t.Fatalf("reconciled replay=%+v engine=%+v error=%v", response, secondEngine, err)
	}
}

func TestApplyConfigurationValidationAndFatalStartFailure(t *testing.T) {
	initial := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	candidate := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}],"new":true}`)
	engine := &fakeEngine{}
	loader := &fakeLoader{engine: engine}
	service, err := NewService(loader, "v", initial, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: candidate, OperationId: "apply-2", Revision: 2}
	loader.validateErr = errors.New("bad candidate")
	if _, err := service.ApplyConfiguration(context.Background(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid candidate status=%v", err)
	}
	loader.validateErr = nil
	engine.startErr = errors.New("listener start failure")
	if _, err := service.ApplyConfiguration(context.Background(), request); status.Code(err) != codes.Unavailable {
		t.Fatalf("failed runtime start status=%v", err)
	}
	select {
	case <-service.Fatal():
	default:
		t.Fatal("fatal restart signal was not sent")
	}
	statusResponse, _ := service.GetStatus(context.Background(), new(xrayruntimev1.EmptyRequest))
	if statusResponse.GetState() != xrayruntimev1.RuntimeState_RUNTIME_STATE_FAILED {
		t.Fatalf("failed runtime state=%v", statusResponse.GetState())
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceInboundAndRevisionFence(t *testing.T) {
	configuration := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	engine := &fakeEngine{}
	service, err := NewService(&fakeLoader{engine: engine}, "v", configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	request := &xrayruntimev1.ReplaceInboundRequest{
		CandidateConfigurationJson: configuration, PreviousConfigurationJson: configuration,
		InboundTag: "vless-reality", OperationId: "replace-1", Revision: 2,
	}
	response, err := service.ReplaceInbound(context.Background(), request)
	if err != nil || response.GetAlreadyApplied() || engine.replacements != 1 {
		t.Fatalf("replace=%+v replacements=%d error=%v", response, engine.replacements, err)
	}
	response, err = service.ReplaceInbound(context.Background(), request)
	if err != nil || !response.GetAlreadyApplied() || engine.replacements != 1 {
		t.Fatalf("replace replay=%+v replacements=%d error=%v", response, engine.replacements, err)
	}
	stale := &xrayruntimev1.ReplaceInboundRequest{
		CandidateConfigurationJson: request.GetCandidateConfigurationJson(), PreviousConfigurationJson: request.GetPreviousConfigurationJson(),
		InboundTag: request.GetInboundTag(), OperationId: "replace-stale", Revision: 1,
	}
	if _, err := service.ReplaceInbound(context.Background(), stale); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale revision status=%v", err)
	}
	conflict := &xrayruntimev1.ReplaceInboundRequest{
		CandidateConfigurationJson: []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}],"changed":true}`),
		PreviousConfigurationJson:  request.GetPreviousConfigurationJson(), InboundTag: request.GetInboundTag(),
		OperationId: request.GetOperationId(), Revision: request.GetRevision(),
	}
	if _, err := service.ReplaceInbound(context.Background(), conflict); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("same operation conflicting payload status=%v", err)
	}
}

func TestReplaceInboundRequestsProcessRestartWhenRollbackFails(t *testing.T) {
	configuration := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	engine := &fakeEngine{replaceErr: ErrInboundRollbackFailed}
	service, err := NewService(&fakeLoader{engine: engine}, "v", configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := &xrayruntimev1.ReplaceInboundRequest{
		CandidateConfigurationJson: configuration, PreviousConfigurationJson: configuration,
		InboundTag: "vless-reality", OperationId: "replace-fatal", Revision: 1,
	}
	if _, err := service.ReplaceInbound(context.Background(), request); status.Code(err) != codes.Unavailable {
		t.Fatalf("failed rollback status=%v", err)
	}
	select {
	case <-service.Fatal():
	default:
		t.Fatal("failed inbound rollback did not signal process restart")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUserManagementUsesProtocolInboundAndRevisionFence(t *testing.T) {
	configuration := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"},{"tag":"vmess-tls","protocol":"vmess"},{"tag":"hysteria2","protocol":"hysteria"}]}`)
	engine := &fakeEngine{users: map[string]string{}}
	service, err := NewService(&fakeLoader{engine: engine}, "v", configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	add := &xrayruntimev1.AddUserRequest{
		Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Email: "device-1@xray-easy", Credential: "12345678-1234-4234-8234-123456789012",
		Flow: "xtls-rprx-vision", OperationId: "add-1", Revision: 1,
	}
	response, err := service.AddUser(context.Background(), add)
	if err != nil || response.GetAlreadyApplied() || engine.users[add.GetEmail()] != add.GetCredential() {
		t.Fatalf("add user=%+v users=%v error=%v", response, engine.users, err)
	}
	response, err = service.AddUser(context.Background(), add)
	if err != nil || !response.GetAlreadyApplied() {
		t.Fatalf("add replay=%+v error=%v", response, err)
	}
	users, err := service.ListUsers(context.Background(), &xrayruntimev1.ListUsersRequest{Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS})
	if err != nil || len(users.GetEmails()) != 1 || users.GetEmails()[0] != add.GetEmail() {
		t.Fatalf("user list=%+v error=%v", users, err)
	}
	remove := &xrayruntimev1.RemoveUserRequest{Protocol: add.GetProtocol(), Email: add.GetEmail(), OperationId: "remove-2", Revision: 2}
	response, err = service.RemoveUser(context.Background(), remove)
	if err != nil || response.GetAlreadyApplied() || len(engine.users) != 0 {
		t.Fatalf("remove user=%+v users=%v error=%v", response, engine.users, err)
	}
	if _, err := service.AddUser(context.Background(), &xrayruntimev1.AddUserRequest{Protocol: xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED, Email: "e", Credential: "c", OperationId: "bad", Revision: 3}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unsupported protocol status=%v", err)
	}
}

func TestConfiguredInboundTagsRejectAmbiguousEntries(t *testing.T) {
	if _, err := ConfiguredInboundTags([]byte(`{"inbounds":[{"protocol":"vless"}]}`)); err == nil {
		t.Fatal("supported inbound with empty tag was accepted")
	}
	if _, err := ConfiguredInboundTags([]byte(`{"inbounds":[{"tag":"one","protocol":"vless"},{"tag":"two","protocol":"vless"}]}`)); err == nil {
		t.Fatal("multiple VLESS inbounds were accepted")
	}
	if _, err := ConfiguredInboundTags([]byte("bad json")); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

func TestValidationAndMutationRespectContextCancellation(t *testing.T) {
	configuration := []byte(`{"inbounds":[{"tag":"vless-reality","protocol":"vless"}]}`)
	loader := &fakeLoader{engine: &fakeEngine{}}
	service, err := NewService(loader, "v", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: configuration, OperationId: "cancel-validation", Revision: 1}
	if _, err := service.ValidateConfiguration(canceled, request); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled validation status=%v", err)
	}
	if _, err := service.ApplyConfiguration(canceled, request); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled apply status=%v", err)
	}
}

func TestConfiguredProtocolsFiltersAndDeduplicates(t *testing.T) {
	got, err := ConfiguredProtocols([]byte(`{"inbounds":[{"protocol":"vless"},{"protocol":"vless"},{"protocol":"hysteria"},{"protocol":"wireguard"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "vless,hysteria2" {
		t.Fatalf("protocols = %v", got)
	}
	if _, err := ConfiguredProtocols([]byte("not json")); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

func TestLoadEngineBuildsEmbeddedCoreWithoutStartingListeners(t *testing.T) {
	if _, err := LoadEngine(nil); err == nil {
		t.Fatal("empty config was accepted")
	}
	if _, err := LoadEngine([]byte("not json")); err == nil {
		t.Fatal("invalid config was accepted")
	}
	engine, err := LoadEngine([]byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`))
	if err != nil {
		t.Fatalf("load valid embedded Xray config: %v", err)
	}
	if engine.Version() == "" {
		t.Fatal("embedded Xray version is empty")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("close unstarted config candidate: %v", err)
	}
}

func TestValidateConfigUsesBuilderOnly(t *testing.T) {
	valid := []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("validate valid Xray snapshot: %v", err)
	}
	if err := ValidateConfig([]byte(`{"inbounds":[`)); err == nil {
		t.Fatal("invalid Xray snapshot was accepted")
	}
}

func TestCapturedXrayLogsKeepWarningsAndHideAccessAndSecrets(t *testing.T) {
	var captured []logRecord
	handler := capturedXrayLog{write: func(level, component, message string) {
		captured = append(captured, logRecord{level: level, component: component, message: message})
	}}
	handler.Handle(&corelog.GeneralMessage{Severity: corelog.Severity_Info, Content: "informational log"})
	handler.Handle(&corelog.AccessMessage{From: "192.0.2.10:1234"})
	handler.Handle(&corelog.GeneralMessage{Severity: corelog.Severity_Warning, Content: `rejected 192.0.2.10:1234 password="visible-secret"`})
	if len(captured) != 1 {
		t.Fatalf("captured messages = %+v, want only the warning", captured)
	}
	if captured[0].level != "warn" || captured[0].component != "xray" {
		t.Fatalf("captured warning metadata = %+v", captured[0])
	}
	redacted := diagnostics.Redact(captured[0].message)
	if strings.Contains(redacted, "192.0.2.10") || strings.Contains(redacted, "visible-secret") {
		t.Fatalf("captured warning leaked private data: %q", redacted)
	}
}
