package runtime

import (
	"context"
	"errors"
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
}

func (l *fakeLoader) Load(data []byte) (EngineHandle, error) {
	l.loads++
	l.input = append([]byte(nil), data...)
	if l.err != nil {
		return nil, l.err
	}
	return l.engine, nil
}

func (l *fakeLoader) Validate(data []byte) error {
	l.validations++
	l.input = append([]byte(nil), data...)
	return l.validateErr
}

type fakeEngine struct {
	startErr error
	closeErr error
	starts   int
	closes   int
}

func (e *fakeEngine) Start() error    { e.starts++; return e.startErr }
func (e *fakeEngine) Close() error    { e.closes++; return e.closeErr }
func (e *fakeEngine) Version() string { return "Xray test" }

func TestNewServiceStartsActiveSnapshotAndReportsState(t *testing.T) {
	engine := &fakeEngine{}
	loader := &fakeLoader{engine: engine}
	configuration := []byte(`{"inbounds":[{"protocol":"vless"},{"protocol":"hysteria"},{"protocol":"vmess"},{"protocol":"ignored"}]}`)
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

func TestApplyAndMutationMethodsAreExplicitlyUnavailable(t *testing.T) {
	service, err := NewService(&fakeLoader{engine: &fakeEngine{}}, "v", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		call func() error
	}{
		{"apply", func() error {
			_, err := service.ApplyConfiguration(context.Background(), &xrayruntimev1.ConfigurationRequest{})
			return err
		}},
		{"replace inbound", func() error {
			_, err := service.ReplaceInbound(context.Background(), &xrayruntimev1.ReplaceInboundRequest{})
			return err
		}},
		{"add user", func() error {
			_, err := service.AddUser(context.Background(), &xrayruntimev1.AddUserRequest{})
			return err
		}},
		{"remove user", func() error {
			_, err := service.RemoveUser(context.Background(), &xrayruntimev1.RemoveUserRequest{})
			return err
		}},
		{"list users", func() error {
			_, err := service.ListUsers(context.Background(), &xrayruntimev1.ListUsersRequest{})
			return err
		}},
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
