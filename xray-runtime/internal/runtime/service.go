package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	appLog "github.com/xtls/xray-core/app/log"
	corelog "github.com/xtls/xray-core/common/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"xray-easy/internal/diagnostics"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

const maxConfigurationBytes = 16 << 20

// Loader keeps active-instance construction and side-effect-free validation
// replaceable in unit tests.
type Loader interface {
	Load([]byte) (EngineHandle, error)
	Validate([]byte) error
}

// EngineHandle represents the one configured Xray instance.
type EngineHandle interface {
	Start() error
	Close() error
	Version() string
}

type coreLoader struct {
	writeLog func(level, component, message string)
}

func (l coreLoader) Load(data []byte) (EngineHandle, error) {
	if l.writeLog != nil {
		_ = appLog.RegisterHandlerCreator(appLog.LogType_Console, func(appLog.LogType, appLog.HandlerCreatorOptions) (corelog.Handler, error) {
			return capturedXrayLog{write: l.writeLog}, nil
		})
	}
	return LoadEngine(data)
}

func (coreLoader) Validate(data []byte) error { return ValidateConfig(data) }

// Service owns the Xray instance and implements its private product-level API.
type Service struct {
	xrayruntimev1.UnimplementedRuntimeServer

	loader         Loader
	serviceVersion string
	startedAt      time.Time
	mu             sync.RWMutex
	engine         EngineHandle
	state          xrayruntimev1.RuntimeState
	activeRevision int64
	lastError      string
	protocols      []string
	logs           []logRecord
	logLimit       int
}

type logRecord struct {
	at        time.Time
	level     string
	component string
	message   string
}

// NewService constructs the runtime service, optionally starting the durable
// active snapshot supplied by the process entrypoint.
func NewService(loader Loader, serviceVersion string, activeConfiguration []byte, activeRevision int64) (*Service, error) {
	if strings.TrimSpace(serviceVersion) == "" {
		serviceVersion = "dev"
	}
	service := &Service{
		serviceVersion: serviceVersion, startedAt: time.Now().UTC(),
		state: xrayruntimev1.RuntimeState_RUNTIME_STATE_NO_CONFIGURATION, logLimit: 200,
	}
	if loader == nil {
		loader = coreLoader{writeLog: service.addLog}
	}
	service.loader = loader
	service.addLog("info", "runtime", "embedded Xray runtime service starting")
	if len(activeConfiguration) == 0 {
		return service, nil
	}
	engine, err := loader.Load(activeConfiguration)
	if err != nil {
		return nil, fmt.Errorf("load active Xray configuration: %w", err)
	}
	if err := engine.Start(); err != nil {
		_ = engine.Close()
		return nil, fmt.Errorf("start active Xray configuration: %w", err)
	}
	protocols, err := ConfiguredProtocols(activeConfiguration)
	if err != nil {
		_ = engine.Close()
		return nil, err
	}
	service.engine = engine
	service.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING
	service.activeRevision = activeRevision
	service.protocols = protocols
	service.addLog("info", "runtime", "embedded Xray instance started")
	return service, nil
}

// Close shuts down the embedded Xray instance.
func (s *Service) Close() error {
	s.mu.Lock()
	engine := s.engine
	s.engine = nil
	s.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_STOPPING
	s.mu.Unlock()
	if engine == nil {
		return nil
	}
	return engine.Close()
}

func (s *Service) addLog(level, component, message string) {
	s.mu.Lock()
	if s.logLimit < 1 {
		s.logLimit = 200
	}
	entry := logRecord{at: time.Now().UTC(), level: level, component: component, message: diagnostics.Redact(message)}
	if len(s.logs) >= s.logLimit {
		copy(s.logs, s.logs[1:])
		s.logs = s.logs[:s.logLimit-1]
	}
	s.logs = append(s.logs, entry)
	s.mu.Unlock()
	slog.Log(context.Background(), runtimeLogLevel(level), "runtime event", "service", "xray-runtime", "component", component, "message", entry.message)
}

func runtimeLogLevel(level string) slog.Level {
	switch level {
	case "error":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// Health reports readiness and the embedded core version.
func (s *Service) Health(_ context.Context, _ *xrayruntimev1.HealthRequest) (*xrayruntimev1.HealthResponse, error) {
	s.mu.RLock()
	ready := s.state == xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING || s.state == xrayruntimev1.RuntimeState_RUNTIME_STATE_NO_CONFIGURATION
	engine := s.engine
	s.mu.RUnlock()
	version := ""
	if engine != nil {
		version = engine.Version()
	}
	return &xrayruntimev1.HealthResponse{Ready: ready, ServiceVersion: s.serviceVersion, XrayCoreVersion: version}, nil
}

// GetStatus returns non-secret process state.
func (s *Service) GetStatus(_ context.Context, _ *xrayruntimev1.EmptyRequest) (*xrayruntimev1.RuntimeStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	version := ""
	if s.engine != nil {
		version = s.engine.Version()
	}
	return &xrayruntimev1.RuntimeStatus{
		State: s.state, ServiceVersion: s.serviceVersion, XrayCoreVersion: version,
		ActiveRevision: s.activeRevision, LastError: diagnostics.Redact(s.lastError),
		StartedAt: timestamppb.New(s.startedAt),
	}, nil
}

// GetCapabilities reports the currently configured protocols and the features
// implemented by this runtime API.
func (s *Service) GetCapabilities(_ context.Context, _ *xrayruntimev1.EmptyRequest) (*xrayruntimev1.CapabilitiesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	response := &xrayruntimev1.CapabilitiesResponse{}
	for _, name := range s.protocols {
		protocol, ok := protocolFromName(name)
		if !ok {
			continue
		}
		response.Protocols = append(response.Protocols, &xrayruntimev1.ProtocolCapability{
			Protocol: protocol, Configured: true,
			UserManagement: false, TrafficCounters: false, OnlineStatus: false, SourceIp: false,
		})
	}
	return response, nil
}

// GetRecentLogs returns a bounded list of redacted runtime lifecycle messages.
func (s *Service) GetRecentLogs(_ context.Context, _ *xrayruntimev1.EmptyRequest) (*xrayruntimev1.LogsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	response := &xrayruntimev1.LogsResponse{Entries: make([]*xrayruntimev1.LogEntry, 0, len(s.logs))}
	for _, entry := range s.logs {
		response.Entries = append(response.Entries, &xrayruntimev1.LogEntry{
			Timestamp: timestamppb.New(entry.at), Level: entry.level, Component: entry.component,
			Message: diagnostics.Redact(entry.message),
		})
	}
	return response, nil
}

// ValidateConfiguration builds a candidate config without constructing a core
// instance, binding listeners, or replacing the active instance.
func (s *Service) ValidateConfiguration(_ context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.ConfigurationResponse, error) {
	if request == nil || len(request.GetConfigurationJson()) == 0 || len(request.GetConfigurationJson()) > maxConfigurationBytes {
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is empty or exceeds the size limit")
	}
	if strings.TrimSpace(request.GetOperationId()) == "" || request.GetRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "operation ID and positive revision are required")
	}
	if err := s.loader.Validate(request.GetConfigurationJson()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is invalid")
	}
	digest := sha256.Sum256(request.GetConfigurationJson())
	return &xrayruntimev1.ConfigurationResponse{
		Valid: true, OperationId: request.GetOperationId(), Revision: request.GetRevision(),
		ConfigurationDigest: hex.EncodeToString(digest[:]),
	}, nil
}

// ApplyConfiguration is implemented with durable revision fencing in the
// next migration stage.
func (s *Service) ApplyConfiguration(context.Context, *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.OperationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "configuration apply is not available yet")
}

func (s *Service) ReplaceInbound(context.Context, *xrayruntimev1.ReplaceInboundRequest) (*xrayruntimev1.OperationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "inbound replacement is not available yet")
}

func (s *Service) AddUser(context.Context, *xrayruntimev1.AddUserRequest) (*xrayruntimev1.OperationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "live user management is not available yet")
}

func (s *Service) RemoveUser(context.Context, *xrayruntimev1.RemoveUserRequest) (*xrayruntimev1.OperationResponse, error) {
	return nil, status.Error(codes.Unimplemented, "live user management is not available yet")
}

func (s *Service) ListUsers(context.Context, *xrayruntimev1.ListUsersRequest) (*xrayruntimev1.ListUsersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "live user management is not available yet")
}

func (s *Service) GetTelemetry(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.TelemetryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "telemetry is not available yet")
}

func (s *Service) ProbeRealityTarget(context.Context, *xrayruntimev1.ProbeRealityTargetRequest) (*xrayruntimev1.ProbeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "REALITY probing is not available yet")
}

func (s *Service) ProbeIPv6Egress(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.ProbeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "IPv6 probing is not available yet")
}

func protocolFromName(name string) (xrayruntimev1.Protocol, bool) {
	switch name {
	case "vless":
		return xrayruntimev1.Protocol_PROTOCOL_VLESS, true
	case "vmess":
		return xrayruntimev1.Protocol_PROTOCOL_VMESS, true
	case "hysteria2":
		return xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, true
	default:
		return xrayruntimev1.Protocol_PROTOCOL_UNSPECIFIED, false
	}
}
