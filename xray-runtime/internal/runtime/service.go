package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
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

const (
	maxConfigurationBytes = 16 << 20
	maxOperationIDBytes   = 128
	maxInboundTagBytes    = 128
	maxUserEmailBytes     = 320
	maxCredentialBytes    = 512
	maxUserFlowBytes      = 64
)

// Loader keeps active-instance construction and side-effect-free validation
// replaceable in unit tests.
type Loader interface {
	Load([]byte) (EngineHandle, error)
	Validate(context.Context, []byte) error
}

// EngineHandle represents the one configured Xray instance.
type EngineHandle interface {
	Start() error
	Close() error
	Version() string
	StatsAvailable() bool
	GetTelemetry(context.Context, map[xrayruntimev1.Protocol]string) ([]RuntimeUserTelemetry, error)
	ReplaceInbound(context.Context, string, []byte) (bool, error)
	AddUser(context.Context, xrayruntimev1.Protocol, string, string, string, string) (bool, error)
	RemoveUser(context.Context, string, string) (bool, error)
	ListUsers(context.Context, string) ([]string, error)
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

func (coreLoader) Validate(ctx context.Context, data []byte) error {
	return ValidateConfigIsolatedContext(ctx, data)
}

// Service owns the Xray instance and implements its private product-level API.
type Service struct {
	xrayruntimev1.UnimplementedRuntimeServer

	loader         Loader
	serviceVersion string
	startedAt      time.Time
	opMu           sync.Mutex
	mu             sync.RWMutex
	engine         EngineHandle
	activeConfig   []byte
	state          xrayruntimev1.RuntimeState
	activeRevision int64
	lastError      string
	protocols      []string
	inboundTags    map[xrayruntimev1.Protocol]string
	telemetry      telemetryCapabilities
	lastSeen       map[string]time.Time
	probeTarget    func(context.Context, string, string) error
	probeIPv6      func(context.Context) error
	fence          *RevisionFence
	fatal          chan error
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
func NewService(loader Loader, serviceVersion string, activeConfiguration []byte, activeRevision int64, revisionStatePath ...string) (*Service, error) {
	if strings.TrimSpace(serviceVersion) == "" {
		serviceVersion = "dev"
	}
	path := ""
	if len(revisionStatePath) > 0 {
		path = revisionStatePath[0]
	}
	fence, err := NewRevisionFence(path)
	if err != nil {
		return nil, err
	}
	if fence.Latest() > activeRevision {
		activeRevision = fence.Latest()
	}
	service := &Service{
		serviceVersion: serviceVersion, startedAt: time.Now().UTC(),
		state: xrayruntimev1.RuntimeState_RUNTIME_STATE_NO_CONFIGURATION, logLimit: 200,
		activeConfig: append([]byte(nil), activeConfiguration...), inboundTags: make(map[xrayruntimev1.Protocol]string),
		fence: fence, fatal: make(chan error, 1), activeRevision: activeRevision, lastSeen: make(map[string]time.Time),
		probeTarget: probeRealityTarget, probeIPv6: probeIPv6Egress,
	}
	if loader == nil {
		loader = coreLoader{writeLog: service.addLog}
	}
	service.loader = loader
	service.addLog("info", "runtime", "embedded Xray runtime service starting")
	if len(activeConfiguration) > maxConfigurationBytes {
		return nil, errors.New("active Xray configuration exceeds the size limit")
	}
	if len(activeConfiguration) == 0 {
		return service, nil
	}
	engine, err := loader.Load(activeConfiguration)
	if err != nil {
		return nil, errors.New("load active Xray configuration failed")
	}
	if err := engine.Start(); err != nil {
		_ = engine.Close()
		return nil, errors.New("start active Xray configuration failed")
	}
	protocols, err := ConfiguredProtocols(activeConfiguration)
	if err != nil {
		_ = engine.Close()
		return nil, err
	}
	service.engine = engine
	service.inboundTags, err = ConfiguredInboundTags(activeConfiguration)
	if err != nil {
		_ = engine.Close()
		return nil, err
	}
	service.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING
	service.activeRevision = activeRevision
	service.protocols = protocols
	service.telemetry = telemetryCapabilitiesFor(activeConfiguration, engine.StatsAvailable())
	service.addLog("info", "runtime", "embedded Xray instance started")
	return service, nil
}

// Close shuts down the embedded Xray instance.
func (s *Service) Close() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
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

// Fatal reports an unrecoverable core lifecycle error. The entrypoint should
// stop the process so Docker can reconstruct the runtime from active.json.
func (s *Service) Fatal() <-chan error { return s.fatal }

func (s *Service) markFatal(err error) {
	s.mu.Lock()
	s.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_FAILED
	s.lastError = "Xray runtime requires process restart"
	s.mu.Unlock()
	s.addLog("error", "runtime", "Xray runtime entered an unrecoverable state")
	select {
	case s.fatal <- err:
	default:
	}
}

func (s *Service) addLog(level, component, message string) {
	s.mu.Lock()
	if s.logLimit < 1 {
		s.logLimit = 200
	}
	entry := logRecord{at: time.Now().UTC(), level: level, component: component, message: redactXrayLog(diagnostics.Redact(message))}
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
			UserManagement: true, TrafficCounters: s.telemetry.trafficCounters,
			OnlineStatus: s.telemetry.onlineStatus, SourceIp: s.telemetry.sourceIP,
			InboundTag: s.inboundTags[protocol],
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
			Message: redactXrayLog(diagnostics.Redact(entry.message)),
		})
	}
	return response, nil
}

// ValidateConfiguration performs builder parsing and full core construction
// in an isolated child process, without binding listeners or replacing the
// active instance.
func (s *Service) ValidateConfiguration(ctx context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.ConfigurationResponse, error) {
	if request == nil || len(request.GetConfigurationJson()) == 0 || len(request.GetConfigurationJson()) > maxConfigurationBytes || len(request.GetOperationId()) > maxOperationIDBytes {
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is empty or exceeds the size limit")
	}
	if strings.TrimSpace(request.GetOperationId()) == "" || request.GetRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "operation ID and positive revision are required")
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if err := s.loader.Validate(ctx, request.GetConfigurationJson()); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "configuration validation timed out")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "configuration validation was canceled")
		}
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is invalid")
	}
	digest := sha256.Sum256(request.GetConfigurationJson())
	return &xrayruntimev1.ConfigurationResponse{
		Valid: true, OperationId: request.GetOperationId(), Revision: request.GetRevision(),
		ConfigurationDigest: hex.EncodeToString(digest[:]),
	}, nil
}

// ApplyConfiguration replaces the single embedded core instance. A failed
// post-close start is unrecoverable in-process and asks the entrypoint to exit.
func (s *Service) ApplyConfiguration(ctx context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.OperationResponse, error) {
	if _, err := s.ValidateConfiguration(ctx, request); err != nil {
		return nil, err
	}
	protocols, err := ConfiguredProtocols(request.GetConfigurationJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is invalid")
	}
	tags, err := ConfiguredInboundTags(request.GetConfigurationJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "configuration snapshot is invalid")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	key := "apply"
	fingerprint := payloadFingerprint(string(request.GetConfigurationJson()))
	key, fingerprint = mutationIdentity(request.GetOperationId(), key, fingerprint)
	already, err := s.fence.Begin(request.GetRevision(), request.GetOperationId(), key, fingerprint)
	if err != nil {
		return nil, revisionStatus(err)
	}
	if already {
		return operationResponse(request.GetOperationId(), request.GetRevision(), true), nil
	}
	if bytes.Equal(s.activeConfig, request.GetConfigurationJson()) {
		if err := s.commit(request.GetRevision(), request.GetOperationId(), key, fingerprint); err != nil {
			return nil, status.Error(codes.Unavailable, "Xray revision state could not be committed")
		}
		return operationResponse(request.GetOperationId(), request.GetRevision(), true), nil
	}
	s.mu.Lock()
	previous := s.engine
	s.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_STOPPING
	s.mu.Unlock()
	if previous != nil {
		if err := previous.Close(); err != nil {
			s.markFatal(err)
			return nil, status.Error(codes.Unavailable, "active Xray instance could not be stopped; runtime is restarting")
		}
	}
	s.mu.Lock()
	s.engine = nil
	s.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_STARTING
	s.mu.Unlock()
	engine, err := s.loader.Load(request.GetConfigurationJson())
	if err == nil {
		err = engine.Start()
	}
	if err != nil {
		if engine != nil {
			_ = engine.Close()
		}
		s.markFatal(err)
		return nil, status.Error(codes.Unavailable, "candidate Xray runtime failed to start; runtime is restarting from the last active configuration")
	}
	s.mu.Lock()
	s.engine = engine
	s.activeConfig = append([]byte(nil), request.GetConfigurationJson()...)
	s.protocols = protocols
	s.inboundTags = tags
	s.telemetry = telemetryCapabilitiesFor(request.GetConfigurationJson(), engine.StatsAvailable())
	s.state = xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING
	s.activeRevision = request.GetRevision()
	s.mu.Unlock()
	if err := s.commit(request.GetRevision(), request.GetOperationId(), key, fingerprint); err != nil {
		s.markFatal(err)
		return nil, status.Error(codes.Unavailable, "Xray revision state could not be committed; runtime is restarting")
	}
	s.addLog("info", "runtime", "embedded Xray configuration applied")
	return operationResponse(request.GetOperationId(), request.GetRevision(), false), nil
}

// ReplaceInbound changes one live inbound without recreating the core process.
func (s *Service) ReplaceInbound(ctx context.Context, request *xrayruntimev1.ReplaceInboundRequest) (*xrayruntimev1.OperationResponse, error) {
	if request == nil || strings.TrimSpace(request.GetInboundTag()) == "" || len(request.GetInboundTag()) > maxInboundTagBytes || len(request.GetCandidateConfigurationJson()) == 0 || len(request.GetCandidateConfigurationJson()) > maxConfigurationBytes || len(request.GetPreviousConfigurationJson()) > maxConfigurationBytes || strings.TrimSpace(request.GetOperationId()) == "" || len(request.GetOperationId()) > maxOperationIDBytes || request.GetRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "inbound tag, operation ID, positive revision, and valid snapshots are required")
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if len(request.GetCandidateConfigurationJson()) > 0 {
		if err := s.loader.Validate(ctx, request.GetCandidateConfigurationJson()); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, status.Error(codes.DeadlineExceeded, "inbound validation timed out")
			}
			if errors.Is(err, context.Canceled) {
				return nil, status.Error(codes.Canceled, "inbound validation was canceled")
			}
			return nil, status.Error(codes.InvalidArgument, "candidate Xray configuration is invalid")
		}
	}
	tags, err := ConfiguredInboundTags(request.GetCandidateConfigurationJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "candidate Xray configuration is invalid")
	}
	protocols, err := ConfiguredProtocols(request.GetCandidateConfigurationJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "candidate Xray configuration is invalid")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	key := "replace-inbound:" + request.GetInboundTag()
	fingerprint := payloadFingerprint(request.GetInboundTag(), string(request.GetCandidateConfigurationJson()), string(request.GetPreviousConfigurationJson()))
	key, fingerprint = mutationIdentity(request.GetOperationId(), key, fingerprint)
	already, err := s.fence.Begin(request.GetRevision(), request.GetOperationId(), key, fingerprint)
	if err != nil {
		return nil, revisionStatus(err)
	}
	if already {
		return operationResponse(request.GetOperationId(), request.GetRevision(), true), nil
	}
	s.mu.RLock()
	engine := s.engine
	s.mu.RUnlock()
	if engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "Xray runtime has no active configuration")
	}
	alreadyCurrent, err := engine.ReplaceInbound(ctx, request.GetInboundTag(), request.GetCandidateConfigurationJson())
	if err != nil {
		if errors.Is(err, ErrInboundRollbackFailed) {
			s.markFatal(err)
			return nil, status.Error(codes.Unavailable, "inbound replacement failed and rollback was unsuccessful; runtime is restarting")
		}
		return nil, status.Error(codes.FailedPrecondition, "Xray inbound replacement failed")
	}
	s.mu.Lock()
	s.inboundTags = tags
	s.activeConfig = append([]byte(nil), request.GetCandidateConfigurationJson()...)
	s.protocols = protocols
	s.telemetry = telemetryCapabilitiesFor(request.GetCandidateConfigurationJson(), engine.StatsAvailable())
	s.mu.Unlock()
	if err := s.commit(request.GetRevision(), request.GetOperationId(), key, fingerprint); err != nil {
		s.markFatal(err)
		return nil, status.Error(codes.Unavailable, "Xray revision state could not be committed; runtime is restarting")
	}
	s.addLog("info", "runtime", "Xray inbound updated")
	return operationResponse(request.GetOperationId(), request.GetRevision(), alreadyCurrent), nil
}

// AddUser adds a user through the inbound's native in-process manager.
func (s *Service) AddUser(ctx context.Context, request *xrayruntimev1.AddUserRequest) (*xrayruntimev1.OperationResponse, error) {
	if request == nil || strings.TrimSpace(request.GetEmail()) == "" || len(request.GetEmail()) > maxUserEmailBytes || strings.TrimSpace(request.GetCredential()) == "" || len(request.GetCredential()) > maxCredentialBytes || len(request.GetFlow()) > maxUserFlowBytes || strings.TrimSpace(request.GetOperationId()) == "" || len(request.GetOperationId()) > maxOperationIDBytes || request.GetRevision() < 0 || !supportedProtocol(request.GetProtocol()) {
		return nil, status.Error(codes.InvalidArgument, "protocol, email, credential, operation ID, and non-negative revision are required")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	tag, engine, err := s.protocolEngine(request.GetProtocol())
	if err != nil {
		return nil, err
	}
	key := userMutationKey("add-user", request.GetProtocol(), request.GetEmail())
	fingerprint := payloadFingerprint(request.GetProtocol().String(), request.GetEmail(), request.GetCredential(), request.GetFlow())
	key, fingerprint = mutationIdentity(request.GetOperationId(), key, fingerprint)
	if request.GetRevision() > 0 {
		already, err := s.fence.Begin(request.GetRevision(), request.GetOperationId(), key, fingerprint)
		if err != nil {
			return nil, revisionStatus(err)
		}
		if already {
			return operationResponse(request.GetOperationId(), request.GetRevision(), true), nil
		}
	}
	wasPresent, err := engine.AddUser(ctx, request.GetProtocol(), tag, request.GetEmail(), request.GetCredential(), request.GetFlow())
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Xray user could not be added")
	}
	if request.GetRevision() > 0 {
		if err := s.commit(request.GetRevision(), request.GetOperationId(), key, fingerprint); err != nil {
			s.markFatal(err)
			return nil, status.Error(codes.Unavailable, "Xray revision state could not be committed; runtime is restarting")
		}
	}
	return operationResponse(request.GetOperationId(), request.GetRevision(), wasPresent), nil
}

// RemoveUser revokes a user through the inbound's native in-process manager.
func (s *Service) RemoveUser(ctx context.Context, request *xrayruntimev1.RemoveUserRequest) (*xrayruntimev1.OperationResponse, error) {
	if request == nil || strings.TrimSpace(request.GetEmail()) == "" || len(request.GetEmail()) > maxUserEmailBytes || strings.TrimSpace(request.GetOperationId()) == "" || len(request.GetOperationId()) > maxOperationIDBytes || request.GetRevision() < 0 || !supportedProtocol(request.GetProtocol()) {
		return nil, status.Error(codes.InvalidArgument, "protocol, email, operation ID, and non-negative revision are required")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	tag, engine, err := s.protocolEngine(request.GetProtocol())
	if err != nil {
		return nil, err
	}
	key := userMutationKey("remove-user", request.GetProtocol(), request.GetEmail())
	fingerprint := payloadFingerprint(request.GetProtocol().String(), request.GetEmail())
	key, fingerprint = mutationIdentity(request.GetOperationId(), key, fingerprint)
	if request.GetRevision() > 0 {
		already, err := s.fence.Begin(request.GetRevision(), request.GetOperationId(), key, fingerprint)
		if err != nil {
			return nil, revisionStatus(err)
		}
		if already {
			return operationResponse(request.GetOperationId(), request.GetRevision(), true), nil
		}
	}
	wasAbsent, err := engine.RemoveUser(ctx, tag, request.GetEmail())
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Xray user could not be removed")
	}
	delete(s.lastSeen, request.GetEmail())
	if request.GetRevision() > 0 {
		if err := s.commit(request.GetRevision(), request.GetOperationId(), key, fingerprint); err != nil {
			s.markFatal(err)
			return nil, status.Error(codes.Unavailable, "Xray revision state could not be committed; runtime is restarting")
		}
	}
	return operationResponse(request.GetOperationId(), request.GetRevision(), wasAbsent), nil
}

// ListUsers exposes the non-secret user labels from one configured inbound.
func (s *Service) ListUsers(ctx context.Context, request *xrayruntimev1.ListUsersRequest) (*xrayruntimev1.ListUsersResponse, error) {
	if request == nil || !supportedProtocol(request.GetProtocol()) {
		return nil, status.Error(codes.InvalidArgument, "protocol is required")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	tag, engine, err := s.protocolEngine(request.GetProtocol())
	if err != nil {
		return nil, err
	}
	users, err := engine.ListUsers(ctx, tag)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Xray users are unavailable")
	}
	sort.Strings(users)
	return &xrayruntimev1.ListUsersResponse{Emails: users}, nil
}

func (s *Service) GetTelemetry(ctx context.Context, _ *xrayruntimev1.EmptyRequest) (*xrayruntimev1.TelemetryResponse, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	engine := s.engine
	tags := make(map[xrayruntimev1.Protocol]string, len(s.inboundTags))
	for protocol, tag := range s.inboundTags {
		tags[protocol] = tag
	}
	capabilities := s.telemetry
	s.mu.RUnlock()
	if engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "Xray runtime has no active configuration")
	}
	if !engine.StatsAvailable() {
		return nil, status.Error(codes.Unavailable, "Xray telemetry is unavailable")
	}
	users, err := engine.GetTelemetry(ctx, tags)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "Xray telemetry request timed out")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "Xray telemetry request was canceled")
		}
		return nil, status.Error(codes.Unavailable, "Xray telemetry could not be read")
	}
	response := &xrayruntimev1.TelemetryResponse{SampledAt: timestamppb.New(time.Now().UTC())}
	seenEmails := make(map[string]struct{}, len(users))
	for _, user := range users {
		seenEmails[user.Email] = struct{}{}
		item := &xrayruntimev1.UserTelemetry{Email: user.Email}
		if capabilities.trafficCounters {
			item.UploadBytes = clampNonNegative(user.UploadBytes)
			item.DownloadBytes = clampNonNegative(user.DownloadBytes)
		}
		if capabilities.onlineStatus {
			item.Online = user.Online
			if !user.LastSeen.IsZero() && user.LastSeen.After(s.lastSeen[user.Email]) {
				s.lastSeen[user.Email] = user.LastSeen.UTC()
			}
			lastSeen := s.lastSeen[user.Email]
			if !lastSeen.IsZero() {
				item.LastSeen = timestamppb.New(lastSeen)
			}
		}
		if capabilities.sourceIP {
			for _, observation := range user.SourceIPs {
				ip := &xrayruntimev1.IPObservation{Address: observation.Address}
				if !observation.LastSeen.IsZero() {
					ip.LastSeen = timestamppb.New(observation.LastSeen.UTC())
				}
				item.SourceIps = append(item.SourceIps, ip)
			}
		}
		response.Users = append(response.Users, item)
	}
	for email := range s.lastSeen {
		if _, exists := seenEmails[email]; !exists {
			delete(s.lastSeen, email)
		}
	}
	return response, nil
}

func (s *Service) ProbeRealityTarget(ctx context.Context, request *xrayruntimev1.ProbeRealityTargetRequest) (*xrayruntimev1.ProbeResponse, error) {
	if request == nil || strings.TrimSpace(request.GetTarget()) == "" {
		return nil, status.Error(codes.InvalidArgument, "REALITY target is required")
	}
	probe := s.probeTarget
	if probe == nil {
		probe = probeRealityTarget
	}
	if err := probe(ctx, request.GetTarget(), request.GetServerName()); err != nil {
		if errors.Is(err, errInvalidProbeTarget) {
			return nil, status.Error(codes.InvalidArgument, "REALITY target is invalid")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "REALITY target probe timed out")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "REALITY target probe was canceled")
		}
		return nil, status.Error(codes.Unavailable, "REALITY target probe failed")
	}
	return &xrayruntimev1.ProbeResponse{Ok: true, CheckedAt: timestamppb.New(time.Now().UTC())}, nil
}

func (s *Service) ProbeIPv6Egress(ctx context.Context, _ *xrayruntimev1.EmptyRequest) (*xrayruntimev1.ProbeResponse, error) {
	probe := s.probeIPv6
	if probe == nil {
		probe = probeIPv6Egress
	}
	if err := probe(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "IPv6 egress probe timed out")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "IPv6 egress probe was canceled")
		}
		return nil, status.Error(codes.Unavailable, "IPv6 egress probe failed")
	}
	return &xrayruntimev1.ProbeResponse{Ok: true, CheckedAt: timestamppb.New(time.Now().UTC())}, nil
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

func supportedProtocol(protocol xrayruntimev1.Protocol) bool {
	switch protocol {
	case xrayruntimev1.Protocol_PROTOCOL_VLESS, xrayruntimev1.Protocol_PROTOCOL_VMESS, xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2:
		return true
	default:
		return false
	}
}

// ConfiguredInboundTags maps supported product protocols to their configured
// inbound tags. Multiple inbounds for one protocol are rejected until the API
// supports selecting an inbound explicitly.
func ConfiguredInboundTags(configuration []byte) (map[xrayruntimev1.Protocol]string, error) {
	var document struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Tag      string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configuration, &document); err != nil {
		return nil, fmt.Errorf("read Xray inbound tags: %w", err)
	}
	tags := make(map[xrayruntimev1.Protocol]string)
	for _, inbound := range document.Inbounds {
		protocolName := inbound.Protocol
		if protocolName == "hysteria" {
			protocolName = "hysteria2"
		}
		protocol, supported := protocolFromName(protocolName)
		if !supported {
			continue
		}
		if strings.TrimSpace(inbound.Tag) == "" {
			return nil, fmt.Errorf("supported Xray inbound %q has no tag", protocolName)
		}
		if _, exists := tags[protocol]; exists {
			return nil, fmt.Errorf("multiple Xray inbounds configured for protocol %q", protocolName)
		}
		tags[protocol] = inbound.Tag
	}
	return tags, nil
}

func mutationIdentity(operationID, key, fingerprint string) (string, string) {
	if strings.HasSuffix(operationID, "-rollback") {
		key = "rollback:" + key
	}
	return key, fingerprint
}

func userMutationKey(action string, protocol xrayruntimev1.Protocol, email string) string {
	return action + ":" + protocol.String() + ":" + payloadFingerprint(email)
}

func revisionStatus(err error) error {
	if errors.Is(err, ErrRevisionIO) {
		return status.Error(codes.Unavailable, "Xray revision journal is unavailable")
	}
	if errors.Is(err, ErrStaleRevision) || errors.Is(err, ErrRevisionConflict) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return status.Error(codes.FailedPrecondition, err.Error())
}

func operationResponse(operationID string, revision int64, alreadyApplied bool) *xrayruntimev1.OperationResponse {
	return &xrayruntimev1.OperationResponse{OperationId: operationID, Revision: revision, AlreadyApplied: alreadyApplied}
}

func contextFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return nil
}

func (s *Service) protocolEngine(protocol xrayruntimev1.Protocol) (string, EngineHandle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tag, configured := s.inboundTags[protocol]
	if !configured || s.engine == nil {
		return "", nil, status.Error(codes.FailedPrecondition, "requested Xray protocol is not configured")
	}
	return tag, s.engine, nil
}

func (s *Service) commit(revision int64, operationID, key, fingerprint string) error {
	if err := s.fence.Commit(revision, operationID, key, fingerprint); err != nil {
		return err
	}
	s.mu.Lock()
	if revision > s.activeRevision {
		s.activeRevision = revision
	}
	s.mu.Unlock()
	return nil
}
