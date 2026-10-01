package controller

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// XrayRuntime is the current Xray adapter contract. It intentionally excludes
// HTTP/UI and persistence concerns owned by the backend.
type XrayRuntime interface {
	Health(context.Context) error
	Status(context.Context) (domain.XrayRuntimeStatus, error)
	Logs(context.Context) ([]string, error)
	Validate(context.Context, string, string) error
	Apply(context.Context, string, string) error
	ReplaceInbound(context.Context, string, string, string, string) error
	ProbeTarget(context.Context, string, string) error
	ProbeIPv6(context.Context) error
}

// XrayHandlerRuntime provides the live per-user operations supported by Xray.
type XrayHandlerRuntime interface {
	AddUser(context.Context, string, string, string) error
	RemoveUser(context.Context, string) error
	Users(context.Context) ([]string, error)
	AddHysteriaUser(context.Context, string, string) error
	RemoveHysteriaUser(context.Context, string) error
	AddVMessUser(context.Context, string, string) error
	RemoveVMessUser(context.Context, string) error
	UsersInInbound(context.Context, string) ([]string, error)
}

// XrayStatsRuntime exposes upstream stats in a protocol-neutral backend DTO.
type XrayStatsRuntime interface {
	Poll(context.Context) ([]xrayapi.UserStats, error)
}

// AmneziaWGRuntime owns AmneziaWG peer lifecycle and credential-bearing
// profiles. Controller returns private material only on explicit delivery or
// backup calls and never logs it.
type AmneziaWGRuntime interface {
	awgcontrol.Gateway
	PeerStats(context.Context) ([]domain.AmneziaWGPeerStats, error)
	ExportBackup(context.Context) ([]byte, error)
	RestoreBackup(context.Context, []byte) error
}

// Service orchestrates runtime adapters behind the typed Controller API.
type Service struct {
	controllerv1.UnimplementedControllerServer
	xray           XrayRuntime
	handler        XrayHandlerRuntime
	stats          XrayStatsRuntime
	awg            AmneziaWGRuntime
	now            func() time.Time
	userMutationMu sync.Mutex
}

// NewService creates a Controller backed by the Xray runtime adapter.
func NewService(xray XrayRuntime) *Service {
	return &Service{xray: xray, now: time.Now}
}

// NewServiceWithAdapters composes the configured protocol runtime adapters.
func NewServiceWithAdapters(xray XrayRuntime, handler XrayHandlerRuntime, stats XrayStatsRuntime, awg AmneziaWGRuntime) *Service {
	return &Service{xray: xray, handler: handler, stats: stats, awg: awg, now: time.Now}
}

func (s *Service) Health(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.HealthResponse, error) {
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Health(ctx); err != nil {
		return nil, status.Error(codes.Unavailable, "Xray adapter is unavailable")
	}
	return &controllerv1.HealthResponse{Ok: true, ControllerVersion: "v1"}, nil
}

func (s *Service) GetCapabilities(context.Context, *controllerv1.EmptyRequest) (*controllerv1.CapabilitiesResponse, error) {
	return &controllerv1.CapabilitiesResponse{
		Xray:      &controllerv1.ProtocolCapability{Configured: s != nil && s.xray != nil, Protocols: []string{"vless", "vmess", "hysteria2"}},
		Amneziawg: &controllerv1.ProtocolCapability{Configured: s != nil && s.awg != nil, Protocols: []string{"amneziawg"}},
	}, nil
}

func (s *Service) GetStatus(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.StatusResponse, error) {
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	value, err := xray.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &controllerv1.StatusResponse{
		Protocol: value.Protocol, XrayVersion: value.XrayVersion, State: value.State,
		LastError: value.LastError, StartedAt: protobufTime(value.StartedAt),
		ActiveRevision: value.ActiveRevision, InboundTags: append([]string(nil), value.InboundTags...), StatsAvailable: value.StatsAvailable,
	}, nil
}

func (s *Service) GetLogs(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.LogsResponse, error) {
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	lines, err := xray.Logs(ctx)
	if err != nil {
		return nil, err
	}
	return &controllerv1.LogsResponse{Lines: append([]string{}, lines...)}, nil
}

func (s *Service) ValidateConfig(ctx context.Context, request *controllerv1.ValidateConfigRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Path == "" || request.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "path and operation_id are required")
	}
	ctx, err := configOperationContext(ctx, request.OperationId, request.StateRevision)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Validate(ctx, request.Path, request.OperationId); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true, OperationId: request.OperationId, StateRevision: request.StateRevision}, nil
}

func (s *Service) ApplyConfig(ctx context.Context, request *controllerv1.ApplyConfigRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Path == "" || request.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "path and operation_id are required")
	}
	ctx, err := configOperationContext(ctx, request.OperationId, request.StateRevision)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Apply(ctx, request.Path, request.OperationId); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true, OperationId: request.OperationId, StateRevision: request.StateRevision}, nil
}

func (s *Service) ReplaceInbound(ctx context.Context, request *controllerv1.ReplaceInboundRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.CandidatePath == "" || request.PreviousPath == "" || request.Tag == "" || request.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "candidate_path, previous_path, tag, and operation_id are required")
	}
	ctx, err := configOperationContext(ctx, request.OperationId, request.StateRevision)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ReplaceInbound(ctx, request.CandidatePath, request.PreviousPath, request.Tag, request.OperationId); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true, OperationId: request.OperationId, StateRevision: request.StateRevision}, nil
}

func configOperationContext(ctx context.Context, operationID string, revision int64) (context.Context, error) {
	if revision < 1 {
		return nil, status.Error(codes.InvalidArgument, "state_revision must be positive")
	}
	operationBytes, err := hex.DecodeString(operationID)
	if len(operationID) != 32 || err != nil || len(operationBytes) != 16 {
		return nil, status.Error(codes.InvalidArgument, "operation_id must be a 128-bit hexadecimal ID")
	}
	operationID = strings.ToLower(operationID)
	if traceOperationID := interaction.OperationID(ctx); traceOperationID != "" && traceOperationID != operationID {
		return nil, status.Error(codes.InvalidArgument, "operation_id does not match request metadata")
	}
	if traceRevision := interaction.StateRevision(ctx); traceRevision > 0 && traceRevision != revision {
		return nil, status.Error(codes.InvalidArgument, "state_revision does not match request metadata")
	}
	ctx = interaction.WithOperationID(ctx, operationID)
	return interaction.WithStateRevision(ctx, revision), nil
}

func (s *Service) ProbeTarget(ctx context.Context, request *controllerv1.ProbeTargetRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "target is required")
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ProbeTarget(ctx, request.Target, request.Sni); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true}, nil
}

func (s *Service) ProbeIPv6(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.ProbeIPv6Response, error) {
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ProbeIPv6(ctx); err != nil {
		return nil, err
	}
	return &controllerv1.ProbeIPv6Response{Ok: true, CheckedAt: protobufTime(s.now().UTC())}, nil
}

func (s *Service) AddDeviceUser(ctx context.Context, request *controllerv1.AddDeviceUserRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Protocol == "" || request.Email == "" || request.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "protocol, email, and id are required")
	}
	if !supportedXrayProtocol(request.Protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", request.Protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	s.userMutationMu.Lock()
	defer s.userMutationMu.Unlock()
	if interaction.OperationID(ctx) != "" {
		users, err := deviceUsers(ctx, handler, request.Protocol)
		if err != nil {
			return nil, err
		}
		if containsUser(users, request.Email) {
			return &controllerv1.OperationResponse{Ok: true, AlreadyApplied: true}, nil
		}
	}
	var mutationErr error
	switch request.Protocol {
	case "vless":
		mutationErr = handler.AddUser(ctx, request.Email, request.Id, request.Flow)
	case "hysteria2":
		mutationErr = handler.AddHysteriaUser(ctx, request.Email, request.Id)
	case "vmess":
		mutationErr = handler.AddVMessUser(ctx, request.Email, request.Id)
	}
	if mutationErr != nil {
		return nil, mutationErr
	}
	return &controllerv1.OperationResponse{Ok: true}, nil
}

func (s *Service) RemoveDeviceUser(ctx context.Context, request *controllerv1.RemoveDeviceUserRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Protocol == "" || request.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "protocol and email are required")
	}
	if !supportedXrayProtocol(request.Protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", request.Protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	s.userMutationMu.Lock()
	defer s.userMutationMu.Unlock()
	if interaction.OperationID(ctx) != "" {
		users, err := deviceUsers(ctx, handler, request.Protocol)
		if err != nil {
			return nil, err
		}
		if !containsUser(users, request.Email) {
			return &controllerv1.OperationResponse{Ok: true, AlreadyApplied: true}, nil
		}
	}
	var mutationErr error
	switch request.Protocol {
	case "vless":
		mutationErr = handler.RemoveUser(ctx, request.Email)
	case "hysteria2":
		mutationErr = handler.RemoveHysteriaUser(ctx, request.Email)
	case "vmess":
		mutationErr = handler.RemoveVMessUser(ctx, request.Email)
	}
	if mutationErr != nil {
		return nil, mutationErr
	}
	return &controllerv1.OperationResponse{Ok: true}, nil
}

func deviceUsers(ctx context.Context, handler XrayHandlerRuntime, protocol string) ([]string, error) {
	switch protocol {
	case "vless":
		return handler.Users(ctx)
	case "hysteria2":
		return handler.UsersInInbound(ctx, "hysteria2")
	case "vmess":
		return handler.UsersInInbound(ctx, "vmess-tls")
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", protocol)
	}
}

func containsUser(users []string, email string) bool {
	for _, current := range users {
		if current == email {
			return true
		}
	}
	return false
}

func (s *Service) ListDeviceUsers(ctx context.Context, request *controllerv1.ListDeviceUsersRequest) (*controllerv1.ListDeviceUsersResponse, error) {
	if request == nil || request.Protocol == "" {
		return nil, status.Error(codes.InvalidArgument, "protocol is required")
	}
	if !supportedXrayProtocol(request.Protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", request.Protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	users, err := deviceUsers(ctx, handler, request.Protocol)
	if err != nil {
		return nil, err
	}
	return &controllerv1.ListDeviceUsersResponse{Users: append([]string{}, users...)}, nil
}

func (s *Service) GetXrayTelemetry(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.XrayTelemetryResponse, error) {
	if s == nil || s.stats == nil {
		return nil, status.Error(codes.Unavailable, "Xray statistics adapter is unavailable")
	}
	users, err := s.stats.Poll(ctx)
	if err != nil {
		return nil, err
	}
	response := &controllerv1.XrayTelemetryResponse{Users: make([]*controllerv1.XrayUserTelemetry, 0, len(users))}
	for _, user := range users {
		item := &controllerv1.XrayUserTelemetry{Email: user.Email, Protocol: user.Protocol, UploadBytes: user.UploadBytes, DownloadBytes: user.DownloadBytes, LastSeen: protobufTime(user.LastSeen)}
		for _, address := range user.SourceIPs {
			item.SourceIps = append(item.SourceIps, &controllerv1.IPObservation{Address: address.Address, LastSeen: protobufTime(address.LastSeen)})
		}
		response.Users = append(response.Users, item)
	}
	return response, nil
}

func (s *Service) GetAmneziaWGStatus(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.AmneziaWGStatusResponse, error) {
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	value, err := awg.Status(ctx)
	if err != nil {
		return nil, err
	}
	return &controllerv1.AmneziaWGStatusResponse{Running: value.Running, PublicKey: value.PublicKey, ListenPort: int32(value.ListenPort), PublicHost: value.PublicHost, PublicPort: int32(value.PublicPort), PeerCount: int32(value.PeerCount), Ipv4Network: value.IPv4Network, Ipv6Network: value.IPv6Network, ServiceVersion: value.ServiceVersion}, nil
}

func (s *Service) ListAmneziaWGPeers(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.ListAmneziaWGPeersResponse, error) {
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peers, err := awg.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	response := &controllerv1.ListAmneziaWGPeersResponse{Peers: make([]*controllerv1.AmneziaWGPeer, 0, len(peers))}
	for _, peer := range peers {
		response.Peers = append(response.Peers, toProtoPeer(peer))
	}
	return response, nil
}

func (s *Service) CreateAmneziaWGPeer(ctx context.Context, request *controllerv1.CreateAmneziaWGPeerRequest) (*controllerv1.AmneziaWGPeer, error) {
	if request == nil || request.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peer, err := awg.CreatePeer(ctx, request.Name)
	if err != nil {
		return nil, err
	}
	return toProtoPeer(peer), nil
}

func (s *Service) RemoveAmneziaWGPeer(ctx context.Context, request *controllerv1.RemoveAmneziaWGPeerRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || request.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	if err := awg.RemovePeer(ctx, request.Name); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true}, nil
}

func (s *Service) GetAmneziaWGPeerStats(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.AmneziaWGPeerStatsResponse, error) {
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peers, err := awg.PeerStats(ctx)
	if err != nil {
		return nil, err
	}
	response := &controllerv1.AmneziaWGPeerStatsResponse{Peers: make([]*controllerv1.AmneziaWGPeerStats, 0, len(peers))}
	for _, peer := range peers {
		response.Peers = append(response.Peers, &controllerv1.AmneziaWGPeerStats{Name: peer.Name, SourceIp: peer.SourceIP, LastSeen: protobufTime(peer.LastSeen), UploadBytes: peer.UploadBytes, DownloadBytes: peer.DownloadBytes})
	}
	return response, nil
}

func (s *Service) GetAmneziaWGClientConfig(ctx context.Context, request *controllerv1.GetAmneziaWGClientConfigRequest) (*controllerv1.AmneziaWGClientConfigResponse, error) {
	if request == nil || request.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	config, err := awg.ClientConfig(ctx, request.Name)
	if err != nil {
		return nil, err
	}
	return &controllerv1.AmneziaWGClientConfigResponse{Config: config}, nil
}

func (s *Service) ExportAmneziaWGBackup(ctx context.Context, _ *controllerv1.EmptyRequest) (*controllerv1.AmneziaWGBackupResponse, error) {
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	data, err := awg.ExportBackup(ctx)
	if err != nil {
		return nil, err
	}
	return &controllerv1.AmneziaWGBackupResponse{Data: data}, nil
}

func (s *Service) RestoreAmneziaWGBackup(ctx context.Context, request *controllerv1.RestoreAmneziaWGBackupRequest) (*controllerv1.OperationResponse, error) {
	if request == nil || len(request.Data) == 0 {
		return nil, status.Error(codes.InvalidArgument, "backup data is required")
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	if err := awg.RestoreBackup(ctx, request.Data); err != nil {
		return nil, err
	}
	return &controllerv1.OperationResponse{Ok: true}, nil
}

func (s *Service) xrayHandler() (XrayHandlerRuntime, error) {
	if s == nil || s.handler == nil {
		return nil, status.Error(codes.Unavailable, "Xray Handler adapter is unavailable")
	}
	return s.handler, nil
}

func supportedXrayProtocol(protocol string) bool {
	switch protocol {
	case "vless", "vmess", "hysteria2":
		return true
	default:
		return false
	}
}

func (s *Service) awgRuntime() (AmneziaWGRuntime, error) {
	if s == nil || s.awg == nil {
		return nil, status.Error(codes.Unavailable, "AmneziaWG adapter is unavailable")
	}
	return s.awg, nil
}

func protobufTime(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func toProtoPeer(peer domain.AmneziaWGPeer) *controllerv1.AmneziaWGPeer {
	return &controllerv1.AmneziaWGPeer{Name: peer.Name, PublicKey: peer.PublicKey, Ipv4: peer.IPv4, Ipv6: peer.IPv6, CreatedAt: protobufTime(peer.CreatedAt)}
}

func (s *Service) runtime() (XrayRuntime, error) {
	if s == nil || s.xray == nil {
		return nil, status.Error(codes.Unavailable, "Xray adapter is unavailable")
	}
	return s.xray, nil
}

var _ controllerv1.ControllerServer = (*Service)(nil)
