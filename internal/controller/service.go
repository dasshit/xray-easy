package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"sync"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/supervisor"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// XrayRuntime is the current Xray adapter contract. It intentionally excludes
// HTTP/UI and persistence concerns owned by the backend.
type XrayRuntime interface {
	Health(context.Context) error
	Status(context.Context) (supervisor.Status, error)
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

// Service orchestrates runtime adapters behind the Controller API.
type Service struct {
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

func (s *Service) Health(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Health(ctx); err != nil {
		return nil, status.Error(codes.Unavailable, "Xray adapter is unavailable")
	}
	return response(map[string]any{"ok": true, "controller_version": "v1"})
}

func (s *Service) GetCapabilities(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	capabilities := map[string]any{
		"xray":      map[string]any{"configured": s != nil && s.xray != nil, "protocols": []any{"vless", "vmess", "hysteria2"}},
		"amneziawg": map[string]any{"configured": s != nil && s.awg != nil, "protocols": []any{"amneziawg"}},
	}
	return response(capabilities)
}

func (s *Service) GetStatus(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	value, err := xray.Status(ctx)
	if err != nil {
		return nil, err
	}
	startedAt := ""
	if !value.StartedAt.IsZero() {
		startedAt = value.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	return response(map[string]any{
		"protocol": value.Protocol, "xray_version": value.XrayVersion,
		"state": value.State, "pid": value.PID, "config_path": value.ConfigPath,
		"last_error": value.LastError, "last_exit": value.LastExit,
		"restart_count": value.RestartCount, "started_at": startedAt,
	})
}

func (s *Service) GetLogs(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	lines, err := xray.Logs(ctx)
	if err != nil {
		return nil, err
	}
	values := make([]any, len(lines))
	for index, line := range lines {
		values[index] = line
	}
	return response(map[string]any{"lines": values})
}

func (s *Service) ValidateConfig(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "path", "operation_id")
	if err != nil {
		return nil, err
	}
	path, err := stringField(values, "path", true)
	if err != nil {
		return nil, err
	}
	operation, err := stringField(values, "operation_id", false)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Validate(ctx, path, operation); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true, "operation_id": operation})
}

func (s *Service) ApplyConfig(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "path", "operation_id")
	if err != nil {
		return nil, err
	}
	path, err := stringField(values, "path", true)
	if err != nil {
		return nil, err
	}
	operation, err := stringField(values, "operation_id", true)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.Apply(ctx, path, operation); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true, "operation_id": operation})
}

func (s *Service) ReplaceInbound(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "candidate_path", "previous_path", "tag", "operation_id")
	if err != nil {
		return nil, err
	}
	candidate, err := stringField(values, "candidate_path", true)
	if err != nil {
		return nil, err
	}
	previous, err := stringField(values, "previous_path", true)
	if err != nil {
		return nil, err
	}
	tag, err := stringField(values, "tag", true)
	if err != nil {
		return nil, err
	}
	operation, err := stringField(values, "operation_id", true)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ReplaceInbound(ctx, candidate, previous, tag, operation); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true, "operation_id": operation})
}

func (s *Service) ProbeTarget(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "target", "sni")
	if err != nil {
		return nil, err
	}
	target, err := stringField(values, "target", true)
	if err != nil {
		return nil, err
	}
	sni, err := stringField(values, "sni", false)
	if err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ProbeTarget(ctx, target, sni); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true})
}

func (s *Service) ProbeIPv6(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	xray, err := s.runtime()
	if err != nil {
		return nil, err
	}
	if err := xray.ProbeIPv6(ctx); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true, "checked_at": s.now().UTC().Format(time.RFC3339Nano)})
}

func (s *Service) AddDeviceUser(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "protocol", "email", "id", "flow")
	if err != nil {
		return nil, err
	}
	protocol, err := stringField(values, "protocol", true)
	if err != nil {
		return nil, err
	}
	email, err := stringField(values, "email", true)
	if err != nil {
		return nil, err
	}
	id, err := stringField(values, "id", true)
	if err != nil {
		return nil, err
	}
	flow, err := stringField(values, "flow", false)
	if err != nil {
		return nil, err
	}
	if !supportedXrayProtocol(protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	s.userMutationMu.Lock()
	defer s.userMutationMu.Unlock()
	if interaction.OperationID(ctx) != "" {
		users, err := deviceUsers(ctx, handler, protocol)
		if err != nil {
			return nil, err
		}
		if containsUser(users, email) {
			return response(map[string]any{"ok": true, "already_applied": true})
		}
	}
	switch protocol {
	case "vless":
		err = handler.AddUser(ctx, email, id, flow)
	case "hysteria2":
		err = handler.AddHysteriaUser(ctx, email, id)
	case "vmess":
		err = handler.AddVMessUser(ctx, email, id)
	}
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true})
}

func (s *Service) RemoveDeviceUser(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "protocol", "email")
	if err != nil {
		return nil, err
	}
	protocol, err := stringField(values, "protocol", true)
	if err != nil {
		return nil, err
	}
	email, err := stringField(values, "email", true)
	if err != nil {
		return nil, err
	}
	if !supportedXrayProtocol(protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	s.userMutationMu.Lock()
	defer s.userMutationMu.Unlock()
	if interaction.OperationID(ctx) != "" {
		users, err := deviceUsers(ctx, handler, protocol)
		if err != nil {
			return nil, err
		}
		if !containsUser(users, email) {
			return response(map[string]any{"ok": true, "already_applied": true})
		}
	}
	switch protocol {
	case "vless":
		err = handler.RemoveUser(ctx, email)
	case "hysteria2":
		err = handler.RemoveHysteriaUser(ctx, email)
	case "vmess":
		err = handler.RemoveVMessUser(ctx, email)
	}
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true})
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

func (s *Service) ListDeviceUsers(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "protocol")
	if err != nil {
		return nil, err
	}
	protocol, err := stringField(values, "protocol", true)
	if err != nil {
		return nil, err
	}
	if !supportedXrayProtocol(protocol) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported Xray protocol %q", protocol)
	}
	handler, err := s.xrayHandler()
	if err != nil {
		return nil, err
	}
	var users []string
	switch protocol {
	case "vless":
		users, err = handler.Users(ctx)
	case "hysteria2":
		users, err = handler.UsersInInbound(ctx, "hysteria2")
	case "vmess":
		users, err = handler.UsersInInbound(ctx, "vmess-tls")
	}
	if err != nil {
		return nil, err
	}
	valuesList := make([]any, len(users))
	for index, user := range users {
		valuesList[index] = user
	}
	return response(map[string]any{"users": valuesList})
}

func (s *Service) GetXrayTelemetry(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	if s == nil || s.stats == nil {
		return nil, status.Error(codes.Unavailable, "Xray statistics adapter is unavailable")
	}
	users, err := s.stats.Poll(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(users))
	for _, user := range users {
		ips := make([]any, 0, len(user.SourceIPs))
		for _, address := range user.SourceIPs {
			ips = append(ips, map[string]any{"address": address.Address, "last_seen": runtimeTime(address.LastSeen)})
		}
		items = append(items, map[string]any{"email": user.Email, "upload_bytes": strconv.FormatInt(user.UploadBytes, 10), "download_bytes": strconv.FormatInt(user.DownloadBytes, 10), "last_seen": runtimeTime(user.LastSeen), "source_ips": ips})
	}
	return response(map[string]any{"users": items})
}

func (s *Service) GetAmneziaWGStatus(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	value, err := awg.Status(ctx)
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"running": value.Running, "public_key": value.PublicKey, "listen_port": value.ListenPort, "public_host": value.PublicHost, "public_port": value.PublicPort, "peer_count": value.PeerCount, "ipv4_network": value.IPv4Network, "ipv6_network": value.IPv6Network, "service_version": value.ServiceVersion})
}

func (s *Service) ListAmneziaWGPeers(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peers, err := awg.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(peers))
	for _, peer := range peers {
		items = append(items, map[string]any{"name": peer.Name, "public_key": peer.PublicKey, "ipv4": peer.IPv4, "ipv6": peer.IPv6, "created_at": runtimeTime(peer.CreatedAt)})
	}
	return response(map[string]any{"peers": items})
}

func (s *Service) CreateAmneziaWGPeer(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "name")
	if err != nil {
		return nil, err
	}
	name, err := stringField(values, "name", true)
	if err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peer, err := awg.CreatePeer(ctx, name)
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"name": peer.Name, "public_key": peer.PublicKey, "ipv4": peer.IPv4, "ipv6": peer.IPv6, "created_at": runtimeTime(peer.CreatedAt)})
}

func (s *Service) RemoveAmneziaWGPeer(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "name")
	if err != nil {
		return nil, err
	}
	name, err := stringField(values, "name", true)
	if err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	if err := awg.RemovePeer(ctx, name); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true})
}

func (s *Service) GetAmneziaWGPeerStats(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	peers, err := awg.PeerStats(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(peers))
	for _, peer := range peers {
		items = append(items, map[string]any{"name": peer.Name, "source_ip": peer.SourceIP, "last_seen": runtimeTime(peer.LastSeen), "upload_bytes": strconv.FormatInt(peer.UploadBytes, 10), "download_bytes": strconv.FormatInt(peer.DownloadBytes, 10)})
	}
	return response(map[string]any{"peers": items})
}

func (s *Service) GetAmneziaWGClientConfig(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "name")
	if err != nil {
		return nil, err
	}
	name, err := stringField(values, "name", true)
	if err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	config, err := awg.ClientConfig(ctx, name)
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"config": config})
}

func (s *Service) ExportAmneziaWGBackup(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if err := fields(request); err != nil {
		return nil, err
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	data, err := awg.ExportBackup(ctx)
	if err != nil {
		return nil, err
	}
	return response(map[string]any{"data": base64.StdEncoding.EncodeToString(data)})
}

func (s *Service) RestoreAmneziaWGBackup(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	values, err := requireFields(request, "data")
	if err != nil {
		return nil, err
	}
	encoded, err := stringField(values, "data", true)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "backup data must be base64")
	}
	awg, err := s.awgRuntime()
	if err != nil {
		return nil, err
	}
	if err := awg.RestoreBackup(ctx, data); err != nil {
		return nil, err
	}
	return response(map[string]any{"ok": true})
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

func runtimeTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func fields(request *structpb.Struct) error {
	if request != nil && len(request.GetFields()) != 0 {
		return status.Error(codes.InvalidArgument, "unexpected request fields")
	}
	return nil
}

func requireFields(request *structpb.Struct, allowed ...string) (map[string]*structpb.Value, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	values := request.GetFields()
	allowlist := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowlist[key] = struct{}{}
	}
	for key := range values {
		if _, ok := allowlist[key]; !ok {
			return nil, status.Errorf(codes.InvalidArgument, "unexpected request field %q", key)
		}
	}
	return values, nil
}

func stringField(values map[string]*structpb.Value, key string, required bool) (string, error) {
	value := values[key]
	if value == nil {
		if required {
			return "", status.Errorf(codes.InvalidArgument, "%s is required", key)
		}
		return "", nil
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", status.Errorf(codes.InvalidArgument, "%s must be a string", key)
	}
	result := value.GetStringValue()
	if required && result == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", key)
	}
	return result, nil
}

func response(values map[string]any) (*structpb.Struct, error) {
	result, err := structpb.NewStruct(values)
	if err != nil {
		return nil, fmt.Errorf("encode Controller response: %w", err)
	}
	return result, nil
}

func (s *Service) runtime() (XrayRuntime, error) {
	if s == nil || s.xray == nil {
		return nil, status.Error(codes.Unavailable, "Xray adapter is unavailable")
	}
	return s.xray, nil
}
