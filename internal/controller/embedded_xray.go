package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/runtimeauth"
	"xray-easy/internal/xrayapi"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// embeddedControlIdentity is an internal package constant.
	embeddedControlIdentity = "control-plane"
	// embeddedHealthIdentity is an internal package constant.
	embeddedHealthIdentity = "healthcheck"
	// maxRuntimeConfigSnapshot is an internal package constant.
	maxRuntimeConfigSnapshot = 16 << 20
)

// EmbeddedXrayClient adapts the embedded runtime's gRPC API to the Controller
// protocol interfaces.
type EmbeddedXrayClient struct {
	// TokenFile contains the TokenFile value for this object.
	TokenFile string
	// ConfigDir contains the ConfigDir value for this object.
	ConfigDir string

	conn      grpc.ClientConnInterface
	closeConn func() error
	rpc       xrayruntimev1.RuntimeClient
	logger    *slog.Logger
}

// DialEmbeddedXray creates an authenticated gRPC client for the embedded
// Xray runtime. ConfigDir is a read-only mount used only to load snapshots
// named by the current Controller contract.
func DialEmbeddedXray(address, tokenFile, configDir string) (*EmbeddedXrayClient, error) {
	address = strings.TrimSpace(address)
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("embedded Xray gRPC address must be host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("embedded Xray gRPC port must be between 1 and 65535")
	}
	if strings.TrimSpace(tokenFile) == "" {
		return nil, errors.New("embedded Xray token file path is required")
	}
	if strings.TrimSpace(configDir) == "" {
		return nil, errors.New("embedded Xray config directory is required")
	}
	connection, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("create embedded Xray gRPC connection: %w", err)
	}
	return newEmbeddedXrayClient(connection, connection.Close, tokenFile, configDir), nil
}

// NewEmbeddedXrayClientWithConn wraps a test-owned connection.
func NewEmbeddedXrayClientWithConn(connection grpc.ClientConnInterface, tokenFile, configDir string) *EmbeddedXrayClient {
	return newEmbeddedXrayClient(connection, nil, tokenFile, configDir)
}

// newEmbeddedXrayClient performs the operation represented by its name.
func newEmbeddedXrayClient(connection grpc.ClientConnInterface, closeConn func() error, tokenFile, configDir string) *EmbeddedXrayClient {
	return &EmbeddedXrayClient{
		TokenFile: tokenFile, ConfigDir: configDir, conn: connection, closeConn: closeConn,
		rpc: xrayruntimev1.NewRuntimeClient(connection), logger: slog.Default(),
	}
}

// Close releases the runtime gRPC connection when this client owns it.
func (c *EmbeddedXrayClient) Close() error {
	if c == nil || c.closeConn == nil {
		return nil
	}
	return c.closeConn()
}

// Health checks runtime readiness using the restricted healthcheck identity.
func (c *EmbeddedXrayClient) Health(ctx context.Context) error {
	response, err := c.call(ctx, embeddedHealthIdentity, xrayruntimev1.Runtime_Health_FullMethodName, &xrayruntimev1.HealthRequest{ProbeId: "controller-healthcheck"}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.Health(ctx, request.(*xrayruntimev1.HealthRequest))
	})
	if err != nil {
		return err
	}
	if !response.(*xrayruntimev1.HealthResponse).GetReady() {
		return errors.New("embedded Xray runtime is not ready")
	}
	return nil
}

// Status normalizes embedded runtime state to the status shape used by the UI.
func (c *EmbeddedXrayClient) Status(ctx context.Context) (domain.XrayRuntimeStatus, error) {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_GetStatus_FullMethodName, &xrayruntimev1.EmptyRequest{}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.GetStatus(ctx, request.(*xrayruntimev1.EmptyRequest))
	})
	if err != nil {
		return domain.XrayRuntimeStatus{}, err
	}
	value := response.(*xrayruntimev1.RuntimeStatus)
	state, ok := embeddedRuntimeState(value.GetState())
	if !ok || strings.TrimSpace(value.GetXrayCoreVersion()) == "" {
		return domain.XrayRuntimeStatus{}, errors.New("decode embedded Xray status: required fields are invalid")
	}
	capabilityResponse, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_GetCapabilities_FullMethodName, &xrayruntimev1.EmptyRequest{}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.GetCapabilities(ctx, request.(*xrayruntimev1.EmptyRequest))
	})
	if err != nil {
		return domain.XrayRuntimeStatus{}, err
	}
	inboundTags := make([]string, 0, len(capabilityResponse.(*xrayruntimev1.CapabilitiesResponse).GetProtocols()))
	seenTags := make(map[string]struct{}, cap(inboundTags))
	statsAvailable := false
	for index, capability := range capabilityResponse.(*xrayruntimev1.CapabilitiesResponse).GetProtocols() {
		if capability == nil || !capability.GetConfigured() || strings.TrimSpace(capability.GetInboundTag()) == "" {
			return domain.XrayRuntimeStatus{}, fmt.Errorf("decode embedded Xray capabilities: protocol %d is invalid", index)
		}
		tag := strings.TrimSpace(capability.GetInboundTag())
		if _, exists := seenTags[tag]; exists {
			return domain.XrayRuntimeStatus{}, fmt.Errorf("decode embedded Xray capabilities: inbound tag %q is duplicated", tag)
		}
		seenTags[tag] = struct{}{}
		inboundTags = append(inboundTags, tag)
		statsAvailable = statsAvailable || capability.GetTrafficCounters() || capability.GetOnlineStatus() || capability.GetSourceIp()
	}
	sort.Strings(inboundTags)
	startedAt, err := embeddedTimestamp("started_at", value.GetStartedAt())
	if err != nil {
		return domain.XrayRuntimeStatus{}, err
	}
	return domain.XrayRuntimeStatus{
		Protocol: "embedded-core", XrayVersion: value.GetXrayCoreVersion(), State: state,
		LastError: value.GetLastError(), StartedAt: startedAt,
		ActiveRevision: value.GetActiveRevision(), InboundTags: inboundTags, StatsAvailable: statsAvailable,
	}, nil
}

// Logs returns bounded, redacted logs emitted by the embedded runtime.
func (c *EmbeddedXrayClient) Logs(ctx context.Context) ([]string, error) {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_GetRecentLogs_FullMethodName, &xrayruntimev1.EmptyRequest{}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.GetRecentLogs(ctx, request.(*xrayruntimev1.EmptyRequest))
	})
	if err != nil {
		return nil, err
	}
	entries := response.(*xrayruntimev1.LogsResponse).GetEntries()
	lines := make([]string, 0, len(entries))
	for index, entry := range entries {
		if entry == nil || strings.TrimSpace(entry.GetMessage()) == "" {
			return nil, fmt.Errorf("decode embedded Xray logs: entry %d is invalid", index)
		}
		at, err := embeddedTimestamp("logs.timestamp", entry.GetTimestamp())
		if err != nil {
			return nil, err
		}
		lines = append(lines, fmt.Sprintf("%s [%s] %s: %s", at.Format(time.RFC3339), strings.ToUpper(entry.GetLevel()), entry.GetComponent(), entry.GetMessage()))
	}
	return lines, nil
}

// SetLogLevel changes the runtime filter without replacing the Xray instance.
func (c *EmbeddedXrayClient) SetLogLevel(ctx context.Context, level string) error {
	request := &xrayruntimev1.SetLogLevelRequest{Level: level, OperationId: interaction.OperationID(ctx)}
	_, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_SetLogLevel_FullMethodName, request, func(outgoing context.Context, message proto.Message) (proto.Message, error) {
		return c.rpc.SetLogLevel(outgoing, message.(*xrayruntimev1.SetLogLevelRequest))
	})
	return err
}

// Validate loads a path from the read-only config mount and validates its
// bytes through the runtime API.
func (c *EmbeddedXrayClient) Validate(ctx context.Context, path, operationID string) error {
	configuration, err := c.readSnapshot(path)
	if err != nil {
		return err
	}
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: configuration, OperationId: operationID, Revision: revision}
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ValidateConfiguration_FullMethodName, request, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ValidateConfiguration(ctx, request.(*xrayruntimev1.ConfigurationRequest))
	})
	if err != nil {
		return err
	}
	value := response.(*xrayruntimev1.ConfigurationResponse)
	if !value.GetValid() || value.GetOperationId() != operationID || value.GetRevision() != revision || value.GetConfigurationDigest() != snapshotDigest(configuration) {
		return errors.New("embedded Xray configuration validation returned an unexpected result")
	}
	return nil
}

// Apply activates a snapshot whose revision was assigned by the backend.
func (c *EmbeddedXrayClient) Apply(ctx context.Context, path, operationID string) error {
	configuration, err := c.readSnapshot(path)
	if err != nil {
		return err
	}
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	request := &xrayruntimev1.ConfigurationRequest{ConfigurationJson: configuration, OperationId: operationID, Revision: revision}
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ApplyConfiguration_FullMethodName, request, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ApplyConfiguration(ctx, request.(*xrayruntimev1.ConfigurationRequest))
	})
	if err != nil {
		return err
	}
	return verifyEmbeddedOperation(response.(*xrayruntimev1.OperationResponse), operationID, revision)
}

// ReplaceInbound sends candidate and prior snapshots without exposing local
// filesystem paths to the embedded runtime service.
func (c *EmbeddedXrayClient) ReplaceInbound(ctx context.Context, candidatePath, previousPath, tag, operationID string) error {
	candidate, err := c.readSnapshot(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate Xray configuration: %w", err)
	}
	previous, err := c.readSnapshot(previousPath)
	if err != nil {
		return fmt.Errorf("read previous Xray configuration: %w", err)
	}
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	request := &xrayruntimev1.ReplaceInboundRequest{
		CandidateConfigurationJson: candidate, PreviousConfigurationJson: previous,
		InboundTag: tag, OperationId: operationID, Revision: revision,
	}
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ReplaceInbound_FullMethodName, request, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ReplaceInbound(ctx, request.(*xrayruntimev1.ReplaceInboundRequest))
	})
	if err != nil {
		return err
	}
	return verifyEmbeddedOperation(response.(*xrayruntimev1.OperationResponse), operationID, revision)
}

// ProbeTarget checks REALITY target DNS and TLS reachability in the Xray
// container's egress network.
func (c *EmbeddedXrayClient) ProbeTarget(ctx context.Context, target, serverName string) error {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ProbeRealityTarget_FullMethodName, &xrayruntimev1.ProbeRealityTargetRequest{Target: target, ServerName: serverName}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ProbeRealityTarget(ctx, request.(*xrayruntimev1.ProbeRealityTargetRequest))
	})
	if err != nil {
		return err
	}
	if !response.(*xrayruntimev1.ProbeResponse).GetOk() {
		return errors.New("embedded Xray target probe returned an unsuccessful response")
	}
	return nil
}

// ProbeIPv6 checks outbound IPv6 TCP reachability from the embedded runtime.
func (c *EmbeddedXrayClient) ProbeIPv6(ctx context.Context) error {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ProbeIPv6Egress_FullMethodName, &xrayruntimev1.EmptyRequest{}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ProbeIPv6Egress(ctx, request.(*xrayruntimev1.EmptyRequest))
	})
	if err != nil {
		return err
	}
	if !response.(*xrayruntimev1.ProbeResponse).GetOk() {
		return errors.New("embedded Xray IPv6 probe returned an unsuccessful response")
	}
	return nil
}

// AddUser implements VLESS live user management.
func (c *EmbeddedXrayClient) AddUser(ctx context.Context, email, credential, flow string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_VLESS, email, credential, flow, true)
}

// RemoveUser implements VLESS live user revocation.
func (c *EmbeddedXrayClient) RemoveUser(ctx context.Context, email string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_VLESS, email, "", "", false)
}

// AddHysteriaUser implements Hysteria 2 live user management.
func (c *EmbeddedXrayClient) AddHysteriaUser(ctx context.Context, email, credential string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, email, credential, "", true)
}

// RemoveHysteriaUser implements Hysteria 2 live user revocation.
func (c *EmbeddedXrayClient) RemoveHysteriaUser(ctx context.Context, email string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2, email, "", "", false)
}

// AddVMessUser implements VMess live user management.
func (c *EmbeddedXrayClient) AddVMessUser(ctx context.Context, email, credential string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_VMESS, email, credential, "", true)
}

// RemoveVMessUser implements VMess live user revocation.
func (c *EmbeddedXrayClient) RemoveVMessUser(ctx context.Context, email string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_VMESS, email, "", "", false)
}

// AddShadowsocksUser installs a Shadowsocks 2022 per-device PSK and method
// into the embedded runtime.
func (c *EmbeddedXrayClient) AddShadowsocksUser(ctx context.Context, email, password, method string) error {
	return c.mutateUserWithMethod(ctx, xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS, email, password, "", method, true)
}

// RemoveShadowsocksUser revokes a Shadowsocks user from the inbound.
func (c *EmbeddedXrayClient) RemoveShadowsocksUser(ctx context.Context, email string) error {
	return c.mutateUserWithMethod(ctx, xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS, email, "", "", "", false)
}

// AddTrojanUser installs a Trojan password into the embedded runtime.
func (c *EmbeddedXrayClient) AddTrojanUser(ctx context.Context, email, password string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_TROJAN, email, password, "", true)
}

// RemoveTrojanUser revokes a Trojan password from the embedded runtime.
func (c *EmbeddedXrayClient) RemoveTrojanUser(ctx context.Context, email string) error {
	return c.mutateUser(ctx, xrayruntimev1.Protocol_PROTOCOL_TROJAN, email, "", "", false)
}

// mutateUser performs the operation represented by its name.
func (c *EmbeddedXrayClient) mutateUser(ctx context.Context, protocol xrayruntimev1.Protocol, email, credential, flow string, add bool) error {
	return c.mutateUserWithMethod(ctx, protocol, email, credential, flow, "", add)
}

// mutateUserWithMethod performs the operation represented by its name.
func (c *EmbeddedXrayClient) mutateUserWithMethod(ctx context.Context, protocol xrayruntimev1.Protocol, email, credential, flow, method string, add bool) error {
	ctx, _, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return fmt.Errorf("create embedded Xray operation ID: %w", err)
	}
	operationID, revision := interaction.OperationID(ctx), interaction.StateRevision(ctx)
	if add {
		request := &xrayruntimev1.AddUserRequest{Protocol: protocol, Email: email, Credential: credential, Flow: flow, ShadowsocksMethod: method, OperationId: operationID, Revision: revision}
		response, callErr := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_AddUser_FullMethodName, request, func(ctx context.Context, request proto.Message) (proto.Message, error) {
			return c.rpc.AddUser(ctx, request.(*xrayruntimev1.AddUserRequest))
		})
		if callErr != nil {
			return callErr
		}
		return verifyEmbeddedOperation(response.(*xrayruntimev1.OperationResponse), operationID, revision)
	}
	request := &xrayruntimev1.RemoveUserRequest{Protocol: protocol, Email: email, OperationId: operationID, Revision: revision}
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_RemoveUser_FullMethodName, request, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.RemoveUser(ctx, request.(*xrayruntimev1.RemoveUserRequest))
	})
	if err != nil {
		return err
	}
	return verifyEmbeddedOperation(response.(*xrayruntimev1.OperationResponse), operationID, revision)
}

// Users returns VLESS user identities in the active inbound.
func (c *EmbeddedXrayClient) Users(ctx context.Context) ([]string, error) {
	return c.listUsers(ctx, xrayruntimev1.Protocol_PROTOCOL_VLESS)
}

// UsersInInbound maps the legacy supported inbound tags to runtime protocols.
func (c *EmbeddedXrayClient) UsersInInbound(ctx context.Context, inbound string) ([]string, error) {
	protocol, ok := map[string]xrayruntimev1.Protocol{
		"vless-reality": xrayruntimev1.Protocol_PROTOCOL_VLESS,
		"vmess-tls":     xrayruntimev1.Protocol_PROTOCOL_VMESS,
		"hysteria2":     xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2,
		"shadowsocks":   xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS,
		"trojan-tls":    xrayruntimev1.Protocol_PROTOCOL_TROJAN,
	}[inbound]
	if !ok {
		return nil, fmt.Errorf("unsupported Xray inbound %q", inbound)
	}
	return c.listUsers(ctx, protocol)
}

// listUsers performs the operation represented by its name.
func (c *EmbeddedXrayClient) listUsers(ctx context.Context, protocol xrayruntimev1.Protocol) ([]string, error) {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_ListUsers_FullMethodName, &xrayruntimev1.ListUsersRequest{Protocol: protocol}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.ListUsers(ctx, request.(*xrayruntimev1.ListUsersRequest))
	})
	if err != nil {
		return nil, err
	}
	return append([]string(nil), response.(*xrayruntimev1.ListUsersResponse).GetEmails()...), nil
}

// Poll returns normalized cumulative counters and source-IP observations.
func (c *EmbeddedXrayClient) Poll(ctx context.Context) ([]xrayapi.UserStats, error) {
	response, err := c.call(ctx, embeddedControlIdentity, xrayruntimev1.Runtime_GetTelemetry_FullMethodName, &xrayruntimev1.EmptyRequest{}, func(ctx context.Context, request proto.Message) (proto.Message, error) {
		return c.rpc.GetTelemetry(ctx, request.(*xrayruntimev1.EmptyRequest))
	})
	if err != nil {
		return nil, err
	}
	users := response.(*xrayruntimev1.TelemetryResponse).GetUsers()
	values := make([]xrayapi.UserStats, 0, len(users))
	for index, user := range users {
		if user == nil || user.GetEmail() == "" || user.GetUploadBytes() < 0 || user.GetDownloadBytes() < 0 {
			return nil, fmt.Errorf("decode embedded Xray telemetry: user %d is invalid", index)
		}
		lastSeen, err := embeddedTimestamp("telemetry.last_seen", user.GetLastSeen())
		if err != nil {
			return nil, err
		}
		value := xrayapi.UserStats{Email: user.GetEmail(), Protocol: xrayProtocolName(user.GetProtocol()), UploadBytes: user.GetUploadBytes(), DownloadBytes: user.GetDownloadBytes(), LastSeen: lastSeen}
		for ipIndex, observation := range user.GetSourceIps() {
			if observation == nil {
				return nil, fmt.Errorf("decode embedded Xray telemetry: source IP %d for user %d is invalid", ipIndex, index)
			}
			address, err := netip.ParseAddr(observation.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("decode embedded Xray telemetry: source IP %d for user %d is invalid", ipIndex, index)
			}
			ipLastSeen, err := embeddedTimestamp("telemetry.source_ip.last_seen", observation.GetLastSeen())
			if err != nil {
				return nil, err
			}
			value.SourceIPs = append(value.SourceIPs, xrayapi.IPObservation{Address: address.WithZone("").Unmap().String(), LastSeen: ipLastSeen})
		}
		values = append(values, value)
	}
	return values, nil
}

// WatchTelemetry opens the authenticated long-lived telemetry stream from the
// embedded Xray runtime. The caller owns cancellation and Recv lifecycle.
func (c *EmbeddedXrayClient) WatchTelemetry(ctx context.Context, interval time.Duration) (xrayruntimev1.Runtime_WatchTelemetryClient, error) {
	if c == nil || c.conn == nil || c.rpc == nil {
		return nil, errors.New("embedded Xray gRPC connection is not initialized")
	}
	if interval < 500*time.Millisecond {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	request := &xrayruntimev1.WatchTelemetryRequest{SampleIntervalMs: uint32(interval.Milliseconds())}
	outgoing, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create embedded Xray stream request ID: %w", err)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, err
	}
	method := xrayruntimev1.Runtime_WatchTelemetry_FullMethodName
	outgoing, err = runtimeauth.SignContext(outgoing, token, embeddedControlIdentity, method, request)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	stream, err := c.rpc.WatchTelemetry(outgoing, request)
	interaction.LogRPC(c.logger, "xray-controller-xray-runtime-client", method, requestID, "xray", started, err, interaction.TraceFromContext(outgoing))
	if err != nil {
		return nil, fmt.Errorf("open embedded Xray telemetry stream: %w", err)
	}
	slog.Default().Info("grpc stream started", "service", "xray-controller-xray-runtime-client", "method", method, "request_id", requestID, "protocol", "xray")
	return &loggedRuntimeTelemetryStream{Runtime_WatchTelemetryClient: stream, logger: c.logger, requestID: requestID, started: started}, nil
}

// loggedRuntimeTelemetryStream is an internal type used by the package.
type loggedRuntimeTelemetryStream struct {
	xrayruntimev1.Runtime_WatchTelemetryClient
	logger    *slog.Logger
	requestID string
	started   time.Time
	logged    bool
}

// Recv receives the next value from the stream.
func (s *loggedRuntimeTelemetryStream) Recv() (*xrayruntimev1.TelemetryResponse, error) {
	response, err := s.Runtime_WatchTelemetryClient.Recv()
	if err != nil && !s.logged {
		s.logged = true
		logErr := err
		if errors.Is(logErr, io.EOF) {
			logErr = nil
		}
		interaction.LogRPC(s.logger, "xray-controller-xray-runtime-client", xrayruntimev1.Runtime_WatchTelemetry_FullMethodName, s.requestID, "xray", s.started, logErr, interaction.Trace{})
	}
	return response, err
}

// call performs the operation represented by its name.
func (c *EmbeddedXrayClient) call(ctx context.Context, identity, method string, request proto.Message, invoke func(context.Context, proto.Message) (proto.Message, error)) (proto.Message, error) {
	if c == nil || c.conn == nil || c.rpc == nil {
		return nil, errors.New("embedded Xray gRPC connection is not initialized")
	}
	ctx, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create embedded Xray request ID: %w", err)
	}
	token, err := c.readToken()
	if err != nil {
		return nil, err
	}
	ctx, err = runtimeauth.SignContext(ctx, token, identity, method, request)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	response, err := invoke(ctx, request)
	interaction.LogRPC(c.logger, "xray-controller-xray-runtime-client", method, requestID, "xray", started, err, interaction.TraceFromContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("embedded Xray %s: %w", method[strings.LastIndex(method, "/")+1:], err)
	}
	if response == nil {
		return nil, errors.New("embedded Xray runtime returned an empty protobuf response")
	}
	return response, nil
}

// readToken reads the requested value.
func (c *EmbeddedXrayClient) readToken() ([]byte, error) {
	if c == nil || strings.TrimSpace(c.TokenFile) == "" {
		return nil, errors.New("embedded Xray token file path is empty")
	}
	token, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("read embedded Xray token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) < 32 {
		return nil, errors.New("embedded Xray token must contain at least 32 bytes")
	}
	return token, nil
}

// readSnapshot reads the requested value.
func (c *EmbeddedXrayClient) readSnapshot(path string) ([]byte, error) {
	if c == nil || strings.TrimSpace(c.ConfigDir) == "" || strings.TrimSpace(path) == "" {
		return nil, errors.New("embedded Xray config directory and snapshot path are required")
	}
	root, err := filepath.EvalSymlinks(c.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("resolve embedded Xray config directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve embedded Xray configuration snapshot: %w", err)
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, errors.New("Xray configuration snapshot is outside the mounted config directory")
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat embedded Xray configuration snapshot: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxRuntimeConfigSnapshot {
		return nil, errors.New("Xray configuration snapshot is empty or exceeds the size limit")
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("read embedded Xray configuration snapshot: %w", err)
	}
	return data, nil
}

// snapshotDigest performs the operation represented by its name.
func snapshotDigest(snapshot []byte) string {
	digest := sha256.Sum256(snapshot)
	return hex.EncodeToString(digest[:])
}

// verifyEmbeddedOperation performs the operation represented by its name.
func verifyEmbeddedOperation(response *xrayruntimev1.OperationResponse, operationID string, revision int64) error {
	if response == nil || response.GetOperationId() != operationID || response.GetRevision() != revision {
		return errors.New("embedded Xray operation returned a different identity or revision")
	}
	return nil
}

// embeddedRuntimeState performs the operation represented by its name.
func embeddedRuntimeState(state xrayruntimev1.RuntimeState) (string, bool) {
	switch state {
	case xrayruntimev1.RuntimeState_RUNTIME_STATE_STARTING:
		return "starting", true
	case xrayruntimev1.RuntimeState_RUNTIME_STATE_NO_CONFIGURATION:
		return "no_configuration", true
	case xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING:
		return "running", true
	case xrayruntimev1.RuntimeState_RUNTIME_STATE_STOPPING:
		return "stopping", true
	case xrayruntimev1.RuntimeState_RUNTIME_STATE_FAILED:
		return "failed", true
	default:
		return "", false
	}
}

// embeddedTimestamp performs the operation represented by its name.
func embeddedTimestamp(field string, value *timestamppb.Timestamp) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("decode embedded Xray %s: %w", field, err)
	}
	return value.AsTime().UTC(), nil
}

var (
	_ XrayRuntime        = (*EmbeddedXrayClient)(nil)
	_ XrayHandlerRuntime = (*EmbeddedXrayClient)(nil)
	_ XrayStatsRuntime   = (*EmbeddedXrayClient)(nil)
)
