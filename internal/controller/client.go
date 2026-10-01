package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type rpcInvoker interface {
	Invoke(context.Context, string, any, any, ...grpc.CallOption) error
	Close() error
}

// Client is the authenticated backend gateway to the private Controller.
type Client struct {
	connection rpcInvoker
	token      string
	logger     *slog.Logger
	close      func() error
}

// Dial creates a long-lived gRPC client from a mounted token file.
func Dial(address, tokenPath string) (*Client, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read Controller token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("Controller token is empty")
	}
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)))
	if err != nil {
		return nil, fmt.Errorf("create Controller gRPC client: %w", err)
	}
	return &Client{connection: connection, token: token, logger: slog.Default(), close: connection.Close}, nil
}

// NewClientWithConn creates a client around a test-owned connection.
func NewClientWithConn(connection rpcInvoker, token string) *Client {
	return &Client{connection: connection, token: token, logger: slog.Default()}
}

// Close closes the Controller gRPC connection when this client owns it.
func (c *Client) Close() error {
	if c == nil || c.close == nil {
		return nil
	}
	return c.close()
}

// Health verifies that Controller and its required Xray adapter respond.
func (c *Client) Health(ctx context.Context) error {
	_, err := c.call(ctx, "Health", &controllerv1.EmptyRequest{})
	return err
}

// Capabilities returns the protocol adapters configured in Controller.
func (c *Client) Capabilities(ctx context.Context) (*controllerv1.CapabilitiesResponse, error) {
	response, err := c.call(ctx, "GetCapabilities", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	return response.(*controllerv1.CapabilitiesResponse), nil
}

// Status returns the current embedded Xray runtime state.
func (c *Client) Status(ctx context.Context) (domain.XrayRuntimeStatus, error) {
	result, err := c.call(ctx, "GetStatus", &controllerv1.EmptyRequest{})
	if err != nil {
		return domain.XrayRuntimeStatus{}, err
	}
	value := result.(*controllerv1.StatusResponse)
	if value.Protocol == "" || value.XrayVersion == "" || value.State == "" || value.ActiveRevision < 0 {
		return domain.XrayRuntimeStatus{}, errors.New("decode Controller status: required fields are invalid")
	}
	startedAt, err := protobufTimeToTime("started_at", value.StartedAt)
	if err != nil {
		return domain.XrayRuntimeStatus{}, err
	}
	return domain.XrayRuntimeStatus{
		Protocol: value.Protocol, XrayVersion: value.XrayVersion, State: value.State,
		LastError: value.LastError, StartedAt: startedAt, ActiveRevision: value.ActiveRevision,
		InboundTags: append([]string(nil), value.InboundTags...), StatsAvailable: value.StatsAvailable,
	}, nil
}

// Logs returns the embedded runtime's redacted recent log lines.
func (c *Client) Logs(ctx context.Context) ([]string, error) {
	result, err := c.call(ctx, "GetLogs", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	return append([]string{}, result.(*controllerv1.LogsResponse).Lines...), nil
}

// Validate asks the Xray adapter to validate a candidate config.
func (c *Client) Validate(ctx context.Context, path, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	response, err := c.call(ctx, "ValidateConfig", &controllerv1.ValidateConfigRequest{Path: path, OperationId: operationID, StateRevision: revision})
	if err != nil {
		return err
	}
	return verifyOperationRevision(response, revision, "ValidateConfig")
}

// Apply activates a validated Xray config.
func (c *Client) Apply(ctx context.Context, path, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	response, err := c.call(ctx, "ApplyConfig", &controllerv1.ApplyConfigRequest{Path: path, OperationId: operationID, StateRevision: revision})
	if err != nil {
		return err
	}
	return verifyOperationRevision(response, revision, "ApplyConfig")
}

// ReplaceInbound updates one running Xray inbound without restarting Xray.
func (c *Client) ReplaceInbound(ctx context.Context, candidatePath, previousPath, tag, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	revision := interaction.StateRevision(ctx)
	response, err := c.call(ctx, "ReplaceInbound", &controllerv1.ReplaceInboundRequest{CandidatePath: candidatePath, PreviousPath: previousPath, Tag: tag, OperationId: operationID, StateRevision: revision})
	if err != nil {
		return err
	}
	return verifyOperationRevision(response, revision, "ReplaceInbound")
}

func verifyOperationRevision(response proto.Message, revision int64, method string) error {
	value, ok := response.(*controllerv1.OperationResponse)
	if !ok || value.StateRevision != revision {
		return fmt.Errorf("Controller %s returned a different config revision", method)
	}
	return nil
}

// ProbeTarget checks the configured REALITY target through the Xray adapter.
func (c *Client) ProbeTarget(ctx context.Context, target, sni string) error {
	_, err := c.call(ctx, "ProbeTarget", &controllerv1.ProbeTargetRequest{Target: target, Sni: sni})
	return err
}

// ProbeIPv6 checks outbound IPv6 connectivity from the Xray container.
func (c *Client) ProbeIPv6(ctx context.Context) error {
	_, err := c.call(ctx, "ProbeIPv6", &controllerv1.EmptyRequest{})
	return err
}

// AddUser installs a VLESS user in the running Xray inbound.
func (c *Client) AddUser(ctx context.Context, email, id, flow string) error {
	_, err := c.call(ctx, "AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "vless", Email: email, Id: id, Flow: flow})
	return err
}

// RemoveUser removes a VLESS user from the running Xray inbound.
func (c *Client) RemoveUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", &controllerv1.RemoveDeviceUserRequest{Protocol: "vless", Email: email})
	return err
}

// AddHysteriaUser installs a Hysteria 2 credential into Xray.
func (c *Client) AddHysteriaUser(ctx context.Context, email, password string) error {
	_, err := c.call(ctx, "AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "hysteria2", Email: email, Id: password})
	return err
}

// RemoveHysteriaUser revokes a Hysteria 2 credential from Xray.
func (c *Client) RemoveHysteriaUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", &controllerv1.RemoveDeviceUserRequest{Protocol: "hysteria2", Email: email})
	return err
}

// AddVMessUser installs a VMess UUID into Xray.
func (c *Client) AddVMessUser(ctx context.Context, email, id string) error {
	_, err := c.call(ctx, "AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "vmess", Email: email, Id: id})
	return err
}

// AddShadowsocksUser installs a classic Shadowsocks password with its AEAD method.
func (c *Client) AddShadowsocksUser(ctx context.Context, email, password, method string) error {
	_, err := c.call(ctx, "AddDeviceUser", &controllerv1.AddDeviceUserRequest{Protocol: "shadowsocks", Email: email, Id: password, Method: method})
	return err
}

// RemoveShadowsocksUser revokes a Shadowsocks user from Xray.
func (c *Client) RemoveShadowsocksUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", &controllerv1.RemoveDeviceUserRequest{Protocol: "shadowsocks", Email: email})
	return err
}

// RemoveVMessUser revokes a VMess user from Xray.
func (c *Client) RemoveVMessUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", &controllerv1.RemoveDeviceUserRequest{Protocol: "vmess", Email: email})
	return err
}

// Users returns loaded VLESS user emails.
func (c *Client) Users(ctx context.Context) ([]string, error) {
	return c.UsersInInbound(ctx, "vless-reality")
}

// UsersInInbound reads loaded Xray users for the supported inbound tag.
func (c *Client) UsersInInbound(ctx context.Context, inbound string) ([]string, error) {
	protocol := map[string]string{"vless-reality": "vless", "hysteria2": "hysteria2", "vmess-tls": "vmess"}[inbound]
	if protocol == "" {
		return nil, fmt.Errorf("unsupported Xray inbound %q", inbound)
	}
	result, err := c.call(ctx, "ListDeviceUsers", &controllerv1.ListDeviceUsersRequest{Protocol: protocol})
	if err != nil {
		return nil, err
	}
	return append([]string{}, result.(*controllerv1.ListDeviceUsersResponse).Users...), nil
}

// Poll reads normalized user counters and source IP observations from Xray.
func (c *Client) Poll(ctx context.Context) ([]xrayapi.UserStats, error) {
	result, err := c.call(ctx, "GetXrayTelemetry", &controllerv1.EmptyRequest{})
	if err != nil {
		return nil, err
	}
	users := result.(*controllerv1.XrayTelemetryResponse).Users
	values := make([]xrayapi.UserStats, 0, len(users))
	for index, user := range users {
		if user == nil || user.Email == "" || user.UploadBytes < 0 || user.DownloadBytes < 0 {
			return nil, fmt.Errorf("decode Controller telemetry: user %d has invalid fields", index)
		}
		lastSeen, err := protobufTimeToTime("last_seen", user.LastSeen)
		if err != nil {
			return nil, err
		}
		value := xrayapi.UserStats{Email: user.Email, UploadBytes: user.UploadBytes, DownloadBytes: user.DownloadBytes, LastSeen: lastSeen}
		for ipIndex, ip := range user.SourceIps {
			if ip == nil || ip.Address == "" {
				return nil, fmt.Errorf("decode Controller telemetry: source IP %d for user %d is invalid", ipIndex, index)
			}
			seen, err := protobufTimeToTime("source_ips.last_seen", ip.LastSeen)
			if err != nil {
				return nil, err
			}
			value.SourceIPs = append(value.SourceIPs, xrayapi.IPObservation{Address: ip.Address, LastSeen: seen})
		}
		values = append(values, value)
	}
	return values, nil
}

// WatchTelemetry opens the authenticated Controller stream used while at least
// one SSE client is subscribed to live profile statistics.
func (c *Client) WatchTelemetry(ctx context.Context, interval time.Duration) (controllerv1.Controller_WatchTelemetryClient, error) {
	connection, ok := c.connection.(grpc.ClientConnInterface)
	if !ok {
		return nil, errors.New("Controller connection does not support server streams")
	}
	if interval < 500*time.Millisecond {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	outgoing, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Controller stream request ID: %w", err)
	}
	outgoing = metadataAppendAuth(outgoing, c.token)
	method := controllerv1.Controller_WatchTelemetry_FullMethodName
	started := time.Now()
	stream, err := controllerv1.NewControllerClient(connection).WatchTelemetry(outgoing, &controllerv1.WatchTelemetryRequest{SampleIntervalMs: uint32(interval.Milliseconds())})
	if err != nil {
		interaction.LogRPC(c.logger, "xray-easy", method, requestID, "runtime", started, err, interaction.TraceFromContext(outgoing))
		return nil, fmt.Errorf("open Controller telemetry stream: %w", err)
	}
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("grpc stream started", "service", "xray-easy", "method", method, "request_id", requestID, "protocol", "runtime")
	return &loggedControllerTelemetryStream{Controller_WatchTelemetryClient: stream, logger: logger, requestID: requestID, started: started, trace: interaction.TraceFromContext(outgoing)}, nil
}

type loggedControllerTelemetryStream struct {
	controllerv1.Controller_WatchTelemetryClient
	logger    *slog.Logger
	requestID string
	started   time.Time
	trace     interaction.Trace
	logged    bool
}

func (s *loggedControllerTelemetryStream) Recv() (*controllerv1.TelemetryUpdate, error) {
	response, err := s.Controller_WatchTelemetryClient.Recv()
	if err != nil && !s.logged {
		s.logged = true
		logErr := err
		if errors.Is(logErr, io.EOF) {
			logErr = nil
		}
		interaction.LogRPC(s.logger, "xray-easy", controllerv1.Controller_WatchTelemetry_FullMethodName, s.requestID, "runtime", s.started, logErr, s.trace)
	}
	return response, err
}

func (c *Client) call(ctx context.Context, method string, request proto.Message) (proto.Message, error) {
	if c == nil || c.connection == nil {
		return nil, errors.New("Controller gRPC connection is not initialized")
	}
	if request == nil {
		request = &controllerv1.EmptyRequest{}
	}
	response, err := newRPCResponse(method)
	if err != nil {
		return nil, err
	}
	outgoing, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Controller request ID: %w", err)
	}
	outgoing = metadataAppendAuth(outgoing, c.token)
	fullMethod := "/" + RPCServiceName + "/" + method
	started := time.Now()
	err = c.connection.Invoke(outgoing, fullMethod, request, response)
	interaction.LogRPC(c.logger, "xray-easy", fullMethod, requestID, protocolForClientCall(method, request), started, err, interaction.TraceFromContext(outgoing))
	if err != nil {
		return nil, fmt.Errorf("Controller %s: %w", method, err)
	}
	return response, nil
}

func newRPCResponse(method string) (proto.Message, error) {
	switch method {
	case "Health":
		return &controllerv1.HealthResponse{}, nil
	case "GetCapabilities":
		return &controllerv1.CapabilitiesResponse{}, nil
	case "GetStatus":
		return &controllerv1.StatusResponse{}, nil
	case "GetLogs":
		return &controllerv1.LogsResponse{}, nil
	case "ValidateConfig", "ApplyConfig", "ReplaceInbound", "ProbeTarget", "AddDeviceUser", "RemoveDeviceUser", "RemoveAmneziaWGPeer", "RestoreAmneziaWGBackup":
		return &controllerv1.OperationResponse{}, nil
	case "ProbeIPv6":
		return &controllerv1.ProbeIPv6Response{}, nil
	case "ListDeviceUsers":
		return &controllerv1.ListDeviceUsersResponse{}, nil
	case "GetXrayTelemetry":
		return &controllerv1.XrayTelemetryResponse{}, nil
	case "GetAmneziaWGStatus":
		return &controllerv1.AmneziaWGStatusResponse{}, nil
	case "ListAmneziaWGPeers":
		return &controllerv1.ListAmneziaWGPeersResponse{}, nil
	case "CreateAmneziaWGPeer":
		return &controllerv1.AmneziaWGPeer{}, nil
	case "GetAmneziaWGPeerStats":
		return &controllerv1.AmneziaWGPeerStatsResponse{}, nil
	case "GetAmneziaWGClientConfig":
		return &controllerv1.AmneziaWGClientConfigResponse{}, nil
	case "ExportAmneziaWGBackup":
		return &controllerv1.AmneziaWGBackupResponse{}, nil
	default:
		return nil, fmt.Errorf("unknown Controller RPC method %q", method)
	}
}

func protocolForClientCall(method string, request proto.Message) string {
	if strings.Contains(method, "AmneziaWG") {
		return "amneziawg"
	}
	if method == "Health" || method == "GetCapabilities" {
		return "runtime"
	}
	switch value := request.(type) {
	case *controllerv1.AddDeviceUserRequest:
		return safeProtocolName(value.GetProtocol())
	case *controllerv1.RemoveDeviceUserRequest:
		return safeProtocolName(value.GetProtocol())
	case *controllerv1.ListDeviceUsersRequest:
		return safeProtocolName(value.GetProtocol())
	}
	return "xray"
}

func protobufTimeToTime(field string, value *timestamppb.Timestamp) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("decode Controller %s: %w", field, err)
	}
	return value.AsTime().UTC(), nil
}

func metadataAppendAuth(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}
