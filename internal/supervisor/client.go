package supervisor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"xray-easy/internal/interaction"
	supervisorv1 "xray-easy/internal/supervisor/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	operationControlPlane = "control-plane"
	operationHealthcheck  = "healthcheck"
)

type Client struct {
	TokenFile string

	conn      grpc.ClientConnInterface
	closeConn func() error
	rpc       supervisorv1.SupervisorClient
	operation string
}

type Status struct {
	Protocol     string    `json:"protocol"`
	XrayVersion  string    `json:"xray_version"`
	State        string    `json:"state"`
	PID          int       `json:"pid"`
	ConfigPath   string    `json:"config_path"`
	LastError    string    `json:"last_error"`
	LastExit     string    `json:"last_exit"`
	RestartCount int       `json:"restart_count"`
	StartedAt    time.Time `json:"started_at"`
}

// Dial creates a long-lived private gRPC connection authenticated with the
// mounted supervisor token. Call Close when the owning process exits.
func Dial(address, tokenFile string) (*Client, error) {
	return DialWithOperation(address, tokenFile, operationControlPlane)
}

// DialWithOperation is used by the container healthcheck, whose credentials
// may call Health but are not authorized for control-plane operations.
func DialWithOperation(address, tokenFile, operation string) (*Client, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("supervisor gRPC address is required")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, errors.New("supervisor gRPC address must be host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("supervisor gRPC port must be between 1 and 65535")
	}
	if operation != operationControlPlane && operation != operationHealthcheck {
		return nil, errors.New("invalid supervisor operation identity")
	}
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("create supervisor gRPC connection: %w", err)
	}
	return newClient(conn, conn.Close, tokenFile, operation), nil
}

// NewClientWithConn wraps an existing gRPC connection, primarily for bufconn
// integration tests. The caller retains ownership of the connection.
func NewClientWithConn(conn grpc.ClientConnInterface, tokenFile string) *Client {
	return newClient(conn, nil, tokenFile, operationControlPlane)
}

func newClient(conn grpc.ClientConnInterface, closeConn func() error, tokenFile, operation string) *Client {
	return &Client{TokenFile: tokenFile, conn: conn, closeConn: closeConn, rpc: supervisorv1.NewSupervisorClient(conn), operation: operation}
}

// Close releases the underlying HTTP/2 connection when this client owns it.
func (c *Client) Close() error {
	if c == nil || c.closeConn == nil {
		return nil
	}
	return c.closeConn()
}

// Validate asks Supervisor to validate a candidate Xray configuration.
func (c *Client) Validate(ctx context.Context, path, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	request := &supervisorv1.ValidateConfigRequest{Path: path, OperationId: operationID, StateRevision: interaction.StateRevision(ctx)}
	_, err := c.call(ctx, supervisorv1.Supervisor_ValidateConfig_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ValidateConfig(ctx, request) })
	return err
}

// Apply activates a validated candidate Xray configuration.
func (c *Client) Apply(ctx context.Context, path, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	request := &supervisorv1.ApplyConfigRequest{Path: path, OperationId: operationID, StateRevision: interaction.StateRevision(ctx)}
	_, err := c.call(ctx, supervisorv1.Supervisor_ApplyConfig_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ApplyConfig(ctx, request) })
	return err
}

// ReplaceInbound updates one Xray inbound through HandlerService without restarting the Xray process.
func (c *Client) ReplaceInbound(ctx context.Context, candidatePath, previousPath, tag, operationID string) error {
	ctx = interaction.WithOperationID(ctx, operationID)
	request := &supervisorv1.ReplaceInboundRequest{
		CandidatePath: candidatePath, PreviousPath: previousPath, Tag: tag,
		OperationId: operationID, StateRevision: interaction.StateRevision(ctx),
	}
	_, err := c.call(ctx, supervisorv1.Supervisor_ReplaceInbound_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ReplaceInbound(ctx, request) })
	return err
}

// ProbeTarget verifies DNS resolution and TLS reachability for a REALITY target.
func (c *Client) ProbeTarget(ctx context.Context, target, sni string) error {
	request := &supervisorv1.ProbeTargetRequest{Target: target, Sni: sni}
	response, err := c.call(ctx, supervisorv1.Supervisor_ProbeTarget_FullMethodName, request,
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ProbeTarget(ctx, request) })
	if err != nil {
		return err
	}
	if !response.(*supervisorv1.ProbeTargetResponse).GetOk() {
		return errors.New("supervisor target probe returned an unsuccessful response")
	}
	return nil
}

// ProbeIPv6 checks outbound IPv6 connectivity from the Xray container.
func (c *Client) ProbeIPv6(ctx context.Context) error {
	response, err := c.call(ctx, supervisorv1.Supervisor_ProbeIPv6_FullMethodName, new(emptypb.Empty),
		func(ctx context.Context) (proto.Message, error) { return c.rpc.ProbeIPv6(ctx, new(emptypb.Empty)) })
	if err != nil {
		return err
	}
	if !response.(*supervisorv1.ProbeIPv6Response).GetOk() {
		return errors.New("supervisor IPv6 probe returned an unsuccessful response")
	}
	return nil
}

// Health checks that Supervisor is running and accepts healthcheck credentials.
func (c *Client) Health(ctx context.Context) error {
	response, err := c.call(ctx, supervisorv1.Supervisor_Health_FullMethodName, new(emptypb.Empty),
		func(ctx context.Context) (proto.Message, error) { return c.rpc.Health(ctx, new(emptypb.Empty)) })
	if err != nil {
		return err
	}
	if !response.(*supervisorv1.HealthResponse).GetOk() {
		return errors.New("supervisor health response is not ready")
	}
	return nil
}

// Status returns the current child process state reported by Supervisor.
func (c *Client) Status(ctx context.Context) (Status, error) {
	result, err := c.call(ctx, supervisorv1.Supervisor_GetStatus_FullMethodName, new(emptypb.Empty),
		func(ctx context.Context) (proto.Message, error) { return c.rpc.GetStatus(ctx, new(emptypb.Empty)) })
	if err != nil {
		return Status{}, err
	}
	response := result.(*supervisorv1.SupervisorStatus)
	if response.Protocol == "" || response.XrayVersion == "" || response.State == "" || response.Pid < 0 || response.RestartCount < 0 {
		return Status{}, errors.New("decode supervisor status: required or numeric field is invalid")
	}
	startedAt, err := protobufTimeToTime("started_at", response.StartedAt)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Protocol: response.Protocol, XrayVersion: response.XrayVersion, State: response.State,
		PID: int(response.Pid), ConfigPath: response.ConfigPath, LastError: response.LastError,
		LastExit: response.LastExit, RestartCount: int(response.RestartCount), StartedAt: startedAt,
	}, nil
}

// Logs returns the bounded, redacted log buffer from the Supervisor process.
func (c *Client) Logs(ctx context.Context) ([]string, error) {
	result, err := c.call(ctx, supervisorv1.Supervisor_GetLogs_FullMethodName, new(emptypb.Empty),
		func(ctx context.Context) (proto.Message, error) { return c.rpc.GetLogs(ctx, new(emptypb.Empty)) })
	if err != nil {
		return nil, err
	}
	return append([]string(nil), result.(*supervisorv1.LogsResponse).Lines...), nil
}

func (c *Client) call(ctx context.Context, method string, request proto.Message, invoke func(context.Context) (proto.Message, error)) (proto.Message, error) {
	if c == nil || c.conn == nil || c.rpc == nil {
		return nil, errors.New("supervisor gRPC connection is not initialized")
	}
	operation := c.operation
	if operation == "" {
		operation = operationControlPlane
	}
	if operation == operationHealthcheck && method != supervisorv1.Supervisor_Health_FullMethodName {
		return nil, errors.New("healthcheck identity cannot invoke supervisor control methods")
	}
	metadataContext, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create supervisor request ID: %w", err)
	}
	metadataContext, err = signRequest(metadataContext, c.TokenFile, operation, method, request)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	response, err := invoke(metadataContext)
	if err != nil {
		interaction.LogRPC(slog.Default(), "xray-supervisor-client", method, requestID, "xray", started, err, interaction.TraceFromContext(metadataContext))
		return nil, fmt.Errorf("supervisor %s: %w", method[strings.LastIndex(method, "/")+1:], err)
	}
	if response == nil {
		return nil, errors.New("supervisor returned an empty protobuf response")
	}
	interaction.LogRPC(slog.Default(), "xray-supervisor-client", method, requestID, "xray", started, nil, interaction.TraceFromContext(metadataContext))
	return response, nil
}

func signRequest(ctx context.Context, tokenFile, operation, method string, request proto.Message) (context.Context, error) {
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read supervisor token: %w", err)
	}
	token = []byte(strings.TrimSpace(string(token)))
	if len(token) == 0 {
		return nil, errors.New("supervisor token is empty")
	}
	requestBytes, err := DeterministicBytes(request)
	if err != nil {
		return nil, fmt.Errorf("marshal supervisor request: %w", err)
	}
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, fmt.Errorf("generate supervisor request nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)
	bodyHash := sha256.Sum256(requestBytes)
	message := strings.Join([]string{method, operation, nonce, hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, token)
	_, _ = mac.Write([]byte(message))
	return metadata.AppendToOutgoingContext(ctx,
		"x-xray-operation", operation,
		"x-xray-nonce", nonce,
		"x-xray-signature", hex.EncodeToString(mac.Sum(nil))), nil
}

func protobufTimeToTime(field string, value *timestamppb.Timestamp) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("decode supervisor %s: invalid timestamp: %w", field, err)
	}
	return value.AsTime().UTC(), nil
}
