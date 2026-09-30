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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"xray-easy/internal/interaction"
)

const (
	operationControlPlane = "control-plane"
	operationHealthcheck  = "healthcheck"
)

type Client struct {
	TokenFile string

	conn      grpc.ClientConnInterface
	closeConn func() error
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
	return &Client{TokenFile: tokenFile, conn: conn, closeConn: conn.Close, operation: operation}, nil
}

// NewClientWithConn wraps an existing gRPC connection, primarily for bufconn
// integration tests. The caller retains ownership of the connection.
func NewClientWithConn(conn grpc.ClientConnInterface, tokenFile string) *Client {
	return &Client{TokenFile: tokenFile, conn: conn, operation: operationControlPlane}
}

func (c *Client) Close() error {
	if c == nil || c.closeConn == nil {
		return nil
	}
	return c.closeConn()
}

func (c *Client) Validate(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, "ValidateConfig", stringRequest(map[string]string{"path": path, "operation_id": operationID}))
	return err
}

func (c *Client) Apply(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, "ApplyConfig", stringRequest(map[string]string{"path": path, "operation_id": operationID}))
	return err
}

// ReplaceInbound updates one Xray inbound through HandlerService without restarting the Xray process.
func (c *Client) ReplaceInbound(ctx context.Context, candidatePath, previousPath, tag, operationID string) error {
	request := stringRequest(map[string]string{
		"candidate_path": candidatePath,
		"previous_path":  previousPath,
		"tag":            tag,
		"operation_id":   operationID,
	})
	_, err := c.call(ctx, "ReplaceInbound", request)
	return err
}

func (c *Client) ProbeTarget(ctx context.Context, target, sni string) error {
	_, err := c.call(ctx, "ProbeTarget", stringRequest(map[string]string{"target": target, "sni": sni}))
	return err
}

// ProbeIPv6 checks outbound IPv6 connectivity from the Xray container.
func (c *Client) ProbeIPv6(ctx context.Context) error {
	_, err := c.call(ctx, "ProbeIPv6", new(emptypb.Empty))
	return err
}

func (c *Client) Health(ctx context.Context) error {
	_, err := c.call(ctx, "Health", new(emptypb.Empty))
	return err
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	response, err := c.call(ctx, "GetStatus", new(emptypb.Empty))
	if err != nil {
		return Status{}, err
	}
	fields := response.GetFields()
	status := Status{}
	if status.Protocol, err = responseString(fields, "protocol", true); err != nil {
		return Status{}, err
	}
	if status.XrayVersion, err = responseString(fields, "xray_version", true); err != nil {
		return Status{}, err
	}
	if status.State, err = responseString(fields, "state", true); err != nil {
		return Status{}, err
	}
	if status.ConfigPath, err = responseString(fields, "config_path", false); err != nil {
		return Status{}, err
	}
	if status.LastError, err = responseString(fields, "last_error", false); err != nil {
		return Status{}, err
	}
	if status.LastExit, err = responseString(fields, "last_exit", false); err != nil {
		return Status{}, err
	}
	if status.PID, err = responseInt(fields, "pid"); err != nil {
		return Status{}, err
	}
	if status.RestartCount, err = responseInt(fields, "restart_count"); err != nil {
		return Status{}, err
	}
	startedAt, err := responseString(fields, "started_at", false)
	if err != nil {
		return Status{}, err
	}
	if startedAt != "" {
		status.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return Status{}, fmt.Errorf("decode supervisor started_at: %w", err)
		}
	}
	return status, nil
}

func (c *Client) Logs(ctx context.Context) ([]string, error) {
	response, err := c.call(ctx, "GetLogs", new(emptypb.Empty))
	if err != nil {
		return nil, err
	}
	value := response.GetFields()["lines"]
	if value == nil || value.GetListValue() == nil {
		return nil, errors.New("decode supervisor logs: lines must be a list")
	}
	lines := make([]string, 0, len(value.GetListValue().GetValues()))
	for index, line := range value.GetListValue().GetValues() {
		if line.GetStringValue() == "" && line.GetKind() == nil {
			return nil, fmt.Errorf("decode supervisor logs: line %d is missing", index)
		}
		if _, ok := line.GetKind().(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("decode supervisor logs: line %d must be a string", index)
		}
		lines = append(lines, line.GetStringValue())
	}
	return lines, nil
}

func (c *Client) call(ctx context.Context, method string, request proto.Message) (*structpb.Struct, error) {
	if c == nil || c.conn == nil {
		return nil, errors.New("supervisor gRPC connection is not initialized")
	}
	operation := c.operation
	if operation == "" {
		operation = operationControlPlane
	}
	if operation == operationHealthcheck && method != "Health" {
		return nil, errors.New("healthcheck identity cannot invoke supervisor control methods")
	}
	metadataContext, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create supervisor request ID: %w", err)
	}
	metadataContext, err = signRequest(metadataContext, c.TokenFile, operation, "/"+RPCServiceName+"/"+method, request)
	if err != nil {
		return nil, err
	}
	response := new(structpb.Struct)
	fullMethod := "/" + RPCServiceName + "/" + method
	started := time.Now()
	if err := c.conn.Invoke(metadataContext, fullMethod, request, response); err != nil {
		interaction.LogRPC(slog.Default(), "xray-supervisor-client", fullMethod, requestID, "xray", started, err)
		return nil, fmt.Errorf("supervisor %s: %w", method, err)
	}
	interaction.LogRPC(slog.Default(), "xray-supervisor-client", fullMethod, requestID, "xray", started, nil)
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
	values := map[string]string{
		"x-xray-operation": operation,
		"x-xray-nonce":     nonce,
		"x-xray-signature": hex.EncodeToString(mac.Sum(nil)),
	}
	return metadata.AppendToOutgoingContext(ctx,
		"x-xray-operation", values["x-xray-operation"],
		"x-xray-nonce", values["x-xray-nonce"],
		"x-xray-signature", values["x-xray-signature"],
	), nil
}

func stringRequest(fields map[string]string) *structpb.Struct {
	values := make(map[string]*structpb.Value, len(fields))
	for key, value := range fields {
		values[key] = structpb.NewStringValue(value)
	}
	return &structpb.Struct{Fields: values}
}

func responseString(fields map[string]*structpb.Value, name string, required bool) (string, error) {
	value := fields[name]
	if value == nil {
		if required {
			return "", fmt.Errorf("decode supervisor response: missing %s", name)
		}
		return "", nil
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", fmt.Errorf("decode supervisor response: %s must be a string", name)
	}
	return value.GetStringValue(), nil
}

func responseInt(fields map[string]*structpb.Value, name string) (int, error) {
	value := fields[name]
	if value == nil {
		return 0, fmt.Errorf("decode supervisor response: missing %s", name)
	}
	number, ok := value.GetKind().(*structpb.Value_NumberValue)
	if !ok || number.NumberValue != float64(int(number.NumberValue)) {
		return 0, fmt.Errorf("decode supervisor response: %s must be an integer", name)
	}
	return int(number.NumberValue), nil
}
