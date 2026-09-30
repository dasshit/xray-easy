package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"

	"xray-easy/internal/interaction"
	"xray-easy/internal/supervisor"
	"xray-easy/internal/xrayapi"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
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
	_, err := c.call(ctx, "Health", nil)
	return err
}

// Status returns the current Xray process state.
func (c *Client) Status(ctx context.Context) (supervisor.Status, error) {
	result, err := c.call(ctx, "GetStatus", nil)
	if err != nil {
		return supervisor.Status{}, err
	}
	fields := result.GetFields()
	var value supervisor.Status
	if value.Protocol, err = responseString(fields, "protocol", true); err != nil {
		return value, err
	}
	if value.XrayVersion, err = responseString(fields, "xray_version", true); err != nil {
		return value, err
	}
	if value.State, err = responseString(fields, "state", true); err != nil {
		return value, err
	}
	if value.ConfigPath, err = responseString(fields, "config_path", false); err != nil {
		return value, err
	}
	if value.LastError, err = responseString(fields, "last_error", false); err != nil {
		return value, err
	}
	if value.LastExit, err = responseString(fields, "last_exit", false); err != nil {
		return value, err
	}
	if value.PID, err = responseInt(fields, "pid"); err != nil {
		return value, err
	}
	if value.RestartCount, err = responseInt(fields, "restart_count"); err != nil {
		return value, err
	}
	startedAt, err := responseString(fields, "started_at", false)
	if err != nil {
		return value, err
	}
	if startedAt != "" {
		value.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return value, fmt.Errorf("decode Controller started_at: %w", err)
		}
	}
	return value, nil
}

// Logs returns the supervisor's redacted recent log lines.
func (c *Client) Logs(ctx context.Context) ([]string, error) {
	result, err := c.call(ctx, "GetLogs", nil)
	if err != nil {
		return nil, err
	}
	value := result.GetFields()["lines"]
	if value == nil || value.GetListValue() == nil {
		return nil, errors.New("decode Controller logs: lines must be a list")
	}
	lines := make([]string, 0, len(value.GetListValue().GetValues()))
	for index, line := range value.GetListValue().GetValues() {
		if _, ok := line.GetKind().(*structpb.Value_StringValue); !ok {
			return nil, fmt.Errorf("decode Controller logs: line %d must be a string", index)
		}
		lines = append(lines, line.GetStringValue())
	}
	return lines, nil
}

// Validate asks the Xray adapter to validate a candidate config.
func (c *Client) Validate(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, "ValidateConfig", map[string]any{"path": path, "operation_id": operationID})
	return err
}

// Apply activates a validated Xray config.
func (c *Client) Apply(ctx context.Context, path, operationID string) error {
	_, err := c.call(ctx, "ApplyConfig", map[string]any{"path": path, "operation_id": operationID})
	return err
}

// ReplaceInbound updates one running Xray inbound without restarting Xray.
func (c *Client) ReplaceInbound(ctx context.Context, candidatePath, previousPath, tag, operationID string) error {
	_, err := c.call(ctx, "ReplaceInbound", map[string]any{"candidate_path": candidatePath, "previous_path": previousPath, "tag": tag, "operation_id": operationID})
	return err
}

// ProbeTarget checks the configured REALITY target through the Xray adapter.
func (c *Client) ProbeTarget(ctx context.Context, target, sni string) error {
	_, err := c.call(ctx, "ProbeTarget", map[string]any{"target": target, "sni": sni})
	return err
}

// ProbeIPv6 checks outbound IPv6 connectivity from the Xray container.
func (c *Client) ProbeIPv6(ctx context.Context) error {
	_, err := c.call(ctx, "ProbeIPv6", nil)
	return err
}

// AddUser installs a VLESS user in the running Xray inbound.
func (c *Client) AddUser(ctx context.Context, email, id, flow string) error {
	_, err := c.call(ctx, "AddDeviceUser", map[string]any{"protocol": "vless", "email": email, "id": id, "flow": flow})
	return err
}

// RemoveUser removes a VLESS user from the running Xray inbound.
func (c *Client) RemoveUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", map[string]any{"protocol": "vless", "email": email})
	return err
}

// AddHysteriaUser installs a Hysteria 2 credential into Xray.
func (c *Client) AddHysteriaUser(ctx context.Context, email, password string) error {
	_, err := c.call(ctx, "AddDeviceUser", map[string]any{"protocol": "hysteria2", "email": email, "id": password})
	return err
}

// RemoveHysteriaUser revokes a Hysteria 2 credential from Xray.
func (c *Client) RemoveHysteriaUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", map[string]any{"protocol": "hysteria2", "email": email})
	return err
}

// AddVMessUser installs a VMess UUID into Xray.
func (c *Client) AddVMessUser(ctx context.Context, email, id string) error {
	_, err := c.call(ctx, "AddDeviceUser", map[string]any{"protocol": "vmess", "email": email, "id": id})
	return err
}

// RemoveVMessUser revokes a VMess user from Xray.
func (c *Client) RemoveVMessUser(ctx context.Context, email string) error {
	_, err := c.call(ctx, "RemoveDeviceUser", map[string]any{"protocol": "vmess", "email": email})
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
	response, err := c.call(ctx, "ListDeviceUsers", map[string]any{"protocol": protocol})
	if err != nil {
		return nil, err
	}
	items, err := listField(response.GetFields(), "users")
	if err != nil {
		return nil, err
	}
	users := make([]string, 0, len(items))
	for index, item := range items {
		value, ok := item.GetKind().(*structpb.Value_StringValue)
		if !ok {
			return nil, fmt.Errorf("decode Controller users: item %d must be a string", index)
		}
		users = append(users, value.StringValue)
	}
	return users, nil
}

// Poll reads normalized user counters and source IP observations from Xray.
func (c *Client) Poll(ctx context.Context) ([]xrayapi.UserStats, error) {
	response, err := c.call(ctx, "GetXrayTelemetry", nil)
	if err != nil {
		return nil, err
	}
	items, err := listField(response.GetFields(), "users")
	if err != nil {
		return nil, err
	}
	users := make([]xrayapi.UserStats, 0, len(items))
	for index, item := range items {
		fields := item.GetStructValue()
		if fields == nil {
			return nil, fmt.Errorf("decode Controller telemetry: user %d must be an object", index)
		}
		values := fields.GetFields()
		email, err := responseString(values, "email", true)
		if err != nil {
			return nil, err
		}
		upload, err := responseCounter(values, "upload_bytes")
		if err != nil {
			return nil, err
		}
		download, err := responseCounter(values, "download_bytes")
		if err != nil {
			return nil, err
		}
		lastSeen, err := responseTime(values, "last_seen")
		if err != nil {
			return nil, err
		}
		ipValues, err := listField(values, "source_ips")
		if err != nil {
			return nil, err
		}
		ips := make([]xrayapi.IPObservation, 0, len(ipValues))
		for ipIndex, ipValue := range ipValues {
			ipFields := ipValue.GetStructValue()
			if ipFields == nil {
				return nil, fmt.Errorf("decode Controller telemetry: source IP %d must be an object", ipIndex)
			}
			address, err := responseString(ipFields.GetFields(), "address", true)
			if err != nil {
				return nil, err
			}
			seen, err := responseTime(ipFields.GetFields(), "last_seen")
			if err != nil {
				return nil, err
			}
			ips = append(ips, xrayapi.IPObservation{Address: address, LastSeen: seen})
		}
		users = append(users, xrayapi.UserStats{Email: email, UploadBytes: upload, DownloadBytes: download, LastSeen: lastSeen, SourceIPs: ips})
	}
	return users, nil
}

func (c *Client) call(ctx context.Context, method string, fields map[string]any) (*structpb.Struct, error) {
	if c == nil || c.connection == nil {
		return nil, errors.New("Controller gRPC connection is not initialized")
	}
	request, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("encode Controller request: %w", err)
	}
	outgoing, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Controller request ID: %w", err)
	}
	outgoing = metadata.AppendToOutgoingContext(outgoing, "authorization", "Bearer "+c.token)
	response := new(structpb.Struct)
	fullMethod := "/" + RPCServiceName + "/" + method
	started := time.Now()
	err = c.connection.Invoke(outgoing, fullMethod, request, response)
	interaction.LogRPC(c.logger, "xray-easy", fullMethod, requestID, protocolForClientCall(method, fields), started, err)
	if err != nil {
		return nil, fmt.Errorf("Controller %s: %w", method, err)
	}
	return response, nil
}

func protocolForClientCall(method string, fields map[string]any) string {
	if strings.Contains(method, "AmneziaWG") {
		return "amneziawg"
	}
	if method == "Health" || method == "GetCapabilities" {
		return "runtime"
	}
	if protocol, ok := fields["protocol"].(string); ok {
		switch protocol {
		case "vless", "vmess", "hysteria2", "amneziawg":
			return protocol
		}
	}
	return "xray"
}

func responseString(fields map[string]*structpb.Value, name string, required bool) (string, error) {
	value := fields[name]
	if value == nil {
		if required {
			return "", fmt.Errorf("decode Controller response: missing %s", name)
		}
		return "", nil
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", fmt.Errorf("decode Controller response: %s must be a string", name)
	}
	return value.GetStringValue(), nil
}

func responseInt(fields map[string]*structpb.Value, name string) (int, error) {
	value := fields[name]
	if value == nil {
		return 0, fmt.Errorf("decode Controller response: missing %s", name)
	}
	numeric, ok := value.GetKind().(*structpb.Value_NumberValue)
	if !ok {
		return 0, fmt.Errorf("decode Controller response: %s must be a number", name)
	}
	number := numeric.NumberValue
	if number < 0 || number >= float64(int(^uint(0)>>1)) || math.Trunc(number) != number {
		return 0, fmt.Errorf("decode Controller response: %s must be a non-negative integer", name)
	}
	return int(number), nil
}
