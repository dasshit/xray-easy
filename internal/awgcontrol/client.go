// Package awgcontrol provides the authenticated gRPC gateway to the optional
// AmneziaWG service container.
package awgcontrol

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

const serviceName = "/xrayeasy.awg.v1.Control/"

// Gateway exposes only the AWG operations needed by the application layer.
type Gateway interface {
	Status(context.Context) (domain.AmneziaWGStatus, error)
	ListPeers(context.Context) ([]domain.AmneziaWGPeer, error)
	CreatePeer(context.Context, string) (domain.AmneziaWGPeer, error)
	RemovePeer(context.Context, string) error
	ClientConfig(context.Context, string) (string, error)
}

type invoker interface {
	Invoke(context.Context, string, any, any, ...grpc.CallOption) error
	Close() error
}

// Client invokes the private AWG gRPC API using its shared bearer token.
type Client struct {
	connection invoker
	token      string
}

// Dial reads the private token file and prepares a connection to the AWG
// service. Network connectivity is checked on the first RPC.
func Dial(address, tokenPath string) (*Client, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read AWG control token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("AWG control token is empty")
	}
	connection, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("create AWG gRPC client: %w", err)
	}
	return &Client{connection: connection, token: token}, nil
}

// Status reads the current server endpoint and peer count.
func (c *Client) Status(ctx context.Context) (domain.AmneziaWGStatus, error) {
	response, err := c.call(ctx, "GetStatus", nil)
	if err != nil {
		return domain.AmneziaWGStatus{}, err
	}
	fields := response.GetFields()
	running, err := boolField(fields, "running")
	if err != nil {
		return domain.AmneziaWGStatus{}, err
	}
	status := domain.AmneziaWGStatus{Running: running}
	for key, target := range map[string]*string{
		"publicKey": &status.PublicKey, "publicHost": &status.PublicHost,
		"ipv4Network": &status.IPv4Network, "ipv6Network": &status.IPv6Network,
		"serviceVersion": &status.ServiceVersion,
	} {
		*target, err = stringField(fields, key)
		if err != nil {
			return domain.AmneziaWGStatus{}, err
		}
	}
	for key, target := range map[string]*int{
		"listenPort": &status.ListenPort, "publicPort": &status.PublicPort, "peerCount": &status.PeerCount,
	} {
		*target, err = integerField(fields, key)
		if err != nil {
			return domain.AmneziaWGStatus{}, err
		}
	}
	return status, nil
}

// ListPeers reads the peers currently persisted by the AWG service.
func (c *Client) ListPeers(ctx context.Context) ([]domain.AmneziaWGPeer, error) {
	response, err := c.call(ctx, "ListPeers", nil)
	if err != nil {
		return nil, err
	}
	value := response.GetFields()["peers"]
	if value == nil || value.GetListValue() == nil {
		return nil, errors.New("AWG response field peers is missing or invalid")
	}
	peers := make([]domain.AmneziaWGPeer, 0, len(value.GetListValue().GetValues()))
	for _, item := range value.GetListValue().GetValues() {
		if item.GetStructValue() == nil {
			return nil, errors.New("AWG response contains an invalid peer")
		}
		peer, err := parsePeer(item.GetStructValue())
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

// PeerStats reads live per-peer counters and endpoint metadata. Empty handshake
// and source fields mean that no peer connection has been observed yet.
func (c *Client) PeerStats(ctx context.Context) ([]domain.AmneziaWGPeerStats, error) {
	response, err := c.call(ctx, "GetPeerStats", nil)
	if err != nil {
		return nil, err
	}
	value := response.GetFields()["peers"]
	if value == nil || value.GetListValue() == nil {
		return nil, errors.New("AWG response field peers is missing or invalid")
	}
	peers := make([]domain.AmneziaWGPeerStats, 0, len(value.GetListValue().GetValues()))
	for _, item := range value.GetListValue().GetValues() {
		if item.GetStructValue() == nil {
			return nil, errors.New("AWG response contains an invalid peer stats entry")
		}
		fields := item.GetStructValue().GetFields()
		name, err := stringField(fields, "name")
		if err != nil {
			return nil, err
		}
		sourceIP := optionalStringField(fields, "sourceIp")
		lastSeen := time.Time{}
		if value := optionalStringField(fields, "lastHandshake"); value != "" {
			lastSeen, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return nil, fmt.Errorf("AWG response field lastHandshake is invalid: %w", err)
			}
		}
		upload, err := parseCounterField(fields, "uploadBytes")
		if err != nil {
			return nil, err
		}
		download, err := parseCounterField(fields, "downloadBytes")
		if err != nil {
			return nil, err
		}
		peers = append(peers, domain.AmneziaWGPeerStats{Name: name, SourceIP: sourceIP, LastSeen: lastSeen, UploadBytes: upload, DownloadBytes: download})
	}
	return peers, nil
}

// CreatePeer generates the device keypair and registers a persistent peer.
func (c *Client) CreatePeer(ctx context.Context, name string) (domain.AmneziaWGPeer, error) {
	response, err := c.call(ctx, "CreatePeer", map[string]any{"name": name})
	if err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return parsePeer(response)
}

// RemovePeer revokes the peer and deletes its saved client profile.
func (c *Client) RemovePeer(ctx context.Context, name string) error {
	_, err := c.call(ctx, "RemovePeer", map[string]any{"name": name})
	return err
}

// ClientConfig returns the credential-bearing profile for an active peer.
func (c *Client) ClientConfig(ctx context.Context, name string) (string, error) {
	response, err := c.call(ctx, "GetClientConfig", map[string]any{"name": name})
	if err != nil {
		return "", err
	}
	return stringField(response.GetFields(), "config")
}

// ExportBackup reads a validated, compressed snapshot containing server state
// and client profiles. The returned archive includes private client keys.
func (c *Client) ExportBackup(ctx context.Context) ([]byte, error) {
	response, err := c.call(ctx, "ExportBackup", nil)
	if err != nil {
		return nil, err
	}
	encoded, err := stringField(response.GetFields(), "data")
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode AWG backup response: %w", err)
	}
	return data, nil
}

// RestoreBackup validates and applies a snapshot, including its client private
// profiles, through the private AWG control service.
func (c *Client) RestoreBackup(ctx context.Context, data []byte) error {
	_, err := c.call(ctx, "RestoreBackup", map[string]any{"data": base64.StdEncoding.EncodeToString(data)})
	return err
}

// Close releases the underlying HTTP/2 connection.
func (c *Client) Close() error { return c.connection.Close() }

func (c *Client) call(ctx context.Context, method string, fields map[string]any) (*structpb.Struct, error) {
	request, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("encode AWG request: %w", err)
	}
	ctx, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create AWG request ID: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	response := new(structpb.Struct)
	fullMethod := serviceName + method
	started := time.Now()
	if err := c.connection.Invoke(ctx, fullMethod, request, response); err != nil {
		interaction.LogRPC(slog.Default(), "awg-client", fullMethod, requestID, "amneziawg", started, err, interaction.TraceFromContext(ctx))
		return nil, fmt.Errorf("AWG %s failed: %w", method, err)
	}
	interaction.LogRPC(slog.Default(), "awg-client", fullMethod, requestID, "amneziawg", started, nil, interaction.TraceFromContext(ctx))
	return response, nil
}

func parsePeer(fields *structpb.Struct) (domain.AmneziaWGPeer, error) {
	values := fields.GetFields()
	var peer domain.AmneziaWGPeer
	var err error
	for key, target := range map[string]*string{
		"name": &peer.Name, "publicKey": &peer.PublicKey, "ipv4": &peer.IPv4, "ipv6": &peer.IPv6,
	} {
		*target, err = stringField(values, key)
		if err != nil {
			return domain.AmneziaWGPeer{}, err
		}
	}
	createdAt, err := stringField(values, "createdAt")
	if err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	peer.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return domain.AmneziaWGPeer{}, fmt.Errorf("AWG response field createdAt is invalid: %w", err)
	}
	return peer, nil
}

func stringField(fields map[string]*structpb.Value, key string) (string, error) {
	value := fields[key]
	if value == nil || value.GetStringValue() == "" {
		return "", fmt.Errorf("AWG response field %s is missing or empty", key)
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return "", fmt.Errorf("AWG response field %s is not a string", key)
	}
	return value.GetStringValue(), nil
}

func optionalStringField(fields map[string]*structpb.Value, key string) string {
	value := fields[key]
	if value == nil || value.GetStringValue() == "" {
		return ""
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return ""
	}
	return value.GetStringValue()
}

func parseCounterField(fields map[string]*structpb.Value, key string) (int64, error) {
	value := fields[key]
	if value == nil || value.GetStringValue() == "" {
		return 0, fmt.Errorf("AWG response field %s is missing or empty", key)
	}
	if _, ok := value.GetKind().(*structpb.Value_StringValue); !ok {
		return 0, fmt.Errorf("AWG response field %s is not a string", key)
	}
	counter, err := strconv.ParseInt(value.GetStringValue(), 10, 64)
	if err != nil || counter < 0 {
		return 0, fmt.Errorf("AWG response field %s is invalid", key)
	}
	return counter, nil
}

func boolField(fields map[string]*structpb.Value, key string) (bool, error) {
	value := fields[key]
	if value == nil {
		return false, fmt.Errorf("AWG response field %s is missing", key)
	}
	if _, ok := value.GetKind().(*structpb.Value_BoolValue); !ok {
		return false, fmt.Errorf("AWG response field %s is not a boolean", key)
	}
	return value.GetBoolValue(), nil
}

func integerField(fields map[string]*structpb.Value, key string) (int, error) {
	value := fields[key]
	if value == nil || value.GetNumberValue() < 0 || value.GetNumberValue() != float64(int(value.GetNumberValue())) {
		return 0, fmt.Errorf("AWG response field %s is not a non-negative integer", key)
	}
	if _, ok := value.GetKind().(*structpb.Value_NumberValue); !ok {
		return 0, fmt.Errorf("AWG response field %s is not a number", key)
	}
	return int(value.GetNumberValue()), nil
}

var _ Gateway = (*Client)(nil)
var _ interface {
	ExportBackup(context.Context) ([]byte, error)
	RestoreBackup(context.Context, []byte) error
} = (*Client)(nil)
