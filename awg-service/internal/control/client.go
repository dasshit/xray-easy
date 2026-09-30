package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Client invokes the private AWG gRPC API with its bearer token.
type Client struct {
	connection *grpc.ClientConn
	client     awgapi.ControlClient
	token      string
}

// DialClient connects to a private AWG service using the token file shared through its data volume.
func DialClient(ctx context.Context, address, tokenPath string) (*Client, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read AWG control token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, fmt.Errorf("AWG control token is empty")
	}
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("create AWG gRPC client: %w", err)
	}
	return &Client{connection: connection, client: awgapi.NewControlClient(connection), token: token}, nil
}

// Invoke runs one generated typed RPC and converts only the CLI's local JSON
// argument/output representation. No google.protobuf.Struct crosses the link.
func (c *Client) Invoke(ctx context.Context, method string, fields map[string]any) (map[string]any, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	request := func(message proto.Message) error {
		data, err := json.Marshal(fields)
		if err != nil {
			return fmt.Errorf("encode AWG API request: %w", err)
		}
		if err := protojson.Unmarshal(data, message); err != nil {
			return fmt.Errorf("decode AWG API request: %w", err)
		}
		return nil
	}
	var response proto.Message
	var err error
	switch method {
	case "GetStatus":
		response, err = c.client.GetStatus(ctx, &emptypb.Empty{})
	case "ListPeers":
		response, err = c.client.ListPeers(ctx, &emptypb.Empty{})
	case "GetPeerStats":
		response, err = c.client.GetPeerStats(ctx, &emptypb.Empty{})
	case "CreatePeer":
		message := new(awgapi.CreatePeerRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.CreatePeer(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	case "AddPeer":
		message := new(awgapi.AddPeerRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.AddPeer(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	case "RemovePeer":
		message := new(awgapi.RemovePeerRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.RemovePeer(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	case "GetClientConfig":
		message := new(awgapi.GetClientConfigRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.GetClientConfig(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	case "ExportBackup":
		result, err := c.client.ExportBackup(ctx, &emptypb.Empty{})
		response = result
		if err != nil {
			return nil, err
		}
	case "RestoreBackup":
		message := new(awgapi.RestoreBackupRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.RestoreBackup(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	case "RenderClientConfig":
		message := new(awgapi.RenderClientConfigRequest)
		if err := request(message); err != nil {
			return nil, err
		}
		result, err := c.client.RenderClientConfig(ctx, message)
		response = result
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown AWG API method %q", method)
	}
	if err != nil {
		return nil, err
	}
	data, err := protojson.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode AWG API response: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode AWG API response: %w", err)
	}
	return result, nil
}

// Close releases the underlying HTTP/2 connection.
func (c *Client) Close() error { return c.connection.Close() }
