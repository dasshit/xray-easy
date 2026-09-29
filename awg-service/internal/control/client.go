package control

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

// Client invokes the private AWG gRPC API with its bearer token.
type Client struct {
	connection *grpc.ClientConn
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
	return &Client{connection: connection, token: token}, nil
}

// Invoke sends a named method request to the private gRPC control service.
func (c *Client) Invoke(ctx context.Context, method string, fields map[string]any) (*structpb.Struct, error) {
	request, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("encode AWG API request: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	response := new(structpb.Struct)
	if err := c.connection.Invoke(ctx, "/xrayeasy.awg.v1.Control/"+method, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

// Close releases the underlying HTTP/2 connection.
func (c *Client) Close() error { return c.connection.Close() }
