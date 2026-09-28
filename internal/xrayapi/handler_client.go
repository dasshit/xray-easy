package xrayapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	handlercommand "xray-easy/internal/xrayapi/handler"
	"xray-easy/internal/xrayapi/protocol"
	"xray-easy/internal/xrayapi/serial"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const inboundTag = "vless-reality"

// HandlerClient wraps the generated Xray HandlerService API. The control
// plane still renders a complete config for durable recovery, while these
// operations update the running inbound without restarting the data plane.
type HandlerClient struct {
	address     string
	dialOptions []grpc.DialOption

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client handlercommand.HandlerServiceClient
}

func NewHandlerClient(address string) *HandlerClient {
	return &HandlerClient{address: address}
}

func (c *HandlerClient) AddUser(ctx context.Context, email, uuid, flow string) error {
	account := make([]byte, 0, len(uuid)+len(flow)+4)
	account = protowire.AppendTag(account, 1, protowire.BytesType)
	account = protowire.AppendString(account, uuid)
	if flow != "" {
		account = protowire.AppendTag(account, 2, protowire.BytesType)
		account = protowire.AppendString(account, flow)
	}
	operation := &handlercommand.AddUserOperation{User: &protocol.User{Email: email, Account: &serial.TypedMessage{Type: "xray.proxy.vless.Account", Value: account}}}
	return c.alter(ctx, &serial.TypedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: mustMarshal(operation)})
}

func (c *HandlerClient) RemoveUser(ctx context.Context, email string) error {
	operation := &handlercommand.RemoveUserOperation{Email: email}
	return c.alter(ctx, &serial.TypedMessage{Type: "xray.app.proxyman.command.RemoveUserOperation", Value: mustMarshal(operation)})
}

func (c *HandlerClient) Users(ctx context.Context) ([]string, error) {
	client, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := c.resolveInboundTag(ctx, client)
	if err != nil {
		return nil, err
	}
	response, err := client.GetInboundUsers(ctx, &handlercommand.GetInboundUserRequest{Tag: tag})
	if err != nil {
		c.reset()
		return nil, fmt.Errorf("get inbound users: %w", err)
	}
	users := make([]string, 0, len(response.GetUsers()))
	for _, user := range response.GetUsers() {
		if user != nil && user.GetEmail() != "" {
			users = append(users, user.GetEmail())
		}
	}
	return users, nil
}

func (c *HandlerClient) alter(ctx context.Context, operation *serial.TypedMessage) error {
	client, err := c.service(ctx)
	if err != nil {
		return err
	}
	tag, err := c.resolveInboundTag(ctx, client)
	if err != nil {
		return err
	}
	if _, err := client.AlterInbound(ctx, &handlercommand.AlterInboundRequest{Tag: tag, Operation: operation}); err != nil {
		c.reset()
		return fmt.Errorf("alter inbound: %w", err)
	}
	return nil
}

func (c *HandlerClient) resolveInboundTag(ctx context.Context, client handlercommand.HandlerServiceClient) (string, error) {
	tags, err := client.ListInbounds(ctx, &handlercommand.ListInboundsRequest{IsOnlyTags: true})
	if err != nil {
		c.reset()
		return "", fmt.Errorf("list Xray inbounds: %w", err)
	}
	fallback := ""
	for _, inbound := range tags.GetInbounds() {
		if inbound == nil || inbound.GetTag() == "" {
			continue
		}
		if inbound.GetTag() == inboundTag {
			return inboundTag, nil
		}
		if fallback == "" {
			fallback = inbound.GetTag()
		} else {
			fallback = ""
			break
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("Xray inbound %q was not found", inboundTag)
}

func (c *HandlerClient) service(ctx context.Context) (handlercommand.HandlerServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	if c.address == "" {
		return nil, fmt.Errorf("Xray API address is empty")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, c.address, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()}, c.dialOptions...)...)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray API %s: %w", c.address, err)
	}
	c.conn = conn
	c.client = handlercommand.NewHandlerServiceClient(conn)
	return c.client, nil
}

func (c *HandlerClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.client = nil, nil
}

func (c *HandlerClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.client = nil, nil
	return err
}

func mustMarshal(message proto.Message) []byte {
	value, err := proto.Marshal(message)
	if err != nil {
		panic(err)
	}
	return value
}
