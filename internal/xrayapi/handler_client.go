package xrayapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"xray-easy/internal/interaction"
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
	return c.alter(ctx, inboundTag, &serial.TypedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: mustMarshal(operation)})
}

// AddHysteriaUser adds a per-device Hysteria 2 credential to the dedicated inbound.
func (c *HandlerClient) AddHysteriaUser(ctx context.Context, email, auth string) error {
	account := protowire.AppendTag(nil, 1, protowire.BytesType)
	account = protowire.AppendString(account, auth)
	operation := &handlercommand.AddUserOperation{User: &protocol.User{Email: email, Account: &serial.TypedMessage{Type: "xray.proxy.hysteria.account.Account", Value: account}}}
	return c.alter(ctx, "hysteria2", &serial.TypedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: mustMarshal(operation)})
}

func (c *HandlerClient) RemoveUser(ctx context.Context, email string) error {
	operation := &handlercommand.RemoveUserOperation{Email: email}
	return c.alter(ctx, inboundTag, &serial.TypedMessage{Type: "xray.app.proxyman.command.RemoveUserOperation", Value: mustMarshal(operation)})
}

// RemoveHysteriaUser revokes the device credential from the Hysteria 2 inbound.
func (c *HandlerClient) RemoveHysteriaUser(ctx context.Context, email string) error {
	operation := &handlercommand.RemoveUserOperation{Email: email}
	return c.alter(ctx, "hysteria2", &serial.TypedMessage{Type: "xray.app.proxyman.command.RemoveUserOperation", Value: mustMarshal(operation)})
}

// AddVMessUser adds one generated UUID to the dedicated VMess TLS inbound.
func (c *HandlerClient) AddVMessUser(ctx context.Context, email, uuid string) error {
	account := protowire.AppendTag(nil, 1, protowire.BytesType)
	account = protowire.AppendString(account, uuid)
	operation := &handlercommand.AddUserOperation{User: &protocol.User{Email: email, Account: &serial.TypedMessage{Type: "xray.proxy.vmess.Account", Value: account}}}
	return c.alter(ctx, "vmess-tls", &serial.TypedMessage{Type: "xray.app.proxyman.command.AddUserOperation", Value: mustMarshal(operation)})
}

// RemoveVMessUser revokes a device credential from the VMess TLS inbound.
func (c *HandlerClient) RemoveVMessUser(ctx context.Context, email string) error {
	operation := &handlercommand.RemoveUserOperation{Email: email}
	return c.alter(ctx, "vmess-tls", &serial.TypedMessage{Type: "xray.app.proxyman.command.RemoveUserOperation", Value: mustMarshal(operation)})
}

func (c *HandlerClient) Users(ctx context.Context) ([]string, error) {
	return c.UsersInInbound(ctx, inboundTag)
}

// UsersInInbound lists currently loaded account emails for one tagged inbound.
func (c *HandlerClient) UsersInInbound(ctx context.Context, inboundTag string) ([]string, error) {
	ctx, _, traceErr := interaction.OutgoingContext(ctx)
	if traceErr != nil {
		return nil, fmt.Errorf("create Xray Handler request ID: %w", traceErr)
	}
	client, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	tag, err := c.resolveInboundTag(ctx, client, inboundTag)
	if err != nil {
		return nil, err
	}
	rpcContext, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create Xray Handler request ID: %w", err)
	}
	started := time.Now()
	response, err := client.GetInboundUsers(rpcContext, &handlercommand.GetInboundUserRequest{Tag: tag})
	interaction.LogRPC(slog.Default(), "xray-handler-client", "/xray.app.proxyman.command.HandlerService/GetInboundUsers", requestID, "xray", started, err, interaction.TraceFromContext(rpcContext))
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

func (c *HandlerClient) alter(ctx context.Context, inboundTag string, operation *serial.TypedMessage) error {
	ctx, _, traceErr := interaction.OutgoingContext(ctx)
	if traceErr != nil {
		return fmt.Errorf("create Xray Handler request ID: %w", traceErr)
	}
	client, err := c.service(ctx)
	if err != nil {
		return err
	}
	tag, err := c.resolveInboundTag(ctx, client, inboundTag)
	if err != nil {
		return err
	}
	rpcContext, requestID, err := interaction.OutgoingContext(ctx)
	if err != nil {
		return fmt.Errorf("create Xray Handler request ID: %w", err)
	}
	started := time.Now()
	if _, err := client.AlterInbound(rpcContext, &handlercommand.AlterInboundRequest{Tag: tag, Operation: operation}); err != nil {
		interaction.LogRPC(slog.Default(), "xray-handler-client", "/xray.app.proxyman.command.HandlerService/AlterInbound", requestID, "xray", started, err, interaction.TraceFromContext(rpcContext))
		c.reset()
		return fmt.Errorf("alter inbound: %w", err)
	}
	interaction.LogRPC(slog.Default(), "xray-handler-client", "/xray.app.proxyman.command.HandlerService/AlterInbound", requestID, "xray", started, nil, interaction.TraceFromContext(rpcContext))
	return nil
}

func (c *HandlerClient) resolveInboundTag(ctx context.Context, client handlercommand.HandlerServiceClient, preferredTag string) (string, error) {
	rpcContext, requestID, traceErr := interaction.OutgoingContext(ctx)
	if traceErr != nil {
		return "", fmt.Errorf("create Xray Handler request ID: %w", traceErr)
	}
	started := time.Now()
	tags, err := client.ListInbounds(rpcContext, &handlercommand.ListInboundsRequest{IsOnlyTags: true})
	interaction.LogRPC(slog.Default(), "xray-handler-client", "/xray.app.proxyman.command.HandlerService/ListInbounds", requestID, "xray", started, err, interaction.TraceFromContext(rpcContext))
	if err != nil {
		c.reset()
		return "", fmt.Errorf("list Xray inbounds: %w", err)
	}
	fallback := ""
	for _, inbound := range tags.GetInbounds() {
		if inbound == nil || inbound.GetTag() == "" {
			continue
		}
		if inbound.GetTag() == preferredTag {
			return preferredTag, nil
		}
		if fallback == "" {
			fallback = inbound.GetTag()
		} else {
			fallback = ""
			break
		}
	}
	if preferredTag == inboundTag && fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("Xray inbound %q was not found", preferredTag)
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
