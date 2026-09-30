package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestClientReadsTokenAndInvokesAuthenticatedRPC(t *testing.T) {
	root := t.TempDir()
	if _, err := DialClient(context.Background(), "passthrough:///unused", filepath.Join(root, "missing")); err == nil {
		t.Fatal("DialClient accepted a missing token file")
	}
	tokenPath := filepath.Join(root, "token")
	if err := os.WriteFile(tokenPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DialClient(context.Background(), "passthrough:///unused", tokenPath); err == nil {
		t.Fatal("DialClient accepted an empty token")
	}
	if err := os.WriteFile(tokenPath, []byte("rpc-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := DialClient(context.Background(), "passthrough:///unused", tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := client.Invoke(ctx, "GetStatus", nil); err == nil {
		t.Fatal("RPC to a missing service unexpectedly succeeded")
	}
	if _, err := client.Invoke(context.Background(), "GetStatus", map[string]any{"not-encodable": make(chan int)}); err == nil {
		t.Fatal("client accepted a non-protobuf request field")
	}
}

func TestClientInvokeReturnsSuccessfulResponse(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(AuthInterceptor("rpc-test-token")))
	api := &statusAPI{}
	Register(server, api)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	connection, err := grpc.NewClient("passthrough:///client-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{connection: connection, token: "rpc-test-token"}
	response, err := client.Invoke(context.Background(), "GetStatus", nil)
	if err != nil || response.GetFields()["ok"].GetBoolValue() != true {
		t.Fatalf("Invoke response = %v, %v", response, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

type statusAPI struct{}

func (*statusAPI) GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"ok": true})
}
func (*statusAPI) ListPeers(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) GetPeerStats(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) CreatePeer(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) AddPeer(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) RemovePeer(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) GetClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) ExportBackup(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) RestoreBackup(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}
func (*statusAPI) RenderClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{})
}

var _ API = (*statusAPI)(nil)
