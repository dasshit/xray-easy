package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	if _, err := client.Invoke(context.Background(), "CreatePeer", map[string]any{"name": make(chan int)}); err == nil {
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
	client := &Client{connection: connection, client: awgapi.NewControlClient(connection), token: "rpc-test-token"}
	for _, test := range []struct {
		method string
		fields map[string]any
		key    string
	}{
		{"GetStatus", nil, "serviceVersion"},
		{"ListPeers", nil, "peers"},
		{"GetPeerStats", nil, "peers"},
		{"CreatePeer", map[string]any{"name": "phone"}, "name"},
		{"AddPeer", map[string]any{"name": "phone", "publicKey": "client-public"}, "publicKey"},
		{"RemovePeer", map[string]any{"name": "phone"}, "removed"},
		{"GetClientConfig", map[string]any{"name": "phone"}, "config"},
		{"ExportBackup", nil, "data"},
		{"RestoreBackup", map[string]any{"data": "ZGVtbw=="}, "restored"},
		{"RenderClientConfig", map[string]any{"name": "phone", "privateKey": "client-private"}, "config"},
	} {
		response, err := client.Invoke(context.Background(), test.method, test.fields)
		if err != nil || response[test.key] == nil {
			t.Fatalf("Invoke %s response = %v, %v", test.method, response, err)
		}
	}
	for _, test := range []struct {
		method string
		fields map[string]any
	}{
		{"CreatePeer", map[string]any{"unknown": true}},
		{"AddPeer", map[string]any{"unknown": true}},
		{"RemovePeer", map[string]any{"unknown": true}},
		{"GetClientConfig", map[string]any{"unknown": true}},
		{"RestoreBackup", map[string]any{"unknown": true}},
		{"RenderClientConfig", map[string]any{"unknown": true}},
	} {
		if _, err := client.Invoke(context.Background(), test.method, test.fields); err == nil {
			t.Errorf("Invoke %s accepted an unknown request field", test.method)
		}
	}
	api.fail = true
	if _, err := client.Invoke(context.Background(), "GetStatus", nil); err == nil {
		t.Fatal("Invoke ignored a server error")
	}
	api.fail = false
	if _, err := client.Invoke(context.Background(), "CreatePeer", map[string]any{"name": "error"}); err == nil {
		t.Fatal("Invoke ignored a peer creation RPC error")
	}
	if _, err := client.Invoke(context.Background(), "AddPeer", map[string]any{"name": "error", "publicKey": "key"}); err == nil {
		t.Fatal("Invoke ignored an AddPeer RPC error")
	}
	if _, err := client.Invoke(context.Background(), "unknown", nil); err == nil {
		t.Fatal("Invoke accepted an unknown method")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

type statusAPI struct {
	awgapi.UnimplementedControlServer
	fail bool
}

func (s *statusAPI) GetStatus(context.Context, *emptypb.Empty) (*awgapi.StatusResponse, error) {
	if s.fail {
		return nil, status.Error(codes.Unavailable, "temporarily unavailable")
	}
	return &awgapi.StatusResponse{ServiceVersion: "test-version"}, nil
}

func (*statusAPI) ListPeers(context.Context, *emptypb.Empty) (*awgapi.ListPeersResponse, error) {
	return &awgapi.ListPeersResponse{Peers: []*awgapi.Peer{{Name: "phone", PublicKey: "peer-public", Ipv4: "10.0.0.2", Ipv6: "fd00::2", CreatedAt: timestamppb.New(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))}}}, nil
}

func (*statusAPI) GetPeerStats(context.Context, *emptypb.Empty) (*awgapi.GetPeerStatsResponse, error) {
	return &awgapi.GetPeerStatsResponse{Peers: []*awgapi.PeerStats{{Name: "phone", SourceIp: "203.0.113.1", UploadBytes: 9_007_199_254_740_993}}}, nil
}

func (*statusAPI) CreatePeer(_ context.Context, request *awgapi.CreatePeerRequest) (*awgapi.Peer, error) {
	if request.GetName() == "error" {
		return nil, status.Error(codes.InvalidArgument, "invalid peer")
	}
	return &awgapi.Peer{Name: request.GetName(), PublicKey: "peer-public", Ipv4: "10.0.0.2", Ipv6: "fd00::2", CreatedAt: timestamppb.Now()}, nil
}

func (*statusAPI) AddPeer(_ context.Context, request *awgapi.AddPeerRequest) (*awgapi.Peer, error) {
	if request.GetName() == "error" {
		return nil, status.Error(codes.InvalidArgument, "invalid peer")
	}
	return &awgapi.Peer{Name: request.GetName(), PublicKey: request.GetPublicKey(), Ipv4: "10.0.0.2", Ipv6: "fd00::2", CreatedAt: timestamppb.Now()}, nil
}

func (*statusAPI) RemovePeer(_ context.Context, request *awgapi.RemovePeerRequest) (*awgapi.RemovePeerResponse, error) {
	return &awgapi.RemovePeerResponse{Removed: true, Name: request.GetName()}, nil
}

func (*statusAPI) GetClientConfig(context.Context, *awgapi.GetClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	return &awgapi.ClientConfigResponse{Config: "[Interface]\n"}, nil
}

func (*statusAPI) ExportBackup(context.Context, *emptypb.Empty) (*awgapi.BackupResponse, error) {
	return &awgapi.BackupResponse{Data: []byte("backup")}, nil
}

func (*statusAPI) RestoreBackup(context.Context, *awgapi.RestoreBackupRequest) (*awgapi.RestoreBackupResponse, error) {
	return &awgapi.RestoreBackupResponse{Restored: true}, nil
}

func (*statusAPI) RenderClientConfig(context.Context, *awgapi.RenderClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	return &awgapi.ClientConfigResponse{Config: "[Interface]\n"}, nil
}

var _ API = (*statusAPI)(nil)
