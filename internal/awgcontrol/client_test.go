package awgcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type fakeInvoker struct {
	calls     []string
	responses map[string]map[string]any
	requests  map[string]proto.Message
	err       error
	closeErr  error
}

func (f *fakeInvoker) Invoke(ctx context.Context, method string, request any, reply any, _ ...grpc.CallOption) error {
	f.calls = append(f.calls, method)
	if f.err != nil {
		return f.err
	}
	values, ok := metadata.FromOutgoingContext(ctx)
	if !ok || len(values.Get("authorization")) != 1 || values.Get("authorization")[0] != "Bearer test-token" {
		return errors.New("missing AWG bearer token")
	}
	if f.requests == nil {
		f.requests = make(map[string]proto.Message)
	}
	f.requests[method] = proto.Clone(request.(proto.Message))
	response, err := fakeResponseMessage(method)
	if err != nil {
		return err
	}
	payload := f.responses[method]
	if payload == nil {
		payload = map[string]any{}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(data, response); err != nil {
		return err
	}
	proto.Merge(reply.(proto.Message), response)
	return nil
}

func (f *fakeInvoker) Close() error { return f.closeErr }

func (*fakeInvoker) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("streaming RPC is not supported by fake")
}

func fakeResponseMessage(method string) (proto.Message, error) {
	switch method {
	case serviceName + "GetStatus":
		return new(awgapi.StatusResponse), nil
	case serviceName + "ListPeers":
		return new(awgapi.ListPeersResponse), nil
	case serviceName + "GetPeerStats":
		return new(awgapi.GetPeerStatsResponse), nil
	case serviceName + "CreatePeer", serviceName + "AddPeer":
		return new(awgapi.Peer), nil
	case serviceName + "RemovePeer":
		return new(awgapi.RemovePeerResponse), nil
	case serviceName + "GetClientConfig", serviceName + "RenderClientConfig":
		return new(awgapi.ClientConfigResponse), nil
	case serviceName + "ExportBackup":
		return new(awgapi.BackupResponse), nil
	case serviceName + "RestoreBackup":
		return new(awgapi.RestoreBackupResponse), nil
	default:
		return nil, errors.New("unexpected AWG RPC method")
	}
}

func newFakeClient(responses map[string]map[string]any) (*Client, *fakeInvoker) {
	connection := &fakeInvoker{responses: responses}
	return &Client{connection: connection, client: awgapi.NewControlClient(connection), token: "test-token"}, connection
}

func TestDialReadsAndTrimsPrivateToken(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "control.token")
	if err := os.WriteFile(tokenPath, []byte("  test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := Dial("passthrough:///awg-service", tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if client.token != "test-token" {
		t.Fatalf("token = %q, want trimmed token", client.token)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Dial("passthrough:///awg-service", filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "read AWG control token") {
		t.Fatalf("Dial with missing token file error = %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(empty, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial("passthrough:///awg-service", empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Dial with empty token error = %v", err)
	}
}

func TestClientStatusAndPeerLifecycleCallsAuthenticatedAPI(t *testing.T) {
	peer := map[string]any{
		"name": "iphone", "publicKey": "peer-key", "ipv4": "10.88.0.2", "ipv6": "fd88:88:88::2",
		"createdAt": "2026-09-30T12:00:00Z",
	}
	client, connection := newFakeClient(map[string]map[string]any{
		serviceName + "GetStatus": {
			"running": true, "publicKey": "server-key", "publicHost": "vpn.example.test", "ipv4Network": "10.88.0.0/24",
			"ipv6Network": "fd88:88:88::/64", "serviceVersion": "prototype-v1", "listenPort": float64(51820), "publicPort": float64(51820), "peerCount": float64(1),
		},
		serviceName + "ListPeers": {"peers": []any{peer}},
		serviceName + "GetPeerStats": {"peers": []any{map[string]any{
			"name": "iphone", "sourceIp": "203.0.113.8", "lastHandshake": "2026-09-30T12:00:00.123Z",
			"uploadBytes": "9007199254740993", "downloadBytes": "45",
		}}},
		serviceName + "CreatePeer":      peer,
		serviceName + "GetClientConfig": {"config": "[Interface]\nPrivateKey = private-key\n"},
	})

	gotStatus, err := client.Status(context.Background())
	if err != nil || !gotStatus.Running || gotStatus.PeerCount != 1 || gotStatus.PublicHost != "vpn.example.test" || gotStatus.ListenPort != 51820 {
		t.Fatalf("Status() = %+v, %v", gotStatus, err)
	}
	peers, err := client.ListPeers(context.Background())
	if err != nil || len(peers) != 1 || peers[0].Name != "iphone" || !peers[0].CreatedAt.Equal(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("ListPeers() = %+v, %v", peers, err)
	}
	created, err := client.CreatePeer(context.Background(), "iphone")
	if err != nil || created.Name != "iphone" {
		t.Fatalf("CreatePeer() = %+v, %v", created, err)
	}
	createRequest := connection.requests[serviceName+"CreatePeer"]
	if createRequest.(*awgapi.CreatePeerRequest).GetName() != "iphone" {
		t.Fatalf("CreatePeer request = %v", createRequest)
	}
	config, err := client.ClientConfig(context.Background(), "iphone")
	if err != nil || !strings.Contains(config, "private-key") {
		t.Fatalf("ClientConfig() = %q, %v", config, err)
	}
	if err := client.RemovePeer(context.Background(), "iphone"); err != nil {
		t.Fatal(err)
	}
	peerStats, err := client.PeerStats(context.Background())
	if err != nil || len(peerStats) != 1 || peerStats[0].Name != "iphone" || peerStats[0].SourceIP != "203.0.113.8" || peerStats[0].UploadBytes != 9007199254740993 || peerStats[0].DownloadBytes != 45 {
		t.Fatalf("PeerStats() = %+v, %v", peerStats, err)
	}
	if got := strings.Join(connection.calls, ","); got != strings.Join([]string{
		serviceName + "GetStatus", serviceName + "ListPeers", serviceName + "CreatePeer", serviceName + "GetClientConfig", serviceName + "RemovePeer", serviceName + "GetPeerStats",
	}, ",") {
		t.Fatalf("AWG RPC calls = %s", got)
	}
}

func TestClientExportsAndRestoresCredentialBearingArchive(t *testing.T) {
	client, connection := newFakeClient(map[string]map[string]any{
		serviceName + "ExportBackup":  {"data": "ZGVtby1hcmNoaXZl"},
		serviceName + "RestoreBackup": {"restored": true},
	})
	archive, err := client.ExportBackup(context.Background())
	if err != nil || string(archive) != "demo-archive" {
		t.Fatalf("ExportBackup() = %q, %v", archive, err)
	}
	if err := client.RestoreBackup(context.Background(), archive); err != nil {
		t.Fatal(err)
	}
	request := connection.requests[serviceName+"RestoreBackup"]
	if got := string(request.(*awgapi.RestoreBackupRequest).GetData()); got != string(archive) {
		t.Fatalf("RestoreBackup payload = %q", got)
	}
	if got := strings.Join(connection.calls, ","); got != serviceName+"ExportBackup,"+serviceName+"RestoreBackup" {
		t.Fatalf("backup RPC calls = %s", got)
	}
}

func TestClientRejectsMalformedUpstreamResponses(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		response  map[string]any
		operation func(*Client) error
	}{
		{"status missing field", "GetStatus", map[string]any{"running": true}, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"status wrong field type", "GetStatus", map[string]any{"running": "yes"}, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"status fractional port", "GetStatus", map[string]any{"running": true, "publicKey": "key", "publicHost": "host", "ipv4Network": "v4", "ipv6Network": "v6", "serviceVersion": "v1", "listenPort": 1.5}, func(c *Client) error { _, err := c.Status(context.Background()); return err }},
		{"peer item wrong type", "ListPeers", map[string]any{"peers": []any{"wrong"}}, func(c *Client) error { _, err := c.ListPeers(context.Background()); return err }},
		{"peer incomplete", "ListPeers", map[string]any{"peers": []any{map[string]any{"name": "phone"}}}, func(c *Client) error { _, err := c.ListPeers(context.Background()); return err }},
		{"peer stats invalid counter", "GetPeerStats", map[string]any{"peers": []any{map[string]any{"name": "phone", "uploadBytes": "-1", "downloadBytes": "0"}}}, func(c *Client) error { _, err := c.PeerStats(context.Background()); return err }},
		{"peer stats negative counter", "GetPeerStats", map[string]any{"peers": []any{map[string]any{"name": "phone", "uploadBytes": "1", "downloadBytes": "-1"}}}, func(c *Client) error { _, err := c.PeerStats(context.Background()); return err }},
		{"profile missing", "GetClientConfig", map[string]any{}, func(c *Client) error { _, err := c.ClientConfig(context.Background(), "phone"); return err }},
		{"backup invalid base64", "ExportBackup", map[string]any{"data": "%%%"}, func(c *Client) error { _, err := c.ExportBackup(context.Background()); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newFakeClient(map[string]map[string]any{serviceName + test.method: test.response})
			if err := test.operation(client); err == nil {
				t.Fatal("malformed response was accepted")
			}
		})
	}
}

func TestClientPropagatesRPCAndConnectionCloseErrors(t *testing.T) {
	client, connection := newFakeClient(nil)
	connection.err = errors.New("connection refused")
	if _, err := client.ListPeers(context.Background()); err == nil || !strings.Contains(err.Error(), "ListPeers failed") {
		t.Fatalf("RPC error = %v", err)
	}
	connection.closeErr = errors.New("close failed")
	if err := client.Close(); err == nil || err.Error() != "close failed" {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestClientRejectsMalformedStatusHandshakeAndCreatedPeerResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		method    string
		response  map[string]any
		operation func(*Client) error
	}{
		{
			name: "status missing endpoint fields", method: "GetStatus",
			response:  map[string]any{"running": true},
			operation: func(client *Client) error { _, err := client.Status(context.Background()); return err },
		},
		{
			name: "peer stats invalid handshake", method: "GetPeerStats",
			response: map[string]any{"peers": []any{map[string]any{
				"name": "phone", "lastHandshake": "yesterday", "uploadBytes": "1", "downloadBytes": "2",
			}}},
			operation: func(client *Client) error { _, err := client.PeerStats(context.Background()); return err },
		},
		{
			name: "created peer invalid timestamp", method: "CreatePeer",
			response:  map[string]any{"name": "phone", "publicKey": "key", "ipv4": "10.0.0.2", "ipv6": "fd00::2", "createdAt": "invalid"},
			operation: func(client *Client) error { _, err := client.CreatePeer(context.Background(), "phone"); return err },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newFakeClient(map[string]map[string]any{serviceName + test.method: test.response})
			if err := test.operation(client); err == nil {
				t.Fatal("malformed response was accepted")
			}
		})
	}
}
