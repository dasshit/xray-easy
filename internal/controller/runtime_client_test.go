package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type responseInvoker struct {
	responses map[string]*structpb.Struct
	errors    map[string]error
	methods   []string
	requests  []*structpb.Struct
}

func (i *responseInvoker) Invoke(_ context.Context, method string, request any, response any, _ ...grpc.CallOption) error {
	i.methods = append(i.methods, method)
	i.requests = append(i.requests, proto.Clone(request.(*structpb.Struct)).(*structpb.Struct))
	if err := i.errors[method]; err != nil {
		return err
	}
	if value := i.responses[method]; value != nil {
		proto.Merge(response.(proto.Message), value)
	}
	return nil
}
func (*responseInvoker) Close() error { return nil }

func responseValue(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestClientRoutesXrayUserAndTelemetryOperations(t *testing.T) {
	users := responseValue(t, map[string]any{"users": []any{"vless@example.test", "vmess@example.test"}})
	stats := responseValue(t, map[string]any{"users": []any{map[string]any{
		"email": "vless@example.test", "upload_bytes": "100", "download_bytes": "200", "last_seen": "2026-09-30T10:00:00Z",
		"source_ips": []any{map[string]any{"address": "203.0.113.3", "last_seen": "2026-09-30T09:59:00Z"}},
	}}})
	invoker := &responseInvoker{responses: map[string]*structpb.Struct{
		"/" + RPCServiceName + "/ListDeviceUsers":  users,
		"/" + RPCServiceName + "/GetXrayTelemetry": stats,
	}}
	client := NewClientWithConn(invoker, "token")
	id := "abcdef0123456789abcdef0123456789"
	ctx := interaction.WithRequestID(context.Background(), id)
	for _, action := range []func() error{
		func() error { return client.AddUser(ctx, "v@example.test", "uuid", "vision") },
		func() error { return client.RemoveUser(ctx, "v@example.test") },
		func() error { return client.AddHysteriaUser(ctx, "h@example.test", "password") },
		func() error { return client.RemoveHysteriaUser(ctx, "h@example.test") },
		func() error { return client.AddVMessUser(ctx, "m@example.test", "uuid") },
		func() error { return client.RemoveVMessUser(ctx, "m@example.test") },
	} {
		if err := action(); err != nil {
			t.Fatal(err)
		}
	}
	if values, err := client.Users(ctx); err != nil || !reflect.DeepEqual(values, []string{"vless@example.test", "vmess@example.test"}) {
		t.Fatalf("Users() = %v, %v", values, err)
	}
	if values, err := client.UsersInInbound(ctx, "vmess-tls"); err != nil || len(values) != 2 {
		t.Fatalf("UsersInInbound() = %v, %v", values, err)
	}
	if _, err := client.UsersInInbound(ctx, "unknown"); err == nil {
		t.Fatal("unsupported Xray inbound accepted")
	}
	observed, err := client.Poll(ctx)
	if err != nil || len(observed) != 1 || observed[0].UploadBytes != 100 || observed[0].DownloadBytes != 200 || len(observed[0].SourceIPs) != 1 || observed[0].SourceIPs[0].Address != "203.0.113.3" {
		t.Fatalf("Poll() = %+v, %v", observed, err)
	}
	for _, call := range invoker.methods {
		if !strings.HasPrefix(call, "/"+RPCServiceName+"/") {
			t.Errorf("unexpected RPC method %q", call)
		}
	}
}

func TestClientRejectsMalformedXrayListsAndTelemetry(t *testing.T) {
	listMethod := "/" + RPCServiceName + "/ListDeviceUsers"
	statsMethod := "/" + RPCServiceName + "/GetXrayTelemetry"
	for _, malformed := range []map[string]any{
		{}, {"users": "not-list"}, {"users": []any{4}},
	} {
		invoker := &responseInvoker{responses: map[string]*structpb.Struct{listMethod: responseValue(t, malformed)}}
		if _, err := NewClientWithConn(invoker, "token").Users(context.Background()); err == nil {
			t.Errorf("malformed user response accepted: %v", malformed)
		}
	}
	for _, malformed := range []map[string]any{
		{},
		{"users": "not-list"},
		{"users": []any{4}},
		{"users": []any{map[string]any{"upload_bytes": "0", "download_bytes": "0", "source_ips": []any{}}}},
		{"users": []any{map[string]any{"email": "device", "upload_bytes": "-1", "download_bytes": "0", "source_ips": []any{}}}},
		{"users": []any{map[string]any{"email": "device", "upload_bytes": "0", "download_bytes": "0", "last_seen": "bad", "source_ips": []any{}}}},
		{"users": []any{map[string]any{"email": "device", "upload_bytes": "0", "download_bytes": "0", "source_ips": "bad"}}},
		{"users": []any{map[string]any{"email": "device", "upload_bytes": "0", "download_bytes": "0", "source_ips": []any{4}}}},
		{"users": []any{map[string]any{"email": "device", "upload_bytes": "0", "download_bytes": "0", "source_ips": []any{map[string]any{"last_seen": ""}}}}},
	} {
		invoker := &responseInvoker{responses: map[string]*structpb.Struct{statsMethod: responseValue(t, malformed)}}
		if _, err := NewClientWithConn(invoker, "token").Poll(context.Background()); err == nil {
			t.Errorf("malformed telemetry response accepted: %v", malformed)
		}
	}
	invoker := &responseInvoker{errors: map[string]error{statsMethod: status.Error(codes.Unavailable, "private adapter failure")}}
	if _, err := NewClientWithConn(invoker, "token").Poll(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("telemetry RPC failure = %v", err)
	}
	deviceMethod := "/" + RPCServiceName + "/RemoveDeviceUser"
	if err := NewClientWithConn(&responseInvoker{errors: map[string]error{deviceMethod: errors.New("closed")}}, "token").RemoveUser(context.Background(), "email"); err == nil {
		t.Fatal("Xray user RPC error ignored")
	}
}

func TestAWGClientRoutesOperationsAndDecodesResponses(t *testing.T) {
	peer := map[string]any{"name": "phone", "public_key": "peer-key", "ipv4": "10.0.0.2", "ipv6": "fd00::2", "created_at": "2026-09-30T10:00:00Z"}
	invoker := &responseInvoker{responses: map[string]*structpb.Struct{
		"/" + RPCServiceName + "/GetAmneziaWGStatus":       responseValue(t, map[string]any{"running": true, "public_key": "server-key", "listen_port": 1234, "public_host": "vpn.example.test", "public_port": 1234, "peer_count": 1, "ipv4_network": "10.0.0.0/24", "ipv6_network": "fd00::/64", "service_version": "v1"}),
		"/" + RPCServiceName + "/ListAmneziaWGPeers":       responseValue(t, map[string]any{"peers": []any{peer}}),
		"/" + RPCServiceName + "/CreateAmneziaWGPeer":      responseValue(t, peer),
		"/" + RPCServiceName + "/GetAmneziaWGClientConfig": responseValue(t, map[string]any{"config": "private-client-profile"}),
		"/" + RPCServiceName + "/GetAmneziaWGPeerStats":    responseValue(t, map[string]any{"peers": []any{map[string]any{"name": "phone", "source_ip": "203.0.113.4", "last_seen": "2026-09-30T10:00:00Z", "upload_bytes": "99", "download_bytes": "101"}}}),
		"/" + RPCServiceName + "/ExportAmneziaWGBackup":    responseValue(t, map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("archive"))}),
	}}
	client := NewClientWithConn(invoker, "token")
	awg := client.AWG()
	serverStatus, err := awg.Status(context.Background())
	if err != nil || !serverStatus.Running || serverStatus.ListenPort != 1234 || serverStatus.PublicHost != "vpn.example.test" {
		t.Fatalf("AWG Status() = %+v, %v", serverStatus, err)
	}
	peers, err := awg.ListPeers(context.Background())
	if err != nil || len(peers) != 1 || peers[0].Name != "phone" {
		t.Fatalf("ListPeers() = %+v, %v", peers, err)
	}
	created, err := awg.CreatePeer(context.Background(), "phone")
	if err != nil || created.IPv4 != "10.0.0.2" {
		t.Fatalf("CreatePeer() = %+v, %v", created, err)
	}
	if err := awg.RemovePeer(context.Background(), "phone"); err != nil {
		t.Fatal(err)
	}
	if config, err := awg.ClientConfig(context.Background(), "phone"); err != nil || config != "private-client-profile" {
		t.Fatalf("ClientConfig() = %q, %v", config, err)
	}
	peerStats, err := awg.PeerStats(context.Background())
	if err != nil || len(peerStats) != 1 || peerStats[0].UploadBytes != 99 || peerStats[0].SourceIP != "203.0.113.4" {
		t.Fatalf("PeerStats() = %+v, %v", peerStats, err)
	}
	archive, err := awg.ExportBackup(context.Background())
	if err != nil || string(archive) != "archive" {
		t.Fatalf("ExportBackup() = %q, %v", archive, err)
	}
	if err := awg.RestoreBackup(context.Background(), []byte("restore")); err != nil {
		t.Fatal(err)
	}
	if err := awg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (*AWGClient)(nil).Close(); err != nil {
		t.Fatalf("nil AWG Close() = %v", err)
	}
	if err := (&AWGClient{}).Close(); err != nil {
		t.Fatalf("uninitialized AWG Close() = %v", err)
	}
}

func TestAWGClientRejectsMalformedResponsesAndRPCFailures(t *testing.T) {
	methods := map[string]*structpb.Struct{
		"/" + RPCServiceName + "/GetAmneziaWGStatus": responseValue(t, map[string]any{"running": "yes"}),
	}
	if _, err := NewClientWithConn(&responseInvoker{responses: methods}, "token").AWG().Status(context.Background()); err == nil {
		t.Fatal("malformed AWG status accepted")
	}
	for _, response := range []map[string]any{{}, {"peers": "bad"}, {"peers": []any{4}}, {"peers": []any{map[string]any{"name": "phone"}}}} {
		invoker := &responseInvoker{responses: map[string]*structpb.Struct{"/" + RPCServiceName + "/ListAmneziaWGPeers": responseValue(t, response)}}
		if _, err := NewClientWithConn(invoker, "token").AWG().ListPeers(context.Background()); err == nil {
			t.Errorf("malformed peer response accepted: %v", response)
		}
	}
	for _, response := range []map[string]any{{}, {"peers": "bad"}, {"peers": []any{4}}, {"peers": []any{map[string]any{"upload_bytes": "0", "download_bytes": "0"}}}} {
		invoker := &responseInvoker{responses: map[string]*structpb.Struct{"/" + RPCServiceName + "/GetAmneziaWGPeerStats": responseValue(t, response)}}
		if _, err := NewClientWithConn(invoker, "token").AWG().PeerStats(context.Background()); err == nil {
			t.Errorf("malformed peer stats accepted: %v", response)
		}
	}
	badBackup := &responseInvoker{responses: map[string]*structpb.Struct{"/" + RPCServiceName + "/ExportAmneziaWGBackup": responseValue(t, map[string]any{"data": "not-base64"})}}
	if _, err := NewClientWithConn(badBackup, "token").AWG().ExportBackup(context.Background()); err == nil {
		t.Fatal("malformed backup accepted")
	}
	for method, call := range map[string]func(*AWGClient) error{
		"CreateAmneziaWGPeer": func(client *AWGClient) error {
			_, err := client.CreatePeer(context.Background(), "phone")
			return err
		},
		"GetAmneziaWGClientConfig": func(client *AWGClient) error {
			_, err := client.ClientConfig(context.Background(), "phone")
			return err
		},
		"RestoreAmneziaWGBackup": func(client *AWGClient) error { return client.RestoreBackup(context.Background(), nil) },
		"RemoveAmneziaWGPeer":    func(client *AWGClient) error { return client.RemovePeer(context.Background(), "phone") },
	} {
		invoker := &responseInvoker{errors: map[string]error{"/" + RPCServiceName + "/" + method: status.Error(codes.Unavailable, "offline")}}
		if err := call(NewClientWithConn(invoker, "token").AWG()); status.Code(err) != codes.Unavailable {
			t.Errorf("%s error = %v", method, err)
		}
	}
	if _, err := NewClientWithConn(&responseInvoker{responses: map[string]*structpb.Struct{"/" + RPCServiceName + "/GetAmneziaWGClientConfig": responseValue(t, map[string]any{"config": 1})}}, "token").AWG().ClientConfig(context.Background(), "phone"); err == nil {
		t.Fatal("non-string client config accepted")
	}
}

func TestAWGClientRejectsMalformedFields(t *testing.T) {
	statusMethod := "/" + RPCServiceName + "/GetAmneziaWGStatus"
	for _, value := range []map[string]any{
		{},
		{"running": "yes"},
		{"running": false, "public_key": 1},
		{"running": false, "listen_port": "bad"},
	} {
		client := NewClientWithConn(&responseInvoker{responses: map[string]*structpb.Struct{statusMethod: responseValue(t, value)}}, "token").AWG()
		if _, err := client.Status(context.Background()); err == nil {
			t.Errorf("malformed status accepted: %v", value)
		}
	}

	validPeer := map[string]any{"name": "phone", "public_key": "key", "ipv4": "10.0.0.2", "ipv6": "fd00::2"}
	for _, value := range []map[string]any{
		{},
		{"name": 1, "public_key": "key", "ipv4": "10.0.0.2", "ipv6": "fd00::2"},
		{"name": "phone", "ipv4": "10.0.0.2", "ipv6": "fd00::2"},
		{"name": "phone", "public_key": "key", "ipv6": "fd00::2"},
		{"name": "phone", "public_key": "key", "ipv4": "10.0.0.2"},
		{"name": "phone", "public_key": "key", "ipv4": "10.0.0.2", "ipv6": "fd00::2", "created_at": "bad"},
	} {
		_, err := parsePeer(responseValue(t, value).GetFields())
		if err == nil {
			t.Errorf("malformed peer accepted: %v", value)
		}
	}
	if _, err := parsePeer(responseValue(t, validPeer).GetFields()); err != nil {
		t.Fatalf("valid peer rejected: %v", err)
	}

	statsMethod := "/" + RPCServiceName + "/GetAmneziaWGPeerStats"
	for _, peer := range []map[string]any{
		{"name": 1, "upload_bytes": "0", "download_bytes": "0"},
		{"name": "phone", "upload_bytes": "bad", "download_bytes": "0"},
		{"name": "phone", "upload_bytes": "-1", "download_bytes": "0"},
		{"name": "phone", "upload_bytes": "0", "download_bytes": "bad"},
		{"name": "phone", "upload_bytes": "0", "download_bytes": "0", "last_seen": "bad"},
	} {
		response := responseValue(t, map[string]any{"peers": []any{peer}})
		client := NewClientWithConn(&responseInvoker{responses: map[string]*structpb.Struct{statsMethod: response}}, "token").AWG()
		if _, err := client.PeerStats(context.Background()); err == nil {
			t.Errorf("malformed peer stats accepted: %v", peer)
		}
	}

	backupMethod := "/" + RPCServiceName + "/ExportAmneziaWGBackup"
	for _, response := range []map[string]any{{}, {"data": 1}} {
		client := NewClientWithConn(&responseInvoker{responses: map[string]*structpb.Struct{backupMethod: responseValue(t, response)}}, "token").AWG()
		if _, err := client.ExportBackup(context.Background()); err == nil {
			t.Errorf("malformed AWG backup accepted: %v", response)
		}
	}
}
