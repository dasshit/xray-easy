package controller

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"xray-easy/internal/controller/api/v1"
	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type responseInvoker struct {
	responses map[string]proto.Message
	errors    map[string]error
	methods   []string
	requests  []proto.Message
}

func (i *responseInvoker) Invoke(_ context.Context, method string, request any, response any, _ ...grpc.CallOption) error {
	i.methods = append(i.methods, method)
	i.requests = append(i.requests, proto.Clone(request.(proto.Message)))
	if err := i.errors[method]; err != nil {
		return err
	}
	if value := i.responses[method]; value != nil {
		proto.Merge(response.(proto.Message), value)
	}
	return nil
}
func (*responseInvoker) Close() error { return nil }

func TestClientRoutesXrayUserAndTelemetryOperations(t *testing.T) {
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	listMethod := "/" + RPCServiceName + "/ListDeviceUsers"
	statsMethod := "/" + RPCServiceName + "/GetXrayTelemetry"
	invoker := &responseInvoker{responses: map[string]proto.Message{
		listMethod:  &controllerv1.ListDeviceUsersResponse{Users: []string{"vless@example.test", "vmess@example.test"}},
		statsMethod: &controllerv1.XrayTelemetryResponse{Users: []*controllerv1.XrayUserTelemetry{{Email: "vless@example.test", UploadBytes: 100, DownloadBytes: 200, LastSeen: timestamppb.New(now), SourceIps: []*controllerv1.IPObservation{{Address: "203.0.113.3", LastSeen: timestamppb.New(now)}}}}},
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
	if err != nil || len(observed) != 1 || observed[0].UploadBytes != 100 || observed[0].DownloadBytes != 200 || observed[0].LastSeen != now || len(observed[0].SourceIPs) != 1 || observed[0].SourceIPs[0].Address != "203.0.113.3" {
		t.Fatalf("Poll() = %+v, %v", observed, err)
	}
	for _, call := range invoker.methods {
		if len(call) < len("/"+RPCServiceName+"/") || call[:len("/"+RPCServiceName+"/")] != "/"+RPCServiceName+"/" {
			t.Errorf("unexpected RPC method %q", call)
		}
	}
}

func TestClientRejectsMalformedTypedXrayTelemetryAndAdapterErrors(t *testing.T) {
	statsMethod := "/" + RPCServiceName + "/GetXrayTelemetry"
	for _, response := range []*controllerv1.XrayTelemetryResponse{
		{Users: []*controllerv1.XrayUserTelemetry{nil}},
		{Users: []*controllerv1.XrayUserTelemetry{{Email: "device", UploadBytes: -1}}},
		{Users: []*controllerv1.XrayUserTelemetry{{Email: "device", SourceIps: []*controllerv1.IPObservation{nil}}}},
		{Users: []*controllerv1.XrayUserTelemetry{{Email: "device", SourceIps: []*controllerv1.IPObservation{{Address: "203.0.113.1", LastSeen: &timestamppb.Timestamp{Seconds: 999999999999}}}}}},
	} {
		invoker := &responseInvoker{responses: map[string]proto.Message{statsMethod: response}}
		if _, err := NewClientWithConn(invoker, "token").Poll(context.Background()); err == nil {
			t.Errorf("malformed telemetry response accepted: %+v", response)
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

func TestAWGClientRoutesTypedOperations(t *testing.T) {
	createdAt := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	peer := &controllerv1.AmneziaWGPeer{Name: "phone", PublicKey: "peer-key", Ipv4: "10.0.0.2", Ipv6: "fd00::2", CreatedAt: timestamppb.New(createdAt)}
	invoker := &responseInvoker{responses: map[string]proto.Message{
		"/" + RPCServiceName + "/GetAmneziaWGStatus":       &controllerv1.AmneziaWGStatusResponse{Running: true, PublicKey: "server-key", ListenPort: 1234, PublicHost: "vpn.example.test", PublicPort: 1234, PeerCount: 1, Ipv4Network: "10.0.0.0/24", Ipv6Network: "fd00::/64", ServiceVersion: "v1"},
		"/" + RPCServiceName + "/ListAmneziaWGPeers":       &controllerv1.ListAmneziaWGPeersResponse{Peers: []*controllerv1.AmneziaWGPeer{peer}},
		"/" + RPCServiceName + "/CreateAmneziaWGPeer":      peer,
		"/" + RPCServiceName + "/SetAmneziaWGPeerEnabled":  peer,
		"/" + RPCServiceName + "/SetAmneziaWGPeerExpiry":   peer,
		"/" + RPCServiceName + "/GetAmneziaWGClientConfig": &controllerv1.AmneziaWGClientConfigResponse{Config: "private-client-profile"},
		"/" + RPCServiceName + "/GetAmneziaWGPeerStats":    &controllerv1.AmneziaWGPeerStatsResponse{Peers: []*controllerv1.AmneziaWGPeerStats{{Name: "phone", SourceIp: "203.0.113.4", LastSeen: timestamppb.New(createdAt), UploadBytes: 99, DownloadBytes: 101}}},
		"/" + RPCServiceName + "/ExportAmneziaWGBackup":    &controllerv1.AmneziaWGBackupResponse{Data: []byte("archive")},
	}}
	client := NewClientWithConn(invoker, "token")
	awg := client.AWG()
	serverStatus, err := awg.Status(context.Background())
	if err != nil || !serverStatus.Running || serverStatus.ListenPort != 1234 || serverStatus.PublicHost != "vpn.example.test" {
		t.Fatalf("AWG Status() = %+v, %v", serverStatus, err)
	}
	peers, err := awg.ListPeers(context.Background())
	if err != nil || len(peers) != 1 || peers[0].Name != "phone" || peers[0].CreatedAt != createdAt {
		t.Fatalf("ListPeers() = %+v, %v", peers, err)
	}
	created, err := awg.CreatePeer(context.Background(), "phone", nil)
	if err != nil || created.IPv4 != "10.0.0.2" {
		t.Fatalf("CreatePeer() = %+v, %v", created, err)
	}
	if _, err := awg.SetPeerEnabled(context.Background(), "phone", true); err != nil {
		t.Fatalf("SetPeerEnabled() = %v", err)
	}
	if _, err := awg.SetPeerExpiry(context.Background(), "phone", nil); err != nil {
		t.Fatalf("SetPeerExpiry(clear) = %v", err)
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
	if len(invoker.requests) == 0 {
		t.Fatal("typed AWG request messages were not recorded")
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

func TestAWGClientRejectsInvalidTypedResponses(t *testing.T) {
	for _, response := range []*controllerv1.AmneziaWGStatusResponse{
		{ListenPort: -1},
		{PublicPort: 65536},
		{PeerCount: -1},
	} {
		if _, err := NewClientWithConn(&responseInvoker{responses: map[string]proto.Message{"/" + RPCServiceName + "/GetAmneziaWGStatus": response}}, "token").AWG().Status(context.Background()); err == nil {
			t.Errorf("invalid AWG status accepted: %+v", response)
		}
	}
	for _, response := range []*controllerv1.ListAmneziaWGPeersResponse{
		{Peers: []*controllerv1.AmneziaWGPeer{nil}},
		{Peers: []*controllerv1.AmneziaWGPeer{{Name: "phone"}}},
		{Peers: []*controllerv1.AmneziaWGPeer{{Name: "phone", PublicKey: "key", Ipv4: "10.0.0.2", Ipv6: "fd00::2", CreatedAt: &timestamppb.Timestamp{Seconds: 999999999999}}}},
	} {
		if _, err := NewClientWithConn(&responseInvoker{responses: map[string]proto.Message{"/" + RPCServiceName + "/ListAmneziaWGPeers": response}}, "token").AWG().ListPeers(context.Background()); err == nil {
			t.Errorf("invalid AWG peer accepted: %+v", response)
		}
	}
	for _, response := range []*controllerv1.AmneziaWGPeerStatsResponse{
		{Peers: []*controllerv1.AmneziaWGPeerStats{nil}},
		{Peers: []*controllerv1.AmneziaWGPeerStats{{Name: "phone", UploadBytes: -1}}},
		{Peers: []*controllerv1.AmneziaWGPeerStats{{Name: "phone", LastSeen: &timestamppb.Timestamp{Seconds: 999999999999}}}},
	} {
		if _, err := NewClientWithConn(&responseInvoker{responses: map[string]proto.Message{"/" + RPCServiceName + "/GetAmneziaWGPeerStats": response}}, "token").AWG().PeerStats(context.Background()); err == nil {
			t.Errorf("invalid AWG peer stats accepted: %+v", response)
		}
	}
	for method, call := range map[string]func(*AWGClient) error{
		"CreateAmneziaWGPeer": func(client *AWGClient) error {
			_, err := client.CreatePeer(context.Background(), "phone", nil)
			return err
		},
		"GetAmneziaWGClientConfig": func(client *AWGClient) error {
			_, err := client.ClientConfig(context.Background(), "phone")
			return err
		},
		"RestoreAmneziaWGBackup": func(client *AWGClient) error { return client.RestoreBackup(context.Background(), nil) },
		"RemoveAmneziaWGPeer":    func(client *AWGClient) error { return client.RemovePeer(context.Background(), "phone") },
		"SetAmneziaWGPeerEnabled": func(client *AWGClient) error {
			_, err := client.SetPeerEnabled(context.Background(), "phone", false)
			return err
		},
		"SetAmneziaWGPeerExpiry": func(client *AWGClient) error {
			_, err := client.SetPeerExpiry(context.Background(), "phone", nil)
			return err
		},
	} {
		invoker := &responseInvoker{errors: map[string]error{"/" + RPCServiceName + "/" + method: status.Error(codes.Unavailable, "offline")}}
		if err := call(NewClientWithConn(invoker, "token").AWG()); status.Code(err) != codes.Unavailable {
			t.Errorf("%s error = %v", method, err)
		}
	}
	if _, err := NewClientWithConn(&responseInvoker{errors: map[string]error{"/" + RPCServiceName + "/ExportAmneziaWGBackup": errors.New("closed")}}, "token").AWG().ExportBackup(context.Background()); err == nil {
		t.Fatal("AWG backup RPC failure ignored")
	}
}
