package control

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGRPCLifecycleRequiresTokenAndChangesPeerWithoutRestart(t *testing.T) {
	opts := testOptions(t)
	engine := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: engine})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(AuthInterceptor("correct-test-token")))
	Register(server, NewService(manager, opts))
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///awg-test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	statusRequest, _ := structpb.NewStruct(nil)
	statusResponse := new(structpb.Struct)
	err = connection.Invoke(ctx, "/xrayeasy.awg.v1.Control/GetStatus", statusRequest, statusResponse)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated status error = %v", err)
	}

	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer correct-test-token")
	_, clientPublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	addRequest, err := structpb.NewStruct(map[string]any{"name": "ios", "publicKey": clientPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	peerResponse := new(structpb.Struct)
	if err := connection.Invoke(authCtx, "/xrayeasy.awg.v1.Control/AddPeer", addRequest, peerResponse); err != nil {
		t.Fatal(err)
	}
	if peerResponse.GetFields()["ipv4"].GetStringValue() != "10.88.0.2" {
		t.Fatalf("unexpected allocated peer: %v", peerResponse.AsMap())
	}
	if engine.ups != 1 {
		t.Fatalf("adding peer restarted the engine %d times", engine.ups-1)
	}

	removeRequest, _ := structpb.NewStruct(map[string]any{"name": "ios"})
	removeResponse := new(structpb.Struct)
	if err := connection.Invoke(authCtx, "/xrayeasy.awg.v1.Control/RemovePeer", removeRequest, removeResponse); err != nil {
		t.Fatal(err)
	}
	if len(manager.Peers()) != 0 || engine.ups != 1 {
		t.Fatalf("peer lifecycle state mismatch; peers=%v ups=%d", manager.Peers(), engine.ups)
	}
}

func TestRenderConfigRequiresRegisteredMatchingPrivateKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("phone", publicKey); err != nil {
		t.Fatal(err)
	}
	service := NewService(manager, opts)
	request, _ := structpb.NewStruct(map[string]any{"name": "phone", "privateKey": privateKey})
	response, err := service.RenderClientConfig(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if response.GetFields()["config"].GetStringValue() == "" {
		t.Fatal("expected a rendered client config")
	}
	badRequest, _ := structpb.NewStruct(map[string]any{"name": "phone", "privateKey": "invalid"})
	_, err = service.RenderClientConfig(context.Background(), badRequest)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid profile key error = %v", err)
	}
}

func TestCreatePeerPersistsProfileAndRemoveDeletesIt(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	request, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	created, err := service.CreatePeer(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if created.GetFields()["name"].GetStringValue() != "iphone" {
		t.Fatalf("created peer = %v", created.AsMap())
	}
	profilePath := filepath.Join(opts.DataDir, "profiles", "iphone.conf")
	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("saved client profile mode = %04o, want 0600", got)
	}
	loaded, err := service.GetClientConfig(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	config := loaded.GetFields()["config"].GetStringValue()
	if !strings.Contains(config, "[Interface]") || !strings.Contains(config, "PrivateKey = ") || !strings.Contains(config, "[Peer]") {
		t.Fatalf("saved profile is incomplete: %q", config)
	}
	if err := os.Remove(profilePath); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetClientConfig(context.Background(), request); status.Code(err) != codes.Internal {
		t.Fatalf("missing saved profile error = %v", err)
	}
	if err := writeClientProfile(opts.DataDir, "iphone", config); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RemovePeer(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("profile still exists after peer removal: stat error = %v", err)
	}
}

func TestAWGBackupRestoresPeersAndPrivateProfiles(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	firstRequest, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	if _, err := service.CreatePeer(context.Background(), firstRequest); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.ExportBackup(context.Background(), &structpb.Struct{})
	if err != nil {
		t.Fatal(err)
	}
	archive := snapshot.GetFields()["data"].GetStringValue()
	secondRequest, _ := structpb.NewStruct(map[string]any{"name": "tablet"})
	if _, err := service.CreatePeer(context.Background(), secondRequest); err != nil {
		t.Fatal(err)
	}
	if len(manager.Peers()) != 2 {
		t.Fatalf("created test peers = %v", manager.Peers())
	}
	if _, err := service.RestoreBackup(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	peers := manager.Peers()
	if len(peers) != 1 || peers[0].Name != "iphone" {
		t.Fatalf("restored peers = %+v", peers)
	}
	if _, err := os.Stat(filepath.Join(opts.DataDir, "profiles", "tablet.conf")); !os.IsNotExist(err) {
		t.Fatalf("removed peer profile survived restore: %v", err)
	}
	loaded, err := service.GetClientConfig(context.Background(), firstRequest)
	if err != nil || !strings.Contains(loaded.GetFields()["config"].GetStringValue(), "PrivateKey = ") {
		t.Fatalf("restored client credential could not be delivered: response=%v error=%v", loaded, err)
	}
	invalid, _ := structpb.NewStruct(map[string]any{"data": archive + "not-base64"})
	if _, err := service.RestoreBackup(context.Background(), invalid); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid backup error = %v", err)
	}
	if len(manager.Peers()) != 1 {
		t.Fatalf("invalid backup changed peers: %+v", manager.Peers())
	}
}

func TestLoadOrCreateTokenRejectsWeakExistingToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("too-short\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateToken(path); err == nil {
		t.Fatal("weak existing token accepted")
	}
}
