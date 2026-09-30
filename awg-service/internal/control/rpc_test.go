package control

import (
	"context"
	"encoding/base64"
	"errors"
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
	if _, peers, err := manager.Status(); err != nil || peers != 0 {
		t.Fatalf("initial manager status = %d peers, %v", peers, err)
	}

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
	statusResponse = new(structpb.Struct)
	if err := connection.Invoke(authCtx, "/xrayeasy.awg.v1.Control/GetStatus", statusRequest, statusResponse); err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetFields()["protocol"].GetStringValue() != "AmneziaWG" || statusResponse.GetFields()["running"].GetBoolValue() != true {
		t.Fatalf("unexpected status response: %v", statusResponse.AsMap())
	}
	listResponse := new(structpb.Struct)
	if err := connection.Invoke(authCtx, "/xrayeasy.awg.v1.Control/ListPeers", statusRequest, listResponse); err != nil {
		t.Fatal(err)
	}
	if len(listResponse.GetFields()["peers"].GetListValue().GetValues()) != 0 {
		t.Fatalf("new device already has peers: %v", listResponse.AsMap())
	}
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
	engine.snapshot = "public_key=" + clientPublicKey + "\nendpoint=203.0.113.9:4567\nlast_handshake_time_sec=1790798400\nlast_handshake_time_nsec=0\nrx_bytes=11\ntx_bytes=22\n"
	statsRequest, _ := structpb.NewStruct(nil)
	statsResponse := new(structpb.Struct)
	if err := connection.Invoke(ctx, "/xrayeasy.awg.v1.Control/GetPeerStats", statsRequest, statsResponse); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated peer stats error = %v", err)
	}
	statsResponse = new(structpb.Struct)
	if err := connection.Invoke(authCtx, "/xrayeasy.awg.v1.Control/GetPeerStats", statsRequest, statsResponse); err != nil {
		t.Fatal(err)
	}
	entries := statsResponse.GetFields()["peers"].GetListValue().GetValues()
	if len(entries) != 1 || entries[0].GetStructValue().GetFields()["name"].GetStringValue() != "ios" || entries[0].GetStructValue().GetFields()["uploadBytes"].GetStringValue() != "11" {
		t.Fatalf("peer stats response = %v", statsResponse.AsMap())
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

func TestRPCValidationAndErrorMapping(t *testing.T) {
	for _, test := range []struct {
		name string
		call func() error
		want codes.Code
	}{
		{name: "not found", call: func() error { return mapError(ErrNotFound) }, want: codes.NotFound},
		{name: "already exists", call: func() error { return mapError(ErrAlreadyExists) }, want: codes.AlreadyExists},
		{name: "invalid", call: func() error { return mapError(ErrInvalid) }, want: codes.InvalidArgument},
		{name: "internal", call: func() error { return mapError(os.ErrPermission) }, want: codes.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := status.Code(test.call()); got != test.want {
				t.Fatalf("mapped status = %s, want %s", got, test.want)
			}
		})
	}
	for _, request := range []*structpb.Struct{nil, {Fields: map[string]*structpb.Value{"name": structpb.NewNumberValue(3)}}, {Fields: map[string]*structpb.Value{"name": structpb.NewStringValue("")}}} {
		if _, err := stringField(request, "name"); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid string field error = %v", err)
		}
	}
	if _, err := response(map[string]any{"invalid": make(chan int)}); err == nil {
		t.Fatal("response accepted an unsupported protobuf value")
	}
}

func TestServiceStatusListsPeersAndRejectsInvalidRequests(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	statusResponse, err := service.GetStatus(context.Background(), &structpb.Struct{})
	if err != nil || statusResponse.GetFields()["publicPort"].GetNumberValue() != float64(opts.PublicPort) {
		t.Fatalf("service status = %v, %v", statusResponse, err)
	}
	peers, err := service.ListPeers(context.Background(), &structpb.Struct{})
	if err != nil || len(peers.GetFields()["peers"].GetListValue().GetValues()) != 0 {
		t.Fatalf("empty peer list = %v, %v", peers, err)
	}
	missing := &structpb.Struct{}
	if _, err := service.AddPeer(context.Background(), missing); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AddPeer missing name = %v", err)
	}
	request, _ := structpb.NewStruct(map[string]any{"name": "../outside", "publicKey": "invalid"})
	if _, err := service.AddPeer(context.Background(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("AddPeer invalid name = %v", err)
	}
	if _, err := service.GetClientConfig(context.Background(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("GetClientConfig invalid name = %v", err)
	}
	validName, _ := structpb.NewStruct(map[string]any{"name": "missing"})
	if _, err := service.GetClientConfig(context.Background(), validName); status.Code(err) != codes.NotFound {
		t.Fatalf("GetClientConfig inactive peer = %v", err)
	}
}

func TestServiceMapsClosedManagerStatusAndTelemetryFailures(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(manager, opts)
	manager.Close()
	if _, err := service.GetStatus(context.Background(), &structpb.Struct{}); status.Code(err) != codes.Internal {
		t.Fatalf("GetStatus with a closed manager = %v", err)
	}
	if _, err := service.GetPeerStats(context.Background(), &structpb.Struct{}); status.Code(err) != codes.Internal {
		t.Fatalf("GetPeerStats with a closed manager = %v", err)
	}
}

func TestServiceCleansUpPeerWhenPrivateProfileCannotBeWritten(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	blockedDataDir := filepath.Join(t.TempDir(), "data-file")
	if err := os.WriteFile(blockedDataDir, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := NewService(manager, opts)
	service.options.DataDir = blockedDataDir
	request, _ := structpb.NewStruct(map[string]any{"name": "phone"})
	if _, err := service.CreatePeer(context.Background(), request); status.Code(err) != codes.Internal {
		t.Fatalf("CreatePeer profile write failure = %v", err)
	}
	if len(manager.Peers()) != 0 {
		t.Fatalf("failed peer profile persisted peer state: %+v", manager.Peers())
	}
}

func TestServicePeerMethodsMapValidationAndRemovalFailures(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	ctx := context.Background()

	if _, err := service.CreatePeer(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreatePeer without request = %v", err)
	}
	invalidName, _ := structpb.NewStruct(map[string]any{"name": "bad_name"})
	if _, err := service.CreatePeer(ctx, invalidName); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("CreatePeer with invalid name = %v", err)
	}
	if _, err := service.RemovePeer(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("RemovePeer without request = %v", err)
	}
	missing, _ := structpb.NewStruct(map[string]any{"name": "missing"})
	if _, err := service.RemovePeer(ctx, missing); status.Code(err) != codes.NotFound {
		t.Fatalf("RemovePeer for unknown peer = %v", err)
	}

	create, _ := structpb.NewStruct(map[string]any{"name": "phone"})
	if _, err := service.CreatePeer(ctx, create); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(opts.DataDir, "profiles", "phone.conf")
	if err := os.Remove(profilePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(profilePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profilePath, "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RemovePeer(ctx, create); status.Code(err) != codes.Internal {
		t.Fatalf("RemovePeer when the saved profile cannot be removed = %v", err)
	}
	if len(manager.Peers()) != 0 {
		t.Fatalf("failed local profile cleanup left peer active: %+v", manager.Peers())
	}
}

func TestBackupRPCRejectsInvalidPayloadsAndUnavailableManager(t *testing.T) {
	service := NewService(nil, Options{DataDir: t.TempDir()})
	if _, err := service.ExportBackup(context.Background(), nil); status.Code(err) != codes.Internal {
		t.Fatalf("ExportBackup without manager = %v", err)
	}
	for _, request := range []*structpb.Struct{
		nil,
		{Fields: map[string]*structpb.Value{"data": structpb.NewStringValue("not-base64")}},
		{Fields: map[string]*structpb.Value{"data": structpb.NewStringValue(strings.Repeat("A", base64.StdEncoding.EncodedLen(maxAWGBackupSize)+1))}},
		{Fields: map[string]*structpb.Value{"data": structpb.NewStringValue(base64.StdEncoding.EncodeToString([]byte("not a gzip archive")))}},
	} {
		if _, err := service.RestoreBackup(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Errorf("RestoreBackup(%v) error = %v", request, err)
		}
	}
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	active := NewService(manager, opts)
	invalidArchive, _ := structpb.NewStruct(map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("not a gzip archive"))})
	if _, err := active.RestoreBackup(context.Background(), invalidArchive); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "open archive") {
		t.Fatalf("RestoreBackup invalid archive = %v", err)
	}
}

func TestClientProfileHelpersValidatePathsFilesAndLifecycle(t *testing.T) {
	if _, err := clientProfilePath("", "phone"); err == nil {
		t.Fatal("profile path accepted an empty data directory")
	}
	if _, err := clientProfilePath(t.TempDir(), "../outside"); err == nil {
		t.Fatal("profile path accepted an unsafe peer name")
	}
	root := t.TempDir()
	if _, err := readClientProfile(root, "missing"); !os.IsNotExist(err) {
		t.Fatalf("missing profile error = %v", err)
	}
	blockedRoot := filepath.Join(t.TempDir(), "data-file")
	if err := os.WriteFile(blockedRoot, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClientProfile(blockedRoot, "phone", "profile"); err == nil {
		t.Fatal("writeClientProfile accepted a file as its data directory")
	}
	profileDir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(profileDir, "phone.conf")
	if err := os.WriteFile(profilePath, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readClientProfile(root, "phone"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed profile error = %v", err)
	}
	if err := os.WriteFile(profilePath, []byte("[Interface]\nPrivateKey = key\n[Peer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if config, err := readClientProfile(root, "phone"); err != nil || !strings.Contains(config, "[Peer]") {
		t.Fatalf("valid profile read = %q, %v", config, err)
	}
	if err := removeClientProfile(root, "../outside"); err == nil {
		t.Fatal("profile removal accepted a path traversal name")
	}
	if err := removeClientProfile(root, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := removeClientProfile(root, "phone"); err != nil {
		t.Fatalf("removing an already-absent profile = %v", err)
	}
	if err := os.Mkdir(profilePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeClientProfile(root, "phone", "replacement"); err == nil {
		t.Fatal("writeClientProfile replaced a directory instead of reporting failure")
	}
	if _, err := readClientProfile(root, "phone"); err == nil {
		t.Fatal("profile directory was accepted as a regular profile file")
	}
}

type faultSavedProfileFile struct {
	*os.File
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
}

func (f *faultSavedProfileFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *faultSavedProfileFile) WriteString(value string) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.WriteString(value)
}

func (f *faultSavedProfileFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultSavedProfileFile) Close() error {
	actualErr := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return actualErr
}

func TestWriteClientProfileCleansTemporaryFileAfterIOFailures(t *testing.T) {
	chmodErr := errors.New("injected chmod failure")
	writeErr := errors.New("injected write failure")
	syncErr := errors.New("injected sync failure")
	closeErr := errors.New("injected close failure")
	for _, test := range []struct {
		name string
		file *faultSavedProfileFile
		want string
	}{
		{name: "chmod", file: &faultSavedProfileFile{chmodErr: chmodErr}, want: "injected chmod failure"},
		{name: "write", file: &faultSavedProfileFile{writeErr: writeErr}, want: "injected write failure"},
		{name: "sync", file: &faultSavedProfileFile{syncErr: syncErr}, want: "injected sync failure"},
		{name: "close", file: &faultSavedProfileFile{closeErr: closeErr}, want: "injected close failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			profiles := filepath.Join(root, "profiles")
			if err := os.Mkdir(profiles, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(profiles, "phone.conf")
			err := writeClientProfileWithPath(path, profiles, "private profile", func(dir, pattern string) (savedProfileFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				test.file.File = file
				return test.file, nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("writeClientProfileWithPath error = %v, want %q", err, test.want)
			}
			entries, err := os.ReadDir(profiles)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed saved profile write left temporary files: %v, %v", entries, err)
			}
		})
	}
	if err := writeClientProfileWithPath(filepath.Join(t.TempDir(), "phone.conf"), t.TempDir(), "profile", func(string, string) (savedProfileFile, error) {
		return nil, errors.New("temporary profile unavailable")
	}); err == nil || !strings.Contains(err.Error(), "temporary profile unavailable") {
		t.Fatalf("writeClientProfile temp creation error = %v", err)
	}
}

func TestServiceGetClientConfigRejectsMalformedSavedKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("phone", publicKey); err != nil {
		t.Fatal(err)
	}
	if err := writeClientProfile(opts.DataDir, "phone", "[Interface]\nPrivateKey = broken\n[Peer]\n"); err != nil {
		t.Fatal(err)
	}
	request, _ := structpb.NewStruct(map[string]any{"name": "phone"})
	if _, err := NewService(manager, opts).GetClientConfig(context.Background(), request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed saved private key error = %v", err)
	}
}

func TestServiceMapsClosedManagerStatusAndPeerStatsFailures(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	service := NewService(manager, opts)
	if _, err := service.GetStatus(context.Background(), nil); status.Code(err) != codes.Internal {
		t.Fatalf("closed manager GetStatus error = %v", err)
	}
	if _, err := service.GetPeerStats(context.Background(), nil); status.Code(err) != codes.Internal {
		t.Fatalf("closed manager GetPeerStats error = %v", err)
	}
}

func TestServiceCreatePeerRemovesRuntimePeerWhenProfileCannotBePersisted(t *testing.T) {
	opts := testOptions(t)
	if err := os.WriteFile(filepath.Join(opts.DataDir, "profiles"), []byte("blocking file"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := NewService(manager, opts)
	request, err := structpb.NewStruct(map[string]any{"name": "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(context.Background(), request); status.Code(err) != codes.Internal {
		t.Fatalf("CreatePeer profile persistence error = %v", err)
	}
	if peers := manager.Peers(); len(peers) != 0 {
		t.Fatalf("failed profile persistence left an active peer: %+v", peers)
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
