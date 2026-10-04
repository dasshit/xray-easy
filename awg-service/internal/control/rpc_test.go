package control

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestEnsureIncomingTraceReturnsRandomSourceFailure(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = unavailableRandomSource{}
	t.Cleanup(func() { cryptorand.Reader = original })
	for _, ctx := range []context.Context{
		context.Background(),
		metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "abcdef0123456789abcdef0123456789")),
	} {
		if _, _, _, _, err := ensureIncomingTrace(ctx); err == nil || !strings.Contains(err.Error(), "random source unavailable") {
			t.Fatalf("ensureIncomingTrace() error = %v; want random-source error", err)
		}
	}
}

func TestLoggingInterceptorsRejectUnavailableRequestIDEntropy(t *testing.T) {
	original := cryptorand.Reader
	cryptorand.Reader = unavailableRandomSource{}
	t.Cleanup(func() { cryptorand.Reader = original })

	called := false
	response, err := LoggingInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Unary"}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	if status.Code(err) != codes.Internal || response != nil || called {
		t.Fatalf("unary logging interceptor = (%v, %v), handler called=%t; want internal error before handler", response, err, called)
	}

	stream := &capturePeerStatsStream{ctx: context.Background(), updates: make(chan *awgapi.PeerStatsUpdate, 1)}
	err = LoggingStreamInterceptor()(nil, stream, &grpc.StreamServerInfo{FullMethod: "/test/Stream"}, func(any, grpc.ServerStream) error {
		called = true
		return nil
	})
	if status.Code(err) != codes.Internal || called {
		t.Fatalf("stream logging interceptor = %v, handler called=%t; want internal error before handler", err, called)
	}
}

func TestLoggingInterceptorCorrelatesWithoutLoggingPayloads(t *testing.T) {
	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	requestID := "abcdef0123456789abcdef0123456789"
	operationID := "0123456789abcdef0123456789abcdef"
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", requestID, "x-controller-operation-id", operationID, "x-controller-attempt", "4", "x-controller-state-revision", "9"))
	secret := "private-key-never-log"
	response, err := LoggingInterceptor()(ctx, map[string]string{"secret": secret}, &grpc.UnaryServerInfo{FullMethod: "/test/Operation"}, func(callContext context.Context, _ any) (any, error) {
		if got := OperationID(callContext); got != operationID {
			t.Errorf("operation ID in handler context = %q, want %q", got, operationID)
		}
		return "ok", errors.New(secret)
	})
	if response != "ok" || err == nil {
		t.Fatalf("interceptor result = %v, %v", response, err)
	}
	for _, expected := range []string{requestID, operationID, `"retry_attempt":4`, `"state_revision":9`, "/test/Operation", "failure", "Unknown"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("log %q does not contain %q", output.String(), expected)
		}
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("log contains request/error secret: %s", output.String())
	}
	output.Reset()
	_, err = LoggingInterceptor()(metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "bad")), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Health"}, func(context.Context, any) (any, error) { return nil, nil })
	if err != nil || !strings.Contains(output.String(), "request_id") || strings.Contains(output.String(), "request_id=bad") {
		t.Fatalf("invalid incoming ID was not replaced safely: %s, %v", output.String(), err)
	}
	output.Reset()
	validID := "abcdef0123456789abcdef0123456789"
	_, err = LoggingInterceptor()(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-request-id", validID, "x-controller-operation-id", "invalid", "x-controller-attempt", "-2", "x-controller-state-revision", "0",
	)), nil, &grpc.UnaryServerInfo{FullMethod: "/test/Mutation"}, func(ctx context.Context, _ any) (any, error) {
		if OperationID(ctx) == "invalid" || StateRevision(ctx) != 0 {
			t.Errorf("invalid trace metadata was retained: operation=%q revision=%d", OperationID(ctx), StateRevision(ctx))
		}
		return nil, nil
	})
	if err != nil || !strings.Contains(output.String(), `"retry_attempt":1`) || strings.Contains(output.String(), `"state_revision"`) {
		t.Fatalf("invalid trace values were not normalized: %s, %v", output.String(), err)
	}
}

func TestStreamInterceptorsAuthenticateAndLogLifecycle(t *testing.T) {
	token := "stream-test-token"
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	stream := &capturePeerStatsStream{ctx: ctx, updates: make(chan *awgapi.PeerStatsUpdate, 1)}
	called := false
	info := &grpc.StreamServerInfo{FullMethod: "/xrayeasy.awg.v1.Control/WatchPeerStats"}
	err := AuthStreamInterceptor(token)(nil, stream, info, func(_ any, _ grpc.ServerStream) error {
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("authenticated stream interceptor = %v, called %v", err, called)
	}
	called = false
	unauthenticated := &capturePeerStatsStream{ctx: context.Background(), updates: make(chan *awgapi.PeerStatsUpdate, 1)}
	err = AuthStreamInterceptor(token)(nil, unauthenticated, info, func(_ any, _ grpc.ServerStream) error {
		called = true
		return nil
	})
	if status.Code(err) != codes.Unauthenticated || called {
		t.Fatalf("unauthenticated stream interceptor = %v, called %v", err, called)
	}

	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	err = LoggingStreamInterceptor()(nil, stream, info, func(_ any, wrapped grpc.ServerStream) error {
		if OperationID(wrapped.Context()) == "" {
			t.Error("stream logging interceptor did not attach an operation ID")
		}
		return context.Canceled
	})
	if err != context.Canceled || !strings.Contains(output.String(), `"result":"canceled"`) || !strings.Contains(output.String(), info.FullMethod) {
		t.Fatalf("stream lifecycle log = %s, error %v", output.String(), err)
	}
	if strings.Contains(output.String(), token) {
		t.Fatalf("stream log contains bearer token: %s", output.String())
	}
	output.Reset()
	err = LoggingStreamInterceptor()(nil, stream, info, func(_ any, _ grpc.ServerStream) error { return nil })
	if err != nil || !strings.Contains(output.String(), `"result":"success"`) {
		t.Fatalf("successful stream lifecycle log = %s, error %v", output.String(), err)
	}
}

func TestAuthInterceptorRejectsDuplicateOrMalformedAuthorization(t *testing.T) {
	token := "unary-test-token"
	info := &grpc.UnaryServerInfo{FullMethod: "/xrayeasy.awg.v1.Control/GetStatus"}
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	for name, ctx := range map[string]context.Context{
		"duplicate values": metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", "Bearer "+token, "authorization", "Bearer "+token,
		)),
		"wrong scheme": metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic "+token)),
		"empty bearer": metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer ")),
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			response, err := AuthInterceptor(token)(ctx, nil, info, func(callContext context.Context, request any) (any, error) {
				called = true
				return handler(callContext, request)
			})
			if status.Code(err) != codes.Unauthenticated || called || response != nil {
				t.Fatalf("interceptor accepted invalid authorization: response=%v error=%v called=%v", response, err, called)
			}
		})
	}
}

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
	Register(server, newStructService(manager, opts).Service)
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

	client := awgapi.NewControlClient(connection)
	statusRequest := &emptypb.Empty{}
	_, err = client.GetStatus(ctx, statusRequest)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated status error = %v", err)
	}

	authCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer correct-test-token")
	statusResponse, err := client.GetStatus(authCtx, statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetProtocol() != "AmneziaWG" || !statusResponse.GetRunning() {
		t.Fatalf("unexpected status response: %v", statusResponse)
	}
	listResponse, err := client.ListPeers(authCtx, statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	if len(listResponse.GetPeers()) != 0 {
		t.Fatalf("new device already has peers: %v", listResponse)
	}
	_, clientPublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peerResponse, err := client.AddPeer(authCtx, &awgapi.AddPeerRequest{Name: "ios", PublicKey: clientPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if peerResponse.GetIpv4() != "10.88.0.2" {
		t.Fatalf("unexpected allocated peer: %v", peerResponse)
	}
	if engine.ups != 1 {
		t.Fatalf("adding peer restarted the engine %d times", engine.ups-1)
	}
	clientPublicKeyBytes, err := decodeKey(clientPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	engine.snapshot = "public_key=" + hex.EncodeToString(clientPublicKeyBytes) + "\nendpoint=203.0.113.9:4567\nlast_handshake_time_sec=1790798400\nlast_handshake_time_nsec=0\nrx_bytes=11\ntx_bytes=22\n"
	statsRequest := &emptypb.Empty{}
	_, err = client.GetPeerStats(ctx, statsRequest)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated peer stats error = %v", err)
	}
	statsResponse, err := client.GetPeerStats(authCtx, statsRequest)
	if err != nil {
		t.Fatal(err)
	}
	entries := statsResponse.GetPeers()
	if len(entries) != 1 || entries[0].GetName() != "ios" || entries[0].GetUploadBytes() != 11 {
		t.Fatalf("peer stats response = %v", statsResponse)
	}

	_, err = client.RemovePeer(authCtx, &awgapi.RemovePeerRequest{Name: "ios"})
	if err != nil {
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
		{name: "operation conflict", call: func() error { return mapError(ErrOperationConflict) }, want: codes.Aborted},
		{name: "operation completed", call: func() error { return mapError(ErrOperationCompleted) }, want: codes.FailedPrecondition},
		{name: "invalid", call: func() error { return mapError(ErrInvalid) }, want: codes.InvalidArgument},
		{name: "internal", call: func() error { return mapError(os.ErrPermission) }, want: codes.Internal},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := status.Code(test.call()); got != test.want {
				t.Fatalf("mapped status = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGeneratedAWGServiceRegistersTypedMethods(t *testing.T) {
	server := grpc.NewServer()
	Register(server, NewService(nil, Options{}))
	info := server.GetServiceInfo()["xrayeasy.awg.v1.Control"]
	if len(info.Methods) != 13 {
		t.Fatalf("registered methods = %d, want 13", len(info.Methods))
	}
	for _, method := range info.Methods {
		if method.Name == "WatchPeerStats" && !method.IsServerStream {
			t.Fatal("WatchPeerStats was registered as a unary RPC")
		}
	}
}

func TestServiceStatusListsPeersAndRejectsInvalidRequests(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := newStructService(manager, opts)
	statusResponse, err := service.GetStatus(context.Background(), &structpb.Struct{})
	if err != nil || statusResponse.GetFields()["publicPort"].GetNumberValue() != float64(opts.PublicPort) {
		t.Fatalf("service status = %v, %v", statusResponse, err)
	}
	peers, err := service.ListPeers(context.Background(), &structpb.Struct{})
	if err != nil || len(peers.GetFields()["peers"].GetListValue().GetValues()) != 0 {
		t.Fatalf("empty peer list = %v, %v", peers, err)
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("listed", publicKey); err != nil {
		t.Fatal(err)
	}
	typedPeers, err := service.Service.ListPeers(context.Background(), &emptypb.Empty{})
	if err != nil || len(typedPeers.GetPeers()) != 1 || typedPeers.GetPeers()[0].GetName() != "listed" {
		t.Fatalf("typed peer list = %v, %v", typedPeers, err)
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
	service := newStructService(manager, opts)
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
	service := newStructService(manager, opts)
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
	service := newStructService(manager, opts)
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
	service := newStructService(nil, Options{DataDir: t.TempDir()})
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
	active := newStructService(manager, opts)
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
	if _, err := newStructService(manager, opts).GetClientConfig(context.Background(), request); status.Code(err) != codes.InvalidArgument {
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
	service := newStructService(manager, opts)
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
	service := newStructService(manager, opts)
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
	service := newStructService(manager, opts)
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
	service := newStructService(manager, opts)
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

func TestCreatePeerRetryReturnsSamePersistedPeerAndProfile(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	service := newStructService(manager, opts)
	operationID := "abcdef0123456789abcdef0123456789"
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	request, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	first, err := service.CreatePeer(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	firstPeer := first.AsMap()
	firstProfile, err := os.ReadFile(filepath.Join(opts.DataDir, "profiles", "iphone.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(ctx, request); err != nil {
		t.Fatalf("retry CreatePeer() = %v", err)
	}
	if got := len(manager.Peers()); got != 1 {
		t.Fatalf("peer count after retry = %d, want one", got)
	}
	secondProfile, err := os.ReadFile(filepath.Join(opts.DataDir, "profiles", "iphone.conf"))
	if err != nil || !bytes.Equal(firstProfile, secondProfile) {
		t.Fatalf("profile changed after retry: err=%v", err)
	}
	manager.Close()

	restarted, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	service = newStructService(restarted, opts)
	second, err := service.CreatePeer(ctx, request)
	if err != nil {
		t.Fatalf("retry after service restart = %v", err)
	}
	if !reflect.DeepEqual(second.AsMap(), firstPeer) || len(restarted.Peers()) != 1 {
		t.Fatalf("retry after restart changed peer: first=%v second=%v peers=%+v", firstPeer, second.AsMap(), restarted.Peers())
	}
	removeID := "fedcba9876543210fedcba9876543210"
	removeCtx := context.WithValue(context.Background(), operationIDKey, removeID)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.RemovePeer(removeCtx, request); err != nil {
			t.Fatalf("RemovePeer retry %d = %v", attempt, err)
		}
	}
	if len(restarted.Peers()) != 0 {
		t.Fatalf("remove retries left peers: %+v", restarted.Peers())
	}
	if _, err := service.CreatePeer(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("replayed create after revoke = %v", err)
	}
	if len(restarted.Peers()) != 0 {
		t.Fatalf("replayed create resurrected a revoked peer: %+v", restarted.Peers())
	}
}

func TestCreatePeerRejectsMalformedIntentAndReusedOperationIDs(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := newStructService(manager, opts)
	createID := "abcdef0123456789abcdef0123456789"
	createContext := context.WithValue(context.Background(), operationIDKey, createID)
	createRequest, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	if _, err := service.CreatePeer(createContext, createRequest); err != nil {
		t.Fatal(err)
	}
	changedName, _ := structpb.NewStruct(map[string]any{"name": "ipad"})
	if _, err := service.CreatePeer(createContext, changedName); status.Code(err) != codes.Aborted {
		t.Fatalf("create retry with a different peer name = %v", err)
	}

	removeID := "fedcba9876543210fedcba9876543210"
	removeContext := context.WithValue(context.Background(), operationIDKey, removeID)
	missingRequest, _ := structpb.NewStruct(map[string]any{"name": "missing"})
	if _, err := service.RemovePeer(removeContext, missingRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(removeContext, missingRequest); status.Code(err) != codes.Aborted {
		t.Fatalf("create reusing a completed remove operation = %v", err)
	}

	malformedID := "0123456789abcdef0123456789abcdef"
	malformedPath := filepath.Join(opts.DataDir, "operations", malformedID+".key")
	if err := os.MkdirAll(filepath.Dir(malformedPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedPath, []byte("not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	malformedContext := context.WithValue(context.Background(), operationIDKey, malformedID)
	if _, err := service.CreatePeer(malformedContext, changedName); status.Code(err) != codes.Internal {
		t.Fatalf("create with a malformed persisted intent = %v", err)
	}
	if _, err := service.CreatePeer(context.Background(), createRequest); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("create using an existing peer name = %v", err)
	}
}

func TestCreatePeerRecoversInterruptedProfileFromOperationKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	operationID := "0123456789abcdef0123456789abcdef"
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(opts.DataDir, operationID, privateKey); err != nil {
		t.Fatal(err)
	}
	orphanID := "fedcba9876543210fedcba9876543210"
	if err := writePendingOperationKey(opts.DataDir, orphanID, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.AddPeerForOperation("iphone", publicKey, operationID); err != nil {
		t.Fatal(err)
	}
	service := newStructService(manager, opts)
	if _, err := os.Stat(filepath.Join(opts.DataDir, "operations", orphanID+".key")); !os.IsNotExist(err) {
		t.Fatalf("orphan pending key survived service initialization: %v", err)
	}
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	request, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	if _, err := service.CreatePeer(ctx, request); err != nil {
		t.Fatalf("CreatePeer recovery = %v", err)
	}
	profile, err := readClientProfile(opts.DataDir, "iphone")
	if err != nil || !strings.Contains(profile, "PrivateKey = "+privateKey) {
		t.Fatalf("recovered profile did not retain original key: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(opts.DataDir, "operations", operationID+".key")); !os.IsNotExist(err) {
		t.Fatalf("completed operation key was not removed: %v", err)
	}
}

func TestCreatePeerRetriesAfterProfilePersistenceFailure(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	profileDirectory := filepath.Join(opts.DataDir, "profiles")
	if err := os.WriteFile(profileDirectory, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	service := newStructService(manager, opts)
	operationID := "abcdef0123456789abcdef0123456789"
	ctx := context.WithValue(context.Background(), operationIDKey, operationID)
	request, _ := structpb.NewStruct(map[string]any{"name": "iphone"})
	if _, err := service.CreatePeer(ctx, request); status.Code(err) != codes.Internal {
		t.Fatalf("CreatePeer with blocked profile path = %v", err)
	}
	if len(manager.Peers()) != 1 {
		t.Fatalf("interrupted peer creation was not persisted: %+v", manager.Peers())
	}
	pendingPath := filepath.Join(opts.DataDir, "operations", operationID+".key")
	privateKey, err := readPendingOperationKey(opts.DataDir, operationID)
	if err != nil {
		t.Fatalf("read pending key after profile failure = %v", err)
	}
	if err := os.Remove(profileDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(profileDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePeer(ctx, request); err != nil {
		t.Fatalf("CreatePeer retry after fixing storage = %v", err)
	}
	profile, err := readClientProfile(opts.DataDir, "iphone")
	if err != nil || !strings.Contains(profile, "PrivateKey = "+privateKey) {
		t.Fatalf("recovered profile key mismatch: err=%v", err)
	}
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("completed retry left pending key: %v", err)
	}
}

func TestPendingOperationKeyFilesAreValidatedAndCleaned(t *testing.T) {
	dataDir := t.TempDir()
	operationID := "abcdef0123456789abcdef0123456789"
	privateKey, otherKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pendingOperationKeyPath(dataDir, "bad-id"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid operation key path = %v", err)
	}
	if _, err := pendingOperationKeyPath("", operationID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty data directory path = %v", err)
	}
	if _, err := readPendingOperationKey(dataDir, operationID); !os.IsNotExist(err) {
		t.Fatalf("read missing operation key = %v", err)
	}
	if err := removePendingOperationKey(dataDir, "bad-id"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("remove invalid operation key = %v", err)
	}
	blocked := filepath.Join(t.TempDir(), "data-file")
	if err := os.WriteFile(blocked, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(blocked, operationID, privateKey); err == nil {
		t.Fatal("pending key write succeeded below a regular file")
	}
	if err := writePendingOperationKey(dataDir, "bad-id", privateKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pending key write with invalid operation ID = %v", err)
	}
	if err := writePendingOperationKey("", operationID, privateKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pending key write with empty data directory = %v", err)
	}
	if err := writePendingOperationKey(dataDir, operationID, privateKey); err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(dataDir, operationID, privateKey); err != nil {
		t.Fatalf("idempotent key write = %v", err)
	}
	if err := writePendingOperationKey(dataDir, operationID, otherKey); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("same operation with another key = %v", err)
	}
	path := filepath.Join(dataDir, "operations", operationID+".key")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPendingOperationKey(dataDir, operationID); err == nil {
		t.Fatal("read accepted an overly permissive pending key file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPendingOperationKey(dataDir, operationID); err == nil {
		t.Fatal("read accepted a malformed private key")
	}
	if err := removePendingOperationKey(dataDir, operationID); err != nil {
		t.Fatal(err)
	}
	if err := removePendingOperationKey(dataDir, operationID); err != nil {
		t.Fatalf("repeat pending key removal = %v", err)
	}
	badOperationID := "11111111222222223333333344444444"
	badOperationPath := filepath.Join(dataDir, "operations", badOperationID+".key")
	if err := os.WriteFile(badOperationPath, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePendingOperationKey(dataDir, badOperationID, privateKey); err == nil {
		t.Fatal("write replaced an existing malformed operation key")
	}
	if err := os.Remove(badOperationPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(badOperationPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badOperationPath, "child"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPendingOperationKey(dataDir, badOperationID); err == nil {
		t.Fatal("read accepted a directory as a pending key file")
	}
	if err := removePendingOperationKey(dataDir, badOperationID); err == nil {
		t.Fatal("remove unexpectedly removed a pending-key directory")
	}
}

type pendingOperationFileStub struct {
	writeErr error
	syncErr  error
	closeErr error
	closed   int
}

func (f *pendingOperationFileStub) WriteString(string) (int, error) { return 0, f.writeErr }
func (f *pendingOperationFileStub) Sync() error                     { return f.syncErr }
func (f *pendingOperationFileStub) Close() error {
	f.closed++
	return f.closeErr
}

func TestPersistPendingOperationKeyCleansFailedWritesAndReturnsCloseFailure(t *testing.T) {
	for _, testcase := range []struct {
		name string
		file pendingOperationFileStub
		want string
	}{
		{name: "write error", file: pendingOperationFileStub{writeErr: errors.New("write failed")}, want: "write failed"},
		{name: "sync error", file: pendingOperationFileStub{syncErr: errors.New("sync failed")}, want: "sync failed"},
		{name: "close error", file: pendingOperationFileStub{closeErr: errors.New("close failed")}, want: "close failed"},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			removed := ""
			file := testcase.file
			err := persistPendingOperationKey(&file, "pending.key", "private-key", func(path string) error {
				removed = path
				return nil
			})
			if err == nil || err.Error() != testcase.want {
				t.Fatalf("persistPendingOperationKey() error = %v, want %q", err, testcase.want)
			}
			if testcase.name == "close error" {
				if removed != "" || file.closed != 1 {
					t.Fatalf("successful write cleanup/close = %q/%d", removed, file.closed)
				}
			} else if removed != "pending.key" || file.closed != 1 {
				t.Fatalf("failed write cleanup/close = %q/%d", removed, file.closed)
			}
		})
	}
}

func TestGRPCPeerMutationsReplaySafelyAcrossServiceRestart(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	newConnection := func(service *Service) (*grpc.Server, *bufconn.Listener, *grpc.ClientConn) {
		t.Helper()
		listener := bufconn.Listen(1 << 20)
		server := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggingInterceptor(), AuthInterceptor("test-token")))
		Register(server, service)
		go func() { _ = server.Serve(listener) }()
		connection, err := grpc.NewClient("passthrough:///awg-operation-replay", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			server.Stop()
			_ = listener.Close()
			t.Fatal(err)
		}
		return server, listener, connection
	}
	server, listener, connection := newConnection(newStructService(manager, opts).Service)
	base := context.Background()
	trace := func(operationID string) context.Context {
		return metadata.NewOutgoingContext(base, metadata.Pairs(
			"authorization", "Bearer test-token", "x-request-id", "abcdef0123456789abcdef0123456789",
			"x-controller-operation-id", operationID, "x-controller-attempt", "2", "x-controller-state-revision", "17",
		))
	}
	createID := "0123456789abcdef0123456789abcdef"
	createRequest := &awgapi.CreatePeerRequest{Name: "iphone"}
	lossyConnection := &loseFirstGRPCResponse{ClientConnInterface: connection, method: "/xrayeasy.awg.v1.Control/CreatePeer"}
	if err := lossyConnection.Invoke(trace(createID), "/xrayeasy.awg.v1.Control/CreatePeer", createRequest, new(awgapi.Peer)); status.Code(err) != codes.Unavailable {
		t.Fatalf("CreatePeer response-loss attempt = %v, want Unavailable", err)
	}
	server.Stop()
	_ = connection.Close()
	_ = listener.Close()
	manager.Close()

	restarted, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	manager = restarted
	server, listener, connection = newConnection(newStructService(manager, opts).Service)
	var firstCreate map[string]any
	for attempt := 0; attempt < 2; attempt++ {
		response := new(awgapi.Peer)
		err := connection.Invoke(trace(createID), "/xrayeasy.awg.v1.Control/CreatePeer", createRequest, response)
		if err != nil {
			t.Fatalf("CreatePeer attempt %d = %v", attempt, err)
		}
		if attempt == 0 {
			firstCreate = map[string]any{"peer": response.String()}
		} else if !reflect.DeepEqual(firstCreate, map[string]any{"peer": response.String()}) {
			t.Fatalf("create retry changed peer: first=%v second=%v", firstCreate, response)
		}
	}
	if len(manager.Peers()) != 1 {
		t.Fatalf("create retry produced %d peers", len(manager.Peers()))
	}
	removeID := "fedcba9876543210fedcba9876543210"
	removeRequest := &awgapi.RemovePeerRequest{Name: "iphone"}
	for attempt := 0; attempt < 2; attempt++ {
		if err := connection.Invoke(trace(removeID), "/xrayeasy.awg.v1.Control/RemovePeer", removeRequest, new(awgapi.RemovePeerResponse)); err != nil {
			t.Fatalf("RemovePeer attempt %d = %v", attempt, err)
		}
	}
	if len(manager.Peers()) != 0 {
		t.Fatalf("remove retry left peers: %+v", manager.Peers())
	}
	server.Stop()
	_ = connection.Close()
	_ = listener.Close()
	manager.Close()

	server.Stop()
	_ = connection.Close()
	_ = listener.Close()
	manager.Close()
	afterRestart, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer afterRestart.Close()
	server, listener, connection = newConnection(newStructService(afterRestart, opts).Service)
	defer server.Stop()
	defer connection.Close()
	defer listener.Close()
	newCreateID := "11111111111111111111111111111111"
	newRequest := &awgapi.CreatePeerRequest{Name: "iphone"}
	if err := connection.Invoke(trace(newCreateID), "/xrayeasy.awg.v1.Control/CreatePeer", newRequest, new(awgapi.Peer)); err != nil {
		t.Fatalf("create replacement peer after restart = %v", err)
	}
	if err := connection.Invoke(trace(removeID), "/xrayeasy.awg.v1.Control/RemovePeer", removeRequest, new(awgapi.RemovePeerResponse)); err != nil {
		t.Fatalf("replay old revoke after restart = %v", err)
	}
	if len(afterRestart.Peers()) != 1 || afterRestart.Peers()[0].OperationID != newCreateID {
		t.Fatalf("old revoke removed a replacement peer: %+v", afterRestart.Peers())
	}
}

type loseFirstGRPCResponse struct {
	grpc.ClientConnInterface
	method string
	lost   bool
}

func (c *loseFirstGRPCResponse) Invoke(ctx context.Context, method string, request, response any, options ...grpc.CallOption) error {
	err := c.ClientConnInterface.Invoke(ctx, method, request, response, options...)
	if err == nil && method == c.method && !c.lost {
		c.lost = true
		return status.Error(codes.Unavailable, "simulated response loss after peer persistence")
	}
	return err
}

func TestAWGBackupRestoresPeersAndPrivateProfiles(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := newStructService(manager, opts)
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
