package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
	"xray-easy/internal/controller"
	"xray-easy/internal/domain"
	"xray-easy/internal/runtimeauth"
	"xray-easy/internal/stats"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

const (
	integrationControllerToken = "integration-controller-token-with-enough-entropy"
	integrationRuntimeToken    = "integration-runtime-token-with-enough-entropy"
)

// integrationRuntimeServer is a real gRPC runtime boundary backed by a small
// deterministic state machine. The embedded Xray engine is exercised in the
// xray-runtime module's own integration tests.
type integrationRuntimeServer struct {
	xrayruntimev1.UnimplementedRuntimeServer

	mu             sync.Mutex
	users          map[string]string
	applyCalls     int
	validated      int
	lastConfig     []byte
	streamStarted  chan struct{}
	streamStartOne sync.Once
	telemetry      chan *xrayruntimev1.TelemetryResponse
}

func newIntegrationRuntimeServer() *integrationRuntimeServer {
	return &integrationRuntimeServer{
		users:         make(map[string]string),
		streamStarted: make(chan struct{}),
		telemetry:     make(chan *xrayruntimev1.TelemetryResponse, 8),
	}
}

func (*integrationRuntimeServer) Health(context.Context, *xrayruntimev1.HealthRequest) (*xrayruntimev1.HealthResponse, error) {
	return &xrayruntimev1.HealthResponse{Ready: true}, nil
}

func (*integrationRuntimeServer) GetStatus(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.RuntimeStatus, error) {
	return &xrayruntimev1.RuntimeStatus{
		State:           xrayruntimev1.RuntimeState_RUNTIME_STATE_RUNNING,
		ServiceVersion:  "integration-test",
		XrayCoreVersion: "integration-test",
		ActiveRevision:  1,
		StartedAt:       timestamppb.Now(),
	}, nil
}

func (*integrationRuntimeServer) GetCapabilities(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.CapabilitiesResponse, error) {
	return &xrayruntimev1.CapabilitiesResponse{Protocols: []*xrayruntimev1.ProtocolCapability{{
		Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS, Configured: true, UserManagement: true,
		TrafficCounters: true, OnlineStatus: true, SourceIp: true, InboundTag: "vless-reality",
	}}}, nil
}

func (s *integrationRuntimeServer) ValidateConfiguration(_ context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.ConfigurationResponse, error) {
	s.mu.Lock()
	s.validated++
	s.lastConfig = append(s.lastConfig[:0], request.GetConfigurationJson()...)
	s.mu.Unlock()
	digest := sha256.Sum256(request.GetConfigurationJson())
	return &xrayruntimev1.ConfigurationResponse{
		Valid: true, OperationId: request.GetOperationId(), Revision: request.GetRevision(),
		ConfigurationDigest: hex.EncodeToString(digest[:]),
	}, nil
}

func (s *integrationRuntimeServer) ApplyConfiguration(_ context.Context, request *xrayruntimev1.ConfigurationRequest) (*xrayruntimev1.OperationResponse, error) {
	s.mu.Lock()
	s.applyCalls++
	s.lastConfig = append(s.lastConfig[:0], request.GetConfigurationJson()...)
	s.mu.Unlock()
	return integrationOperationResponse(request.GetOperationId(), request.GetRevision()), nil
}

func (s *integrationRuntimeServer) AddUser(_ context.Context, request *xrayruntimev1.AddUserRequest) (*xrayruntimev1.OperationResponse, error) {
	s.mu.Lock()
	s.users[request.GetEmail()] = request.GetCredential()
	s.mu.Unlock()
	return integrationOperationResponse(request.GetOperationId(), request.GetRevision()), nil
}

func (s *integrationRuntimeServer) RemoveUser(_ context.Context, request *xrayruntimev1.RemoveUserRequest) (*xrayruntimev1.OperationResponse, error) {
	s.mu.Lock()
	delete(s.users, request.GetEmail())
	s.mu.Unlock()
	return integrationOperationResponse(request.GetOperationId(), request.GetRevision()), nil
}

func (s *integrationRuntimeServer) ListUsers(_ context.Context, _ *xrayruntimev1.ListUsersRequest) (*xrayruntimev1.ListUsersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	emails := make([]string, 0, len(s.users))
	for email := range s.users {
		emails = append(emails, email)
	}
	return &xrayruntimev1.ListUsersResponse{Emails: emails}, nil
}

func (*integrationRuntimeServer) GetTelemetry(context.Context, *xrayruntimev1.EmptyRequest) (*xrayruntimev1.TelemetryResponse, error) {
	return &xrayruntimev1.TelemetryResponse{SampledAt: timestamppb.Now(), SourceGeneration: "integration-runtime", Sequence: 1, FullSnapshot: true}, nil
}

func (s *integrationRuntimeServer) WatchTelemetry(_ *xrayruntimev1.WatchTelemetryRequest, stream xrayruntimev1.Runtime_WatchTelemetryServer) error {
	s.streamStartOne.Do(func() { close(s.streamStarted) })
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case update := <-s.telemetry:
			if err := stream.Send(update); err != nil {
				return err
			}
		}
	}
}

func integrationOperationResponse(operationID string, revision int64) *xrayruntimev1.OperationResponse {
	return &xrayruntimev1.OperationResponse{OperationId: operationID, Revision: revision}
}

func (s *integrationRuntimeServer) userCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

func (s *integrationRuntimeServer) hasUser(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[email]
	return ok
}

func (s *integrationRuntimeServer) applyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyCalls
}

func (s *integrationRuntimeServer) validationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validated
}

func newIntegrationGRPC(t *testing.T, options ...grpc.ServerOption) (*grpc.Server, *bufconn.Listener, *grpc.ClientConn) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(options...)
	connection, err := grpc.NewClient(
		"passthrough:///xray-easy-integration",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	})
	return server, listener, connection
}

func serveIntegrationGRPC(server *grpc.Server, listener *bufconn.Listener) {
	go func() { _ = server.Serve(listener) }()
}

type integrationSSEEvent struct {
	name string
	data map[string]json.RawMessage
}

type integrationPipeSSEWriter struct {
	writer *io.PipeWriter
	header http.Header
}

func (w *integrationPipeSSEWriter) Header() http.Header             { return w.header }
func (*integrationPipeSSEWriter) WriteHeader(int)                   {}
func (w *integrationPipeSSEWriter) Write(value []byte) (int, error) { return w.writer.Write(value) }
func (*integrationPipeSSEWriter) Flush()                            {}

func readIntegrationSSEEvent(reader *bufio.Reader) (integrationSSEEvent, error) {
	var event integrationSSEEvent
	var data strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return integrationSSEEvent{}, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if event.name == "" {
				continue
			}
			if data.Len() > 0 {
				if err := json.Unmarshal([]byte(data.String()), &event.data); err != nil {
					return integrationSSEEvent{}, err
				}
			}
			return event, nil
		}
		if name, value, found := strings.Cut(line, ":"); found {
			value = strings.TrimPrefix(value, " ")
			switch name {
			case "event":
				event.name = value
			case "data":
				if data.Len() > 0 {
					data.WriteByte('\n')
				}
				data.WriteString(value)
			}
		}
	}
}

func readIntegrationClientStats(reader *bufio.Reader, clientID string, wantUpload int64) (map[string]json.RawMessage, error) {
	for {
		event, err := readIntegrationSSEEvent(reader)
		if err != nil {
			return nil, err
		}
		if event.name != "stats" {
			continue
		}
		var clients map[string]map[string]json.RawMessage
		if err := json.Unmarshal(event.data["clients"], &clients); err != nil {
			return nil, err
		}
		client, found := clients[clientID]
		if !found {
			continue
		}
		var upload int64
		if err := json.Unmarshal(client["upload_bytes"], &upload); err != nil {
			return nil, err
		}
		if upload >= wantUpload {
			return client, nil
		}
	}
}

func TestIntegrationProfileAndTelemetryCrossBackendControllerRuntimeGRPCAndSSE(t *testing.T) {
	app := newTestApp(t, true)
	activeConfig := `{"inbounds":[{"listen":"127.0.0.1","port":18443,"protocol":"vless","tag":"vless-reality","settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`
	if err := os.WriteFile(filepath.Join(app.server.configDir, "active.json"), []byte(activeConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	runtimeServer := newIntegrationRuntimeServer()
	runtimeAuthenticator, err := runtimeauth.NewAuthenticator([]byte(integrationRuntimeToken), func(_ string, identity string) bool {
		return identity == "control-plane" || identity == "healthcheck"
	})
	if err != nil {
		t.Fatal(err)
	}
	rpcRuntimeServer, runtimeListener, runtimeConnection := newIntegrationGRPC(t,
		grpc.ChainUnaryInterceptor(runtimeAuthenticator.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(runtimeAuthenticator.StreamServerInterceptor()),
	)
	xrayruntimev1.RegisterRuntimeServer(rpcRuntimeServer, runtimeServer)
	serveIntegrationGRPC(rpcRuntimeServer, runtimeListener)
	runtimeTokenPath := filepath.Join(t.TempDir(), "runtime.token")
	if err := os.WriteFile(runtimeTokenPath, []byte(integrationRuntimeToken), 0o600); err != nil {
		t.Fatal(err)
	}
	embeddedRuntime := controller.NewEmbeddedXrayClientWithConn(runtimeConnection, runtimeTokenPath, app.server.configDir)

	controllerServer := controller.NewServiceWithAdapters(embeddedRuntime, embeddedRuntime, embeddedRuntime, nil)
	controllerGRPCServer, controllerListener, controllerConnection := newIntegrationGRPC(t,
		grpc.ChainUnaryInterceptor(controller.LoggingInterceptor("integration-controller"), controller.AuthInterceptor(integrationControllerToken)),
		grpc.ChainStreamInterceptor(controller.LoggingStreamInterceptor("integration-controller"), controller.AuthStreamInterceptor(integrationControllerToken)),
	)
	controller.RegisterRPC(controllerGRPCServer, controllerServer)
	serveIntegrationGRPC(controllerGRPCServer, controllerListener)
	controllerClient := controller.NewClientWithConn(controllerConnection, integrationControllerToken)
	app.server.xrayRuntime = controllerClient
	app.server.handler = controllerClient
	app.server.stats = stats.NewManager(app.server.store, controllerClient)

	createResponse := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolVLESS), Name: "integration-phone"}, true)
	var created struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if createResponse.Code != http.StatusCreated || created.ID == "" {
		t.Fatalf("create VLESS profile response = %d %+v", createResponse.Code, created)
	}
	stored, err := app.server.store.GetClient(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("read newly created profile from SQLite: %v", err)
	}
	created.Email = stored.Email
	if !runtimeServer.hasUser(created.Email) || runtimeServer.userCount() != 1 || runtimeServer.validationCount() != 1 || runtimeServer.applyCount() != 0 {
		t.Fatalf("live profile mutation: users=%d validations=%d full applies=%d; want 1/1/0", runtimeServer.userCount(), runtimeServer.validationCount(), runtimeServer.applyCount())
	}

	eventsContext, cancelEvents := context.WithTimeout(context.Background(), 10*time.Second)
	eventsRequest := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(eventsContext)
	eventsRequest.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	pipeReader, pipeWriter := io.Pipe()
	writer := &integrationPipeSSEWriter{writer: pipeWriter, header: make(http.Header)}
	streamDone := make(chan struct{})
	go func() {
		newMux(app.server).ServeHTTP(writer, eventsRequest)
		_ = pipeWriter.Close()
		close(streamDone)
	}()
	defer func() {
		cancelEvents()
		_ = pipeReader.Close()
		select {
		case <-streamDone:
		case <-time.After(time.Second):
			t.Error("backend SSE handler did not stop during test cleanup")
		}
	}()
	reader := bufio.NewReader(pipeReader)
	for received := 0; received < 2; received++ {
		if _, err := readIntegrationSSEEvent(reader); err != nil {
			t.Fatalf("read initial SSE snapshot %d: %v", received+1, err)
		}
	}
	select {
	case <-runtimeServer.streamStarted:
	case <-eventsContext.Done():
		t.Fatalf("Controller did not open the runtime telemetry stream: %v", eventsContext.Err())
	}

	pushTelemetry := func(sequence uint64, upload, download int64) {
		t.Helper()
		runtimeServer.telemetry <- &xrayruntimev1.TelemetryResponse{
			SampledAt: timestamppb.Now(), SourceGeneration: "integration-runtime", Sequence: sequence, FullSnapshot: true,
			Users: []*xrayruntimev1.UserTelemetry{{
				Email: created.Email, Protocol: xrayruntimev1.Protocol_PROTOCOL_VLESS,
				Online: true, UploadBytes: upload, DownloadBytes: download, LastSeen: timestamppb.Now(), LastActivity: timestamppb.Now(),
				SourceIps: []*xrayruntimev1.IPObservation{{Address: "198.51.100.27", LastSeen: timestamppb.Now(), ConnectedAt: timestamppb.Now()}},
			}},
		}
	}
	pushTelemetry(1, 1024, 2048)
	firstSnapshot, err := readIntegrationClientStats(reader, created.ID, 1024)
	if err != nil {
		t.Fatalf("read first streamed profile stats: %v", err)
	}
	pushTelemetry(2, 4096, 8192)
	secondSnapshot, err := readIntegrationClientStats(reader, created.ID, 4096)
	if err != nil {
		t.Fatalf("read updated streamed profile stats: %v", err)
	}
	var online bool
	var download int64
	var sourceIPs []string
	var uploadRate float64
	if err := json.Unmarshal(secondSnapshot["online"], &online); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondSnapshot["download_bytes"], &download); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondSnapshot["source_ips"], &sourceIPs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondSnapshot["upload_bytes_per_second"], &uploadRate); err != nil {
		t.Fatal(err)
	}
	if !online || download != 8192 || len(sourceIPs) != 1 || sourceIPs[0] != "198.51.100.27" || uploadRate <= 0 {
		t.Fatalf("end-to-end SSE profile stats: online=%t download=%d sourceIPs=%v uploadRate=%f first=%s", online, download, sourceIPs, uploadRate, firstSnapshot["upload_bytes"])
	}

	disableResponse := requestJSON(t, app, http.MethodPost, fmt.Sprintf("/api/clients/%s/disable", created.ID), nil, true)
	if disableResponse.Code != http.StatusOK || runtimeServer.userCount() != 0 {
		t.Fatalf("disable live profile: response=%d runtime users=%d", disableResponse.Code, runtimeServer.userCount())
	}

	stored, err = app.server.store.GetClient(context.Background(), created.ID)
	if err != nil || stored.Enabled || stored.Revoked {
		t.Fatalf("persisted disabled profile=%+v error=%v", stored, err)
	}
	if _, err := controllerClient.Capabilities(context.Background()); err != nil {
		t.Fatalf("Controller remained unavailable after profile lifecycle: %v", err)
	}
	if err := controllerClient.Close(); err != nil {
		t.Fatalf("close test Controller client: %v", err)
	}
	if err := embeddedRuntime.Close(); err != nil {
		t.Fatalf("close test embedded runtime client: %v", err)
	}
}
