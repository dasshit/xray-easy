package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/stats"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAmneziaWGGateway struct {
	status     domain.AmneziaWGStatus
	peers      map[string]domain.AmneziaWGPeer
	profiles   map[string]string
	statusErr  error
	listErr    error
	createErr  error
	removeErr  error
	profileErr error
}

func (f *fakeAmneziaWGGateway) Status(context.Context) (domain.AmneziaWGStatus, error) {
	return f.status, f.statusErr
}

func (f *fakeAmneziaWGGateway) ListPeers(context.Context) ([]domain.AmneziaWGPeer, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	peers := make([]domain.AmneziaWGPeer, 0, len(f.peers))
	for _, peer := range f.peers {
		peers = append(peers, peer)
	}
	return peers, nil
}

func (f *fakeAmneziaWGGateway) CreatePeer(_ context.Context, name string) (domain.AmneziaWGPeer, error) {
	if f.createErr != nil {
		return domain.AmneziaWGPeer{}, f.createErr
	}
	if _, exists := f.peers[name]; exists {
		return domain.AmneziaWGPeer{}, status.Error(codes.AlreadyExists, "exists")
	}
	peer := domain.AmneziaWGPeer{Name: name, PublicKey: "public-key", IPv4: "10.88.0.2", IPv6: "fd88:88:88::2", CreatedAt: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	f.peers[name] = peer
	f.profiles[name] = "[Interface]\nPrivateKey = client-private\n[Peer]\n"
	return peer, nil
}

func (f *fakeAmneziaWGGateway) RemovePeer(_ context.Context, name string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	if _, exists := f.peers[name]; !exists {
		return status.Error(codes.NotFound, "missing")
	}
	delete(f.peers, name)
	delete(f.profiles, name)
	return nil
}

func (f *fakeAmneziaWGGateway) ClientConfig(_ context.Context, name string) (string, error) {
	if f.profileErr != nil {
		return "", f.profileErr
	}
	profile, exists := f.profiles[name]
	if !exists {
		return "", status.Error(codes.NotFound, "missing")
	}
	return profile, nil
}

func TestAmneziaWGRoutesRequireAuthenticationAndReportDisabledState(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated AWG status = %d", got)
	}
	response := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"available":false`) {
		t.Fatalf("disabled AWG status = %d %s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGUsesUnifiedProfileAPIAndKeepsSecretsInAWGService(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{
		status: domain.AmneziaWGStatus{Running: true, PublicHost: "vpn.example.test", PublicPort: 1234, ListenPort: 1234},
		peers:  make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
	}
	app.server.awg = gateway

	created := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "iphone", Protocol: string(domain.ProtocolAmneziaWG)}, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"id":"awg:iphone"`) || !strings.Contains(created.Body.String(), `"protocol":"amneziawg"`) || strings.Contains(created.Body.String(), "client-private") {
		t.Fatalf("unified AWG create = %d %s", created.Code, created.Body.String())
	}
	listed := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"id":"awg:iphone"`) || !strings.Contains(listed.Body.String(), `"protocols":["amneziawg"]`) {
		t.Fatalf("unified profile list = %d %s", listed.Code, listed.Body.String())
	}

	delivery := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aiphone/profile?format=uri", nil, true)
	if delivery.Code != http.StatusOK || !strings.Contains(delivery.Body.String(), `"name":"iphone"`) || strings.Contains(delivery.Body.String(), "client-private") {
		t.Fatalf("AWG profile reference leaked material: %d %s", delivery.Code, delivery.Body.String())
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aiphone/profile?format=qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatalf("unified AWG QR = %d headers=%v", qr.Code, qr.Header())
	}
	file := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aiphone/profile?format=conf", nil, true)
	if file.Code != http.StatusOK || !strings.Contains(file.Body.String(), "client-private") || file.Header().Get("Cache-Control") != "no-store, private" || file.Header().Get("Content-Disposition") != `attachment; filename="iphone.conf"` {
		t.Fatalf("AWG config delivery = %d %s", file.Code, file.Body.String())
	}

	revoked := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Aiphone/revoke", nil, true)
	if revoked.Code != http.StatusOK || len(gateway.peers) != 0 || len(gateway.profiles) != 0 {
		t.Fatalf("unified AWG revoke = %d %s peers=%d", revoked.Code, revoked.Body.String(), len(gateway.peers))
	}
}

func TestUnifiedAWGCreationValidatesProtocolSpecificInputAndAvailability(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	invalid := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "bad_name", Protocol: string(domain.ProtocolAmneziaWG)}, true)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid AWG profile name = %d %s", invalid.Code, invalid.Body.String())
	}
	unavailable := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone", Protocol: string(domain.ProtocolAmneziaWG)}, true)
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("AWG creation without service = %d %s", unavailable.Code, unavailable.Body.String())
	}
	gateway := &fakeAmneziaWGGateway{peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string)}
	app.server.awg = gateway
	invalidOption := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone", Protocol: string(domain.ProtocolAmneziaWG), Fingerprint: "chrome"}, true)
	if invalidOption.Code != http.StatusBadRequest {
		t.Fatalf("AWG unsupported create option = %d %s", invalidOption.Code, invalidOption.Body.String())
	}
}

func TestAmneziaWGUnavailableErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	app.server.awg = &fakeAmneziaWGGateway{
		peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		statusErr: errors.New("dial failed: bearer token=secret-value"),
	}
	response := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, true)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "secret-value") {
		t.Fatalf("AWG error response = %d %s", response.Code, response.Body.String())
	}
	app.server.awg = &fakeAmneziaWGGateway{
		peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		statusErr: status.Error(codes.Unavailable, "stopped"),
	}
	response = requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, true)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "not running") {
		t.Fatalf("unavailable AWG response = %d %s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGRoutesHandleInvalidMethodsAndUpstreamFailures(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string)}
	app.server.awg = gateway

	if got := requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST AWG status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Aphone/profile?format=uri", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST AWG profile = %d", got)
	}

	app.server.awg = &fakeAmneziaWGGateway{
		peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		listErr: errors.New("private upstream detail"),
	}
	response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format=uri", nil, true)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private upstream detail") {
		t.Fatalf("redacted peer lookup error = %d %s", response.Code, response.Body.String())
	}
	app.server.awg = &fakeAmneziaWGGateway{profileErr: errors.New("private upstream detail")}
	response = requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format=conf", nil, true)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private upstream detail") {
		t.Fatalf("redacted profile error = %d %s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGRevocationRequiresSuccessfulAutomaticBackup(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{
		peers: map[string]domain.AmneziaWGPeer{"phone": {Name: "phone"}}, profiles: make(map[string]string),
	}
	app.server.awg = gateway
	app.server.masterKey = nil
	response := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Aphone/revoke", nil, true)
	if response.Code != http.StatusInternalServerError || len(gateway.peers) != 1 || !strings.Contains(response.Body.String(), "backup_failed") {
		t.Fatalf("revoke without backup = %d %s peers=%d", response.Code, response.Body.String(), len(gateway.peers))
	}
}

func TestWriteAWGErrorMapsKnownGRPCCodes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		code codes.Code
		want int
	}{
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.NotFound, http.StatusNotFound},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.DeadlineExceeded, http.StatusServiceUnavailable},
		{codes.Internal, http.StatusBadGateway},
	} {
		t.Run(fmt.Sprint(test.code), func(t *testing.T) {
			response := httptest.NewRecorder()
			writeAWGError(response, status.Error(test.code, "sensitive gRPC details"))
			if response.Code != test.want || strings.Contains(response.Body.String(), "sensitive gRPC details") {
				t.Fatalf("writeAWGError(%s) = %d %s", test.code, response.Code, response.Body.String())
			}
		})
	}
	response := httptest.NewRecorder()
	writeAWGError(response, nil)
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("writeAWGError(nil) wrote a response: %d %s", response.Code, response.Body.String())
	}
}

func TestUnifiedAWGProfileRouteValidatesFormatsAndPeerPresence(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	peer := domain.AmneziaWGPeer{Name: "phone"}
	gateway := &fakeAmneziaWGGateway{
		peers:    map[string]domain.AmneziaWGPeer{"phone": peer},
		profiles: map[string]string{"phone": "[Interface]\nPrivateKey = client-private\n"},
	}
	app.server.awg = gateway
	for _, test := range []struct {
		format string
		want   int
		body   string
	}{
		{format: "conf", want: http.StatusOK, body: "client-private"},
		{format: "unsupported", want: http.StatusBadRequest, body: "unsupported AmneziaWG profile format"},
	} {
		response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format="+test.format, nil, true)
		if response.Code != test.want || !strings.Contains(response.Body.String(), test.body) {
			t.Fatalf("AWG format %q = %d %s", test.format, response.Code, response.Body.String())
		}
	}
	if response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Amissing/profile?format=uri", nil, true); response.Code != http.StatusNotFound {
		t.Fatalf("missing AWG peer URI status = %d %s", response.Code, response.Body.String())
	}
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Aphone/profile?format=uri", nil, true); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("AWG profile POST status = %d %s", response.Code, response.Body.String())
	}
	app.server.awg = &fakeAmneziaWGGateway{listErr: errors.New("peer database unavailable")}
	if response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format=uri", nil, true); response.Code != http.StatusBadGateway {
		t.Fatalf("AWG peer lookup failure = %d %s", response.Code, response.Body.String())
	}
}

func TestAWGClientCreateAndPeerRoutesCoverLifecycleFailures(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string)}
	app.server.awg = gateway
	create := func(name string) *httptest.ResponseRecorder {
		return requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: name, Protocol: string(domain.ProtocolAmneziaWG)}, true)
	}

	gateway.statusErr = status.Error(codes.Unavailable, "offline")
	if response := create("status-error"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("AWG create status failure = %d %s", response.Code, response.Body.String())
	}
	gateway.statusErr = nil
	gateway.status.Running = false
	if response := create("stopped"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("AWG create while stopped = %d %s", response.Code, response.Body.String())
	}
	gateway.status.Running = true
	gateway.createErr = status.Error(codes.AlreadyExists, "duplicate")
	if response := create("duplicate"); response.Code != http.StatusConflict {
		t.Fatalf("AWG peer create failure = %d %s", response.Code, response.Body.String())
	}
	gateway.createErr = nil
	gateway.peers["phone"] = domain.AmneziaWGPeer{Name: "phone"}
	gateway.profiles["phone"] = "[Interface]\nPrivateKey = secret\n"

	if response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format=qr", nil, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous AWG profile request = %d", response.Code)
	}
	gateway.profileErr = status.Error(codes.NotFound, "missing")
	if response := requestJSON(t, app, http.MethodGet, "/api/clients/awg%3Aphone/profile?format=conf", nil, true); response.Code != http.StatusNotFound {
		t.Fatalf("missing AWG client config = %d %s", response.Code, response.Body.String())
	}
	gateway.profileErr = nil
	gateway.removeErr = status.Error(codes.Unavailable, "offline")
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Aphone/revoke", nil, true); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("AWG peer removal failure = %d %s", response.Code, response.Body.String())
	}
	gateway.removeErr = nil
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/awg%3Amissing/revoke", nil, true); response.Code != http.StatusNotFound {
		t.Fatalf("missing AWG peer removal = %d %s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGStatusAndClientHandlersCoverBoundaryFailures(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	statusRecorder := httptest.NewRecorder()
	app.server.amneziaWGStatus(statusRecorder, httptest.NewRequest(http.MethodGet, "/wrong", nil))
	if statusRecorder.Code != http.StatusNotFound {
		t.Fatalf("status handler accepted a mismatched route: %d", statusRecorder.Code)
	}

	gateway := &fakeAmneziaWGGateway{
		status: domain.AmneziaWGStatus{Running: true},
		peers:  make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		statusErr: status.Error(codes.Unavailable, "offline"),
	}
	app.server.awg = gateway
	statusRecorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/transports/amneziawg", nil)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	app.server.amneziaWGStatus(statusRecorder, request)
	if statusRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status upstream failure = %d %s", statusRecorder.Code, statusRecorder.Body.String())
	}

	gateway.statusErr = nil
	peer := domain.AmneziaWGPeer{Name: "phone", CreatedAt: time.Now().UTC()}
	app.server.stats = stats.NewManager(app.server.store, fixedStatsAPI{})
	result := app.server.withAWGStats([]domain.AmneziaWGPeer{peer})
	if len(result) != 1 || result[0].Protocol != domain.ProtocolAmneziaWG || result[0].Name != peer.Name {
		t.Fatalf("AWG stats projection = %+v", result)
	}

	lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
	defer cancel()
	request = httptest.NewRequest(http.MethodPost, "/api/clients", strings.NewReader(`{"name":"phone","protocol":"amneziawg"}`)).WithContext(ctx)
	request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	response := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("peer create during maintenance = %d %s", response.Code, response.Body.String())
	}
}
