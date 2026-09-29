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
	app := newTestApp(t, true)
	if got := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated AWG status = %d", got)
	}
	response := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, true)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"available":false`) {
		t.Fatalf("disabled AWG status = %d %s", response.Code, response.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg/peers", amneziaWGCreatePeerRequest{Name: "phone"}, true).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("create without AWG service = %d", got)
	}
}

func TestAmneziaWGPeerLifecycleAndSecretProfileDelivery(t *testing.T) {
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{
		status: domain.AmneziaWGStatus{Running: true, PublicHost: "vpn.example.test", PublicPort: 51820, ListenPort: 51820, PeerCount: 0, IPv4Network: "10.88.0.0/24", IPv6Network: "fd88:88:88::/64", ServiceVersion: "prototype-v1"},
		peers:  make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
	}
	app.server.awg = gateway

	statusResponse := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg", nil, true)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"running":true`) {
		t.Fatalf("AWG status = %d %s", statusResponse.Code, statusResponse.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg/peers", amneziaWGCreatePeerRequest{Name: "bad_name"}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("invalid AWG peer name = %d", got)
	}
	created := requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg/peers", amneziaWGCreatePeerRequest{Name: "iphone-1"}, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"ipv4":"10.88.0.2"`) {
		t.Fatalf("create AWG peer = %d %s", created.Code, created.Body.String())
	}
	listed := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers", nil, true)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"name":"iphone-1"`) {
		t.Fatalf("list AWG peers = %d %s", listed.Code, listed.Body.String())
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers/iphone-1/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), "client-private") || profile.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatalf("AWG profile = %d headers=%v body=%s", profile.Code, profile.Header(), profile.Body.String())
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers/iphone-1/profile/qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Header().Get("Cache-Control") != "no-store, private" {
		t.Fatalf("AWG QR response = %d headers=%v", qr.Code, qr.Header())
	}
	revoked := requestJSON(t, app, http.MethodDelete, "/api/transports/amneziawg/peers/iphone-1", nil, true)
	if revoked.Code != http.StatusOK || len(gateway.peers) != 0 || len(gateway.profiles) != 0 {
		t.Fatalf("revoke AWG peer = %d %s remaining=%d profiles=%d", revoked.Code, revoked.Body.String(), len(gateway.peers), len(gateway.profiles))
	}
}

func TestAmneziaWGUnavailableErrorsAreRedacted(t *testing.T) {
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
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string)}
	app.server.awg = gateway

	if got := requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST AWG status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPut, "/api/transports/amneziawg/peers", nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("PUT AWG peers = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers/not_a_valid_name/profile", nil, true).Code; got != http.StatusNotFound {
		t.Fatalf("invalid peer path = %d", got)
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers/missing/other", nil, true).Code; got != http.StatusNotFound {
		t.Fatalf("unknown peer route = %d", got)
	}

	app.server.awg = &fakeAmneziaWGGateway{
		peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		listErr: errors.New("private upstream detail"),
	}
	response := requestJSON(t, app, http.MethodGet, "/api/transports/amneziawg/peers", nil, true)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private upstream detail") {
		t.Fatalf("redacted peer list error = %d %s", response.Code, response.Body.String())
	}
	app.server.awg = &fakeAmneziaWGGateway{
		peers: make(map[string]domain.AmneziaWGPeer), profiles: make(map[string]string),
		createErr: errors.New("private upstream detail"),
	}
	response = requestJSON(t, app, http.MethodPost, "/api/transports/amneziawg/peers", amneziaWGCreatePeerRequest{Name: "phone"}, true)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private upstream detail") {
		t.Fatalf("redacted create error = %d %s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGRevocationRequiresSuccessfulAutomaticBackup(t *testing.T) {
	app := newTestApp(t, true)
	gateway := &fakeAmneziaWGGateway{
		peers: map[string]domain.AmneziaWGPeer{"phone": {Name: "phone"}}, profiles: make(map[string]string),
	}
	app.server.awg = gateway
	app.server.masterKey = nil
	response := requestJSON(t, app, http.MethodDelete, "/api/transports/amneziawg/peers/phone", nil, true)
	if response.Code != http.StatusInternalServerError || len(gateway.peers) != 1 || !strings.Contains(response.Body.String(), "backup_failed") {
		t.Fatalf("revoke without backup = %d %s peers=%d", response.Code, response.Body.String(), len(gateway.peers))
	}
}

func TestWriteAWGErrorMapsKnownGRPCCodes(t *testing.T) {
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
}
