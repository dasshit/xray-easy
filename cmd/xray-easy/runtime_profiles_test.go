package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
	"xray-easy/internal/secret"
	"xray-easy/internal/xray"
)

type recordingInboundReplacer struct {
	*fakeXrayRuntime
	calls [][4]string
	err   error
	hook  func()
}

func (r *recordingInboundReplacer) ReplaceInbound(_ context.Context, candidate, previous, tag, operationID string) error {
	r.calls = append(r.calls, [4]string{candidate, previous, tag, operationID})
	if r.hook != nil {
		r.hook()
	}
	return r.err
}

type recordingHysteriaHandler struct {
	*fakeXrayHandler
	users     []string
	added     []string
	removed   []string
	listErr   error
	addErr    error
	removeErr error
	afterAdd  func()
}

type recordingVMessHandler struct {
	*fakeXrayHandler
	users     []string
	added     []string
	removed   []string
	listErr   error
	addErr    error
	removeErr error
}

type recordingShadowsocksHandler struct {
	*fakeXrayHandler
	users     []string
	added     []string
	methods   []string
	removed   []string
	addErr    error
	removeErr error
	listErr   error
}

type reconcilingProtocolHandler struct {
	*fakeXrayHandler
	hysteriaUsers []string
	vmessUsers    []string
	listTag       string
	listErr       error
}

func (h *reconcilingProtocolHandler) AddHysteriaUser(_ context.Context, email, _ string) error {
	h.hysteriaUsers = append(h.hysteriaUsers, email)
	return nil
}

func (h *reconcilingProtocolHandler) RemoveHysteriaUser(_ context.Context, email string) error {
	h.hysteriaUsers = removeEmail(h.hysteriaUsers, email)
	return nil
}

func (h *reconcilingProtocolHandler) AddVMessUser(_ context.Context, email, _ string) error {
	h.vmessUsers = append(h.vmessUsers, email)
	return nil
}

func (h *reconcilingProtocolHandler) RemoveVMessUser(_ context.Context, email string) error {
	h.vmessUsers = removeEmail(h.vmessUsers, email)
	return nil
}

func (h *reconcilingProtocolHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if h.listErr != nil && h.listTag == tag {
		return nil, h.listErr
	}
	switch tag {
	case xray.HysteriaInboundTag:
		return append([]string(nil), h.hysteriaUsers...), nil
	case xray.VMessInboundTag:
		return append([]string(nil), h.vmessUsers...), nil
	default:
		return nil, fmt.Errorf("unexpected inbound tag %q", tag)
	}
}

func removeEmail(emails []string, target string) []string {
	for index, email := range emails {
		if email == target {
			return append(emails[:index], emails[index+1:]...)
		}
	}
	return emails
}

func (h *recordingVMessHandler) AddVMessUser(_ context.Context, email, _ string) error {
	h.added = append(h.added, email)
	if h.addErr != nil {
		return h.addErr
	}
	h.users = append(h.users, email)
	return nil
}

func (h *recordingVMessHandler) RemoveVMessUser(_ context.Context, email string) error {
	h.removed = append(h.removed, email)
	if h.removeErr != nil {
		return h.removeErr
	}
	for i, value := range h.users {
		if value == email {
			h.users = append(h.users[:i], h.users[i+1:]...)
			break
		}
	}
	return nil
}

func (h *recordingShadowsocksHandler) AddShadowsocksUser(_ context.Context, email, password, method string) error {
	if h.addErr != nil {
		return h.addErr
	}
	h.added = append(h.added, email)
	h.methods = append(h.methods, method)
	h.users = append(h.users, email)
	if password == "" {
		return errors.New("empty Shadowsocks password")
	}
	return nil
}

func (h *recordingShadowsocksHandler) RemoveShadowsocksUser(_ context.Context, email string) error {
	if h.removeErr != nil {
		return h.removeErr
	}
	h.removed = append(h.removed, email)
	h.users = removeEmail(h.users, email)
	return nil
}

func (h *recordingShadowsocksHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if tag != xray.ShadowsocksInboundTag {
		return nil, fmt.Errorf("unexpected inbound tag %q", tag)
	}
	return append([]string(nil), h.users...), h.listErr
}

func (h *recordingVMessHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if tag != xray.VMessInboundTag {
		return nil, fmt.Errorf("unexpected inbound tag %q", tag)
	}
	return append([]string(nil), h.users...), h.listErr
}

func (h *recordingHysteriaHandler) AddHysteriaUser(_ context.Context, email, _ string) error {
	h.added = append(h.added, email)
	if h.addErr != nil {
		return h.addErr
	}
	h.users = append(h.users, email)
	if h.afterAdd != nil {
		h.afterAdd()
	}
	return nil
}

func (h *recordingHysteriaHandler) RemoveHysteriaUser(_ context.Context, email string) error {
	h.removed = append(h.removed, email)
	if h.removeErr != nil {
		return h.removeErr
	}
	for i, value := range h.users {
		if value == email {
			h.users = append(h.users[:i], h.users[i+1:]...)
			break
		}
	}
	return nil
}

func (h *recordingHysteriaHandler) UsersInInbound(_ context.Context, tag string) ([]string, error) {
	if tag != "hysteria2" {
		return nil, fmt.Errorf("unexpected inbound tag %q", tag)
	}
	return append([]string(nil), h.users...), h.listErr
}

func createRuntimeTestClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createRuntimeHysteriaClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create Hysteria 2 profile %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createRuntimeVMessClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolVMess), Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create VMess profile %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func createRuntimeShadowsocksClient(t *testing.T, app testApp, name string) domain.Client {
	t.Helper()
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolShadowsocks), Name: name}, true)
	if response.Code != http.StatusCreated {
		t.Fatalf("create Shadowsocks profile %s: %d %s", name, response.Code, response.Body.String())
	}
	created := decodeResponse[clientResponse](t, response)
	client, err := app.server.store.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestVLESSShortIDReserveAddsUsersThenReplacesInbound(t *testing.T) {
	app := newTestApp(t, true)
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer
	for i := 1; i <= 6; i++ {
		createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
	}
	if len(app.sup.applyCalls) != 1 || len(app.handler.addCall) != 4 || len(replacer.calls) != 1 {
		t.Fatalf("runtime operations: apply=%d AddUser=%d ReplaceInbound=%d", len(app.sup.applyCalls), len(app.handler.addCall), len(replacer.calls))
	}
	if replacer.calls[0][2] != "vless-reality" {
		t.Fatalf("wrong inbound replaced: %v", replacer.calls[0])
	}
	active := filepath.Join(app.server.configDir, "active.json")
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []json.RawMessage `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				RealitySettings struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 || len(config.Inbounds[0].Settings.Clients) != 6 || len(config.Inbounds[0].StreamSettings.RealitySettings.ShortIDs) != 11 {
		t.Fatalf("persisted config did not include six clients and five free IDs: %s", content)
	}
	if len(app.server.diagnosticBuffer.Snapshot(0)) == 0 {
		t.Fatal("short-ID exhaustion was not reported in diagnostics")
	}

	replacer.err = errors.New("replace failed")
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "failed-replace"}, true)
	if failed.Code != http.StatusCreated {
		// The pool was refilled by the previous replacement, so this attempt must
		// use the hot AddUser path rather than invoking the failing replacer.
		t.Fatalf("refilled reserve was not usable: %d %s", failed.Code, failed.Body.String())
	}
	for i := 8; i <= 11; i++ {
		createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
	}
	failed = requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "actual-replace-failure"}, true)
	if failed.Code != http.StatusBadGateway || len(replacer.calls) != 2 {
		t.Fatalf("failed inbound replacement = %d calls=%v body=%s", failed.Code, replacer.calls, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 11 {
		t.Fatalf("failed replacement persisted a client: %d, %v", len(clients), err)
	}
}

func TestHysteriaProfileDeliveryAndLiveUserRollback(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	first := createRuntimeHysteriaClient(t, app, "phone-1")
	if len(app.sup.applyCalls) != 1 {
		t.Fatalf("first Hysteria inbound was not applied: %v", app.sup.applyCalls)
	}
	second := createRuntimeHysteriaClient(t, app, "phone-2")
	if len(handler.added) != 1 || handler.added[0] != second.Email || len(app.handler.addCall) != 0 {
		t.Fatalf("Hysteria profile did not use only its live user API: Hysteria=%v VLESS=%v", handler.added, app.handler.addCall)
	}
	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+first.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"protocol":"hysteria2"`) || !strings.Contains(profile.Body.String(), `"hysteria_uri":"hysteria2://`) || strings.Contains(profile.Body.String(), `"uri":`) {
		t.Fatalf("Hysteria profile response = %d %s", profile.Code, profile.Body.String())
	}
	var delivered struct {
		HysteriaURI string `json:"hysteria_uri"`
	}
	if err := json.Unmarshal(profile.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(delivered.HysteriaURI)
	if err != nil || uri.Query().Get("sni") != "cert.example.test" || uri.Query().Has("insecure") || uri.User.Username() != first.HysteriaAuth {
		t.Fatalf("custom certificate profile must verify its DNS name: %q, %v", delivered.HysteriaURI, err)
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/"+first.ID+"/profile?format=hysteria-qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() < 8 {
		t.Fatalf("Hysteria QR response = %d %v", qr.Code, qr.Header())
	}
	handler.addErr = errors.New("Hysteria AddUser failed")
	app.sup.applyErrors = []error{errors.New("validated fallback failed")}
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "phone-3"}, true)
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("failed Hysteria AddUser status = %d %s", failed.Code, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 2 {
		t.Fatalf("failed profile remained in database: %v, %v", clients, err)
	}
	if len(app.handler.users) != 0 || len(handler.users) != 1 || handler.users[0] != second.Email {
		t.Fatalf("failed Hysteria creation changed runtime users: Hysteria=%v VLESS=%v", handler.users, app.handler.users)
	}
}

func TestVMessProfilesUseCertificateAndLiveUserLifecycle(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer

	first := createRuntimeVMessClient(t, app, "macbook")
	if first.UUID == "" || first.ShortID != "" || !first.VMessCanConnect() || len(app.sup.applyCalls) != 1 || len(replacer.calls) != 0 || len(handler.added) != 0 || !hasInboundTag(filepath.Join(app.server.configDir, "active.json"), xray.VMessInboundTag) {
		t.Fatalf("first VMess profile lifecycle: client=%+v apply=%v replace=%v AddUser=%v", first, app.sup.applyCalls, replacer.calls, handler.added)
	}
	second := createRuntimeVMessClient(t, app, "iphone")
	if len(handler.added) != 1 || handler.added[0] != second.Email || len(app.handler.addCall) != 0 {
		t.Fatalf("subsequent VMess profile did not use its live inbound: VMess=%v VLESS=%v", handler.added, app.handler.addCall)
	}

	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"protocol":"vmess"`) || !strings.Contains(profile.Body.String(), `"vmess_uri":"vmess://`) || strings.Contains(profile.Body.String(), `"uri":`) {
		t.Fatalf("VMess profile response = %d %s", profile.Code, profile.Body.String())
	}
	var delivery struct {
		VMessURI string `json:"vmess_uri"`
	}
	if err := json.Unmarshal(profile.Body.Bytes(), &delivery); err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(delivery.VMessURI, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode VMess share link: %v", err)
	}
	var share struct {
		Address string `json:"add"`
		Port    string `json:"port"`
		ID      string `json:"id"`
		SNI     string `json:"sni"`
		TLS     string `json:"tls"`
	}
	if err := json.Unmarshal(decoded, &share); err != nil || share.Address != "vpn.example.test" || share.Port != "9443" || share.ID != second.UUID || share.SNI != "cert.example.test" || share.TLS != "tls" {
		t.Fatalf("VMess share fields = %+v, err=%v", share, err)
	}
	jsonProfile := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile?format=json", nil, true)
	if jsonProfile.Code != http.StatusOK || !strings.Contains(jsonProfile.Body.String(), `"protocol": "vmess"`) || !strings.Contains(jsonProfile.Body.String(), `"serverName": "cert.example.test"`) {
		t.Fatalf("VMess JSON profile = %d %s", jsonProfile.Code, jsonProfile.Body.String())
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile?format=vmess-qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() < 8 {
		t.Fatalf("VMess QR response = %d %v", qr.Code, qr.Header())
	}

	disabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/disable", nil, true)
	if disabled.Code != http.StatusOK || len(handler.removed) != 1 || handler.removed[0] != second.Email {
		t.Fatalf("VMess disable = %d removals=%v body=%s", disabled.Code, handler.removed, disabled.Body.String())
	}
	enabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/enable", nil, true)
	if enabled.Code != http.StatusOK || len(handler.added) != 2 || handler.added[1] != second.Email {
		t.Fatalf("VMess enable = %d additions=%v body=%s", enabled.Code, handler.added, enabled.Body.String())
	}
	revoked := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/revoke", nil, true)
	if revoked.Code != http.StatusOK || len(handler.removed) != 2 || handler.removed[1] != second.Email {
		t.Fatalf("VMess revoke = %d removals=%v body=%s", revoked.Code, handler.removed, revoked.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/enable", nil, true).Code; got != http.StatusConflict {
		t.Fatalf("enable revoked VMess profile = %d", got)
	}
}

func TestShadowsocksProfilesUseLiveUserLifecycleAndDelivery(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Setenv("XRAY_SHADOWSOCKS_METHOD", domain.ShadowsocksMethod2022AES256GCM)
	t.Setenv("XRAY_SHADOWSOCKS_NETWORK", domain.ShadowsocksNetworkTCPUDP)
	app := newTestApp(t, true)
	handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler

	first := createRuntimeShadowsocksClient(t, app, "phone-1")
	if first.ShadowsocksPasswordEnc == "" || len(app.sup.applyCalls) != 1 || len(handler.added) != 0 {
		t.Fatalf("first Shadowsocks profile lifecycle: client=%+v apply=%v additions=%v", first, app.sup.applyCalls, handler.added)
	}
	second := createRuntimeShadowsocksClient(t, app, "phone-2")
	if len(handler.added) != 1 || handler.added[0] != second.Email || len(handler.methods) != 1 || handler.methods[0] != domain.ShadowsocksMethod2022AES256GCM {
		t.Fatalf("subsequent Shadowsocks profile did not use live user API: additions=%v methods=%v", handler.added, handler.methods)
	}

	profile := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile", nil, true)
	if profile.Code != http.StatusOK || !strings.Contains(profile.Body.String(), `"protocol":"shadowsocks"`) || !strings.Contains(profile.Body.String(), `"ss_uri":"ss://`) || strings.Contains(profile.Body.String(), `"uri":`) {
		t.Fatalf("Shadowsocks profile response = %d %s", profile.Code, profile.Body.String())
	}
	jsonProfile := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile?format=json", nil, true)
	if jsonProfile.Code != http.StatusOK || !strings.Contains(jsonProfile.Body.String(), `"method": "2022-blake3-aes-256-gcm"`) || !strings.Contains(jsonProfile.Body.String(), `"password": "`) {
		t.Fatalf("Shadowsocks JSON profile = %d %s", jsonProfile.Code, jsonProfile.Body.String())
	}
	qr := requestJSON(t, app, http.MethodGet, "/api/clients/"+second.ID+"/profile?format=ss-qr", nil, true)
	if qr.Code != http.StatusOK || qr.Header().Get("Content-Type") != "image/png" || qr.Body.Len() < 8 {
		t.Fatalf("Shadowsocks QR response = %d %v", qr.Code, qr.Header())
	}
	disabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/disable", nil, true)
	if disabled.Code != http.StatusOK || len(handler.removed) != 1 || handler.removed[0] != second.Email {
		t.Fatalf("Shadowsocks disable = %d removals=%v body=%s", disabled.Code, handler.removed, disabled.Body.String())
	}
	enabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/enable", nil, true)
	if enabled.Code != http.StatusOK || len(handler.added) != 2 {
		t.Fatalf("Shadowsocks enable = %d additions=%v body=%s", enabled.Code, handler.added, enabled.Body.String())
	}
	revoked := requestJSON(t, app, http.MethodPost, "/api/clients/"+second.ID+"/revoke", nil, true)
	if revoked.Code != http.StatusOK || len(handler.removed) != 2 {
		t.Fatalf("Shadowsocks revoke = %d removals=%v body=%s", revoked.Code, handler.removed, revoked.Body.String())
	}
}

func TestNewShadowsocksPasswordIsAStandardBase64SS2022Key(t *testing.T) {
	value, err := newShadowsocksPassword()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("new SS2022 password = %q, decoded bytes=%d, error=%v", value, len(decoded), err)
	}
}

func TestRendererClientsNormalizeLegacyShadowsocksKeysWithoutChangingBytes(t *testing.T) {
	masterKey := bytes.Repeat([]byte("m"), 32)
	legacyBytes := bytes.Repeat([]byte{0xfb}, 32)
	legacyKey := base64.RawURLEncoding.EncodeToString(legacyBytes)
	sealed, err := secret.Seal(masterKey, legacyKey, "shadowsocks_password")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := rendererClientsWithSecrets(masterKey, []domain.Client{{ID: "legacy-ss", ShadowsocksPasswordEnc: sealed}})
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(legacyBytes)
	if len(clients) != 1 || clients[0].ShadowsocksPassword != want {
		t.Fatalf("normalized legacy Shadowsocks credential = %+v, want %q", clients, want)
	}
	opened, err := secret.Open(masterKey, sealed, "shadowsocks_password")
	if err != nil || opened != legacyKey {
		t.Fatalf("normalization changed the stored credential: open=%q error=%v", opened, err)
	}
}

func TestShadowsocksStateMutationFailuresPreservePersistedAccess(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Setenv("XRAY_SHADOWSOCKS_METHOD", domain.ShadowsocksMethod2022AES256GCM)
	t.Setenv("XRAY_SHADOWSOCKS_NETWORK", domain.ShadowsocksNetworkTCPUDP)
	app := newTestApp(t, true)
	handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeShadowsocksClient(t, app, "first-phone")
	client := createRuntimeShadowsocksClient(t, app, "second-phone")

	handler.removeErr = errors.New("remove Shadowsocks peer rejected")
	response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
	stored, err := app.server.store.GetClient(t.Context(), client.ID)
	if response.Code != http.StatusBadGateway || err != nil || !stored.ShadowsocksEnabled || stored.ShadowsocksRevoked {
		t.Fatalf("failed Shadowsocks disable = %d, stored=%+v, err=%v", response.Code, stored, err)
	}
	handler.removeErr = nil
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
		t.Fatalf("disable Shadowsocks before add failure = %d %s", response.Code, response.Body.String())
	}

	handler.addErr = errors.New("add Shadowsocks peer rejected")
	response = requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
	stored, err = app.server.store.GetClient(t.Context(), client.ID)
	if response.Code != http.StatusBadGateway || err != nil || stored.ShadowsocksEnabled {
		t.Fatalf("failed Shadowsocks enable = %d, stored=%+v, err=%v", response.Code, stored, err)
	}
	handler.addErr = nil
	if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true); response.Code != http.StatusOK {
		t.Fatalf("enable Shadowsocks before revoke failure = %d %s", response.Code, response.Body.String())
	}

	handler.removeErr = errors.New("revoke Shadowsocks peer rejected")
	response = requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/revoke", nil, true)
	stored, err = app.server.store.GetClient(t.Context(), client.ID)
	if response.Code != http.StatusBadGateway || err != nil || !stored.ShadowsocksEnabled || stored.ShadowsocksRevoked {
		t.Fatalf("failed Shadowsocks revoke = %d, stored=%+v, err=%v", response.Code, stored, err)
	}
}

func TestShadowsocksProfileRejectsUnavailableCredentialsAndDisabledTransport(t *testing.T) {
	t.Run("transport disabled", func(t *testing.T) {
		t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "false")
		app := newTestApp(t, true)
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolShadowsocks), Name: "phone"}, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "transport_disabled") {
			t.Fatalf("disabled Shadowsocks creation = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("invalid listener port", func(t *testing.T) {
		t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
		t.Setenv("XRAY_SHADOWSOCKS_PORT", "443")
		app := newTestApp(t, true)
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolShadowsocks), Name: "phone"}, true)
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "transport_disabled") {
			t.Fatalf("invalid Shadowsocks port creation = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestShadowsocksProfileFailsClosedWhenStoredPasswordCannotBeDecrypted(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	client := createRuntimeShadowsocksClient(t, app, "phone")
	execSQLiteTestMutation(t, app, "corrupt stored Shadowsocks credential", `UPDATE clients SET shadowsocks_password_enc='invalid-envelope' WHERE id='`+client.ID+`'`)
	response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile", nil, true)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not decrypt Shadowsocks password") {
		t.Fatalf("corrupt Shadowsocks profile delivery = %d %s", response.Code, response.Body.String())
	}
}

func TestShadowsocksCreationFallsBackToFullApplyWhenLiveHandlerIsUnavailable(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	// The first profile creates the optional inbound through a full apply. The
	// generic handler deliberately lacks the Shadowsocks extension, so the next
	// profile must use the same safe fallback instead of silently persisting a
	// user that Xray did not receive.
	createRuntimeShadowsocksClient(t, app, "phone-1")
	applyCalls := len(app.sup.applyCalls)
	createRuntimeShadowsocksClient(t, app, "phone-2")
	if len(app.sup.applyCalls) != applyCalls+1 {
		t.Fatalf("Shadowsocks handler-unavailable fallback applied %d times, before=%d after=%d", len(app.sup.applyCalls), applyCalls, len(app.sup.applyCalls))
	}
}

func TestShadowsocksCreationFallsBackWhenLiveAddFails(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeShadowsocksClient(t, app, "phone-1")
	applyCalls := len(app.sup.applyCalls)
	handler.addErr = errors.New("live Shadowsocks add failed")
	createRuntimeShadowsocksClient(t, app, "phone-2")
	if len(app.sup.applyCalls) != applyCalls+1 {
		t.Fatalf("Shadowsocks add failure did not fall back to apply: before=%d after=%d", applyCalls, len(app.sup.applyCalls))
	}
}

func TestShadowsocksCreationRollsBackProfileWhenFallbackApplyFails(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeShadowsocksClient(t, app, "phone-1")
	applyCalls := len(app.sup.applyCalls)
	handler.addErr = errors.New("live add unavailable")
	app.sup.applyErrors = []error{errors.New("fallback apply rejected")}
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolShadowsocks), Name: "phone-2"}, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "fallback apply rejected") || !strings.Contains(response.Body.String(), "live add unavailable") {
		t.Fatalf("failed fallback response = %d %s", response.Code, response.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 1 || clients[0].Name != "phone-1" {
		t.Fatalf("failed Shadowsocks create remained persisted: %+v, %v", clients, err)
	}
	if len(app.sup.applyCalls) != applyCalls+1 {
		t.Fatalf("failed fallback Xray apply calls = %d, want %d", len(app.sup.applyCalls), applyCalls+1)
	}
}

func TestShadowsocksProfileCreationReportsEncryptionSetupErrors(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	app.server.masterKey = []byte("too-short")
	if _, err := app.server.createProtocolClient(t.Context(), settings, domain.ProtocolShadowsocks, "phone", "", "", app.admin.ID); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("invalid master key create error = %v", err)
	}
}

func TestShadowsocksReconcilerRepairsLiveRoster(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler, users: []string{"stale@example.test"}}
	app.server.handler = handler
	client := createRuntimeShadowsocksClient(t, app, "phone")
	// The profile creation path used a full apply; emulate an empty live
	// Shadowsocks roster so reconciliation has to add the persisted user and
	// remove a stale one through the protocol-specific HandlerService methods.
	handler.users = []string{"stale@example.test"}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatalf("reconcile Shadowsocks roster: %v", err)
	}
	if len(handler.removed) != 1 || handler.removed[0] != "stale@example.test" || len(handler.added) != 1 || handler.added[0] != client.Email {
		t.Fatalf("reconciled Shadowsocks roster: removed=%v added=%v", handler.removed, handler.added)
	}
}

func TestShadowsocksReconcilerReportsHandlerCapabilityAndCredentialFailures(t *testing.T) {
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	t.Run("handler unavailable", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeShadowsocksClient(t, app, "phone")
		app.server.handler = app.handler
		if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Shadowsocks HandlerService is unavailable") {
			t.Fatalf("missing Shadowsocks handler error = %v", err)
		}
	})
	t.Run("stale roster error", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &recordingShadowsocksHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		createRuntimeShadowsocksClient(t, app, "phone")
		handler.listErr = errors.New("Shadowsocks roster unavailable")
		if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "roster unavailable") {
			t.Fatalf("Shadowsocks roster error = %v", err)
		}
	})
}

func TestVMessCreationRequiresAValidSharedTLSCertificate(t *testing.T) {
	app := newTestApp(t, true)
	if err := os.Remove(filepath.Join(app.server.dataDir, "hysteria-tls", "fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolVMess), Name: "macbook"}, true)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"certificate_not_ready"`) {
		t.Fatalf("VMess profile without certificate = %d %s", response.Code, response.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 0 {
		t.Fatalf("certificate validation persisted profiles: %v, %v", clients, err)
	}
}

func TestProtocolSpecificProfilesKeepAccessAndCredentialsIsolated(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler

	vless := createRuntimeTestClient(t, app, "phone")
	hysteria := createRuntimeHysteriaClient(t, app, "phone")
	if vless.Protocol != domain.ProtocolVLESS || vless.UUID == "" || vless.ShortID == "" || vless.HysteriaAuth != "" {
		t.Fatalf("VLESS profile credentials = %+v", vless)
	}
	if hysteria.Protocol != domain.ProtocolHysteria2 || hysteria.UUID != "" || hysteria.ShortID != "" || hysteria.HysteriaAuth == "" {
		t.Fatalf("Hysteria profile credentials = %+v", hysteria)
	}
	if len(app.handler.addCall) != 0 || len(handler.added) != 1 || handler.added[0] != hysteria.Email {
		t.Fatalf("profile creation mutated the wrong inbound: VLESS=%v Hysteria=%v", app.handler.addCall, handler.added)
	}

	list := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), vless.UUID) || strings.Contains(list.Body.String(), hysteria.HysteriaAuth) {
		t.Fatalf("client list exposed protocol credentials: %d %s", list.Code, list.Body.String())
	}
	var listed []clientResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].VLESS == nil || listed[0].Hysteria2 != nil || listed[1].VLESS != nil || listed[1].Hysteria2 == nil {
		t.Fatalf("typed access state in client list = %+v", listed)
	}

	handler.users = []string{hysteria.Email}
	disabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/disable", nil, true)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable Hysteria profile = %d %s", disabled.Code, disabled.Body.String())
	}
	state := decodeResponse[clientResponse](t, disabled)
	if state.Hysteria2 == nil || state.Hysteria2.Enabled || state.VLESS != nil || len(handler.removed) != 1 || len(app.handler.addCall) != 0 {
		t.Fatalf("disable changed the wrong protocol access: state=%+v Hysteria removals=%v VLESS additions=%v", state, handler.removed, app.handler.addCall)
	}

	enabled := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/enable", nil, true)
	if enabled.Code != http.StatusOK || len(handler.added) != 2 || len(app.handler.addCall) != 0 {
		t.Fatalf("enable Hysteria profile = %d Hysteria additions=%v VLESS additions=%v body=%s", enabled.Code, handler.added, app.handler.addCall, enabled.Body.String())
	}
	revoked := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/revoke", nil, true)
	if revoked.Code != http.StatusOK || len(handler.removed) != 2 {
		t.Fatalf("revoke Hysteria profile = %d Hysteria removals=%v body=%s", revoked.Code, handler.removed, revoked.Body.String())
	}
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+hysteria.ID+"/enable", nil, true).Code; got != http.StatusConflict {
		t.Fatalf("enable revoked Hysteria profile = %d", got)
	}
	storedVLESS, err := app.server.store.GetClient(t.Context(), vless.ID)
	if err != nil || !storedVLESS.VLESSCanConnect() {
		t.Fatalf("Hysteria state transitions affected VLESS profile: %+v, %v", storedVLESS, err)
	}
}

func TestClientListIncludesAccessSummariesForEveryXrayProtocol(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", domain.HysteriaTLSCustom)
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	t.Setenv("XRAY_SHADOWSOCKS_ENABLED", "true")
	t.Setenv("XRAY_SHADOWSOCKS_PORT", "8388")
	app := newTestApp(t, true)
	createRuntimeTestClient(t, app, "vless")
	createRuntimeHysteriaClient(t, app, "hysteria")
	createRuntimeVMessClient(t, app, "vmess")
	createRuntimeShadowsocksClient(t, app, "shadowsocks")
	response := requestJSON(t, app, http.MethodGet, "/api/clients", nil, true)
	if response.Code != http.StatusOK {
		t.Fatalf("client list = %d %s", response.Code, response.Body.String())
	}
	var listed []clientResponse
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, client := range listed {
		seen[string(client.Protocol)] = true
	}
	for _, protocol := range []domain.ClientProtocol{domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolVMess, domain.ProtocolShadowsocks} {
		if !seen[string(protocol)] {
			t.Errorf("client list omitted %s: %+v", protocol, listed)
		}
	}
}

func TestClientCreateRejectsOptionsFromOtherProtocolAndUnavailableHysteria(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "false")
	app := newTestApp(t, true)
	badVLESS := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "wrong-vless", Auth: "secret"}, true)
	if badVLESS.Code != http.StatusBadRequest || !strings.Contains(badVLESS.Body.String(), "auth is only valid for Hysteria") {
		t.Fatalf("VLESS accepted Hysteria auth: %d %s", badVLESS.Code, badVLESS.Body.String())
	}
	badHysteria := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "wrong-hysteria", Fingerprint: "safari"}, true)
	if badHysteria.Code != http.StatusBadRequest || !strings.Contains(badHysteria.Body.String(), "fingerprint is only valid for VLESS") {
		t.Fatalf("Hysteria accepted VLESS fingerprint: %d %s", badHysteria.Code, badHysteria.Body.String())
	}
	unavailable := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "unavailable"}, true)
	if unavailable.Code != http.StatusConflict || !strings.Contains(unavailable.Body.String(), `"code":"transport_disabled"`) {
		t.Fatalf("disabled Hysteria create = %d %s", unavailable.Code, unavailable.Body.String())
	}
}

func TestReconcilePersistsRuntimeUsersAndRepairsHysteriaRoster(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler, users: []string{"stray@example.test"}}
	app.server.handler = handler
	client := createRuntimeHysteriaClient(t, app, "phone")
	handler.added = nil
	handler.removed = nil
	app.handler.users = []string{"stray@example.test"}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(handler.removed) != 1 || handler.removed[0] != "stray@example.test" || len(handler.added) != 1 || handler.added[0] != client.Email {
		t.Fatalf("Hysteria roster was not repaired: removed=%v added=%v", handler.removed, handler.added)
	}
	active := filepath.Join(app.server.configDir, "active.json")
	if err := os.WriteFile(active, []byte(`{"inbounds":[{"tag":"vless-reality","settings":{"clients":[]}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !activeConfigUsersMatch(active, []domain.Client{client}, true) {
		t.Fatal("reconciler did not persist the Hysteria roster")
	}
	handler.listErr = errors.New("Hysteria inbound unavailable")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Hysteria inbound unavailable") {
		t.Fatalf("Hysteria list failure = %v", err)
	}
}

func TestReconcileRunningRepairsHysteriaAndVMessRostersAndReportsAPIErrors(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &reconcilingProtocolHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	vless := createRuntimeTestClient(t, app, "vless-device")
	hysteria := createRuntimeHysteriaClient(t, app, "hysteria-device")
	vmess := createRuntimeVMessClient(t, app, "vmess-device")
	disabled := seedTestClient(t, app, "disabled-device")
	if err := app.server.store.SetClientState(t.Context(), disabled.ID, false, false); err != nil {
		t.Fatal(err)
	}

	// Simulate state drift from a stale Xray process: active peers are missing,
	// while disabled and unrecognized users remain in each inbound.
	handler.users = []string{disabled.Email, "stray-vless@xray-easy"}
	handler.hysteriaUsers = []string{"stray-hysteria@xray-easy"}
	handler.vmessUsers = []string{"stray-vmess@xray-easy"}
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !containsEmail(handler.users, vless.Email) || containsEmail(handler.users, disabled.Email) || containsEmail(handler.users, "stray-vless@xray-easy") {
		t.Fatalf("reconciled VLESS users = %v", handler.users)
	}
	if len(handler.hysteriaUsers) != 1 || handler.hysteriaUsers[0] != hysteria.Email {
		t.Fatalf("reconciled Hysteria users = %v", handler.hysteriaUsers)
	}
	if len(handler.vmessUsers) != 1 || handler.vmessUsers[0] != vmess.Email {
		t.Fatalf("reconciled VMess users = %v", handler.vmessUsers)
	}

	for _, tag := range []string{xray.HysteriaInboundTag, xray.VMessInboundTag} {
		handler.listTag, handler.listErr = tag, errors.New("inbound stats unavailable")
		err := app.server.reconcileRunning(t.Context())
		if err == nil || !strings.Contains(err.Error(), "inbound stats unavailable") {
			t.Errorf("reconcile with %s UsersInInbound error = %v", tag, err)
		}
	}
}

func TestProtocolSpecificClientStateTransitionsUseLiveHandlerAPIs(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	app := newTestApp(t, true)
	handler := &reconcilingProtocolHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer
	hysteria := createRuntimeHysteriaClient(t, app, "hysteria-state")
	vmess := createRuntimeVMessClient(t, app, "vmess-state")

	for _, transition := range []struct {
		id     string
		action string
	}{
		{id: hysteria.ID, action: "disable"},
		{id: hysteria.ID, action: "enable"},
		{id: hysteria.ID, action: "revoke"},
		{id: vmess.ID, action: "disable"},
		{id: vmess.ID, action: "enable"},
		{id: vmess.ID, action: "revoke"},
	} {
		response := requestJSON(t, app, http.MethodPost, "/api/clients/"+transition.id+"/"+transition.action, nil, true)
		if response.Code != http.StatusOK {
			t.Fatalf("%s %s transition = %d %s", transition.id, transition.action, response.Code, response.Body.String())
		}
	}
	if len(handler.hysteriaUsers) != 0 {
		t.Fatalf("revoked Hysteria access remained live: %v", handler.hysteriaUsers)
	}
	if len(replacer.calls) == 0 || replacer.calls[len(replacer.calls)-1][2] != xray.VMessInboundTag {
		t.Fatalf("VMess revocation did not replace its inbound: %v", replacer.calls)
	}

	// A failed live add must restore the previous protocol access state.
	vmessRecreated := createRuntimeVMessClient(t, app, "vmess-rollback")
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+vmessRecreated.ID+"/disable", nil, true).Code; got != http.StatusOK {
		t.Fatalf("disable VMess before rollback check = %d", got)
	}
	app.handler.addErr = errors.New("live VLESS add rejected")
	// This VLESS transition shares the same HandlerService but leaves the
	// VMess-only credential lifecycle unchanged.
	vless := createRuntimeTestClient(t, app, "vless-rollback")
	if got := requestJSON(t, app, http.MethodPost, "/api/clients/"+vless.ID+"/disable", nil, true).Code; got != http.StatusOK {
		t.Fatalf("disable VLESS before failure check = %d", got)
	}
	failed := requestJSON(t, app, http.MethodPost, "/api/clients/"+vless.ID+"/enable", nil, true)
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("failed live protocol add = %d %s", failed.Code, failed.Body.String())
	}
	stored, err := app.server.store.GetClient(t.Context(), vless.ID)
	if err != nil || stored.VLESSEnabled || stored.VLESSRevoked {
		t.Fatalf("failed live add did not preserve the disabled access state: %+v, %v", stored, err)
	}
}

func TestOptionalProtocolStateFailuresKeepPersistedAccessUnchanged(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	t.Setenv("XRAY_HYSTERIA2_TLS_MODE", "custom")
	t.Setenv("XRAY_HYSTERIA2_TLS_SERVER_NAME", "cert.example.test")
	t.Run("Hysteria add and remove failures", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		client := createRuntimeHysteriaClient(t, app, "hysteria-failure")
		handler.removeErr = errors.New("remove Hysteria peer rejected")
		response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "remove Hysteria peer rejected") {
			t.Fatalf("Hysteria remove failure = %d %s", response.Code, response.Body.String())
		}
		stored, err := app.server.store.GetClient(t.Context(), client.ID)
		if err != nil || !stored.HysteriaEnabled {
			t.Fatalf("failed Hysteria remove changed persisted state: %+v, %v", stored, err)
		}
		handler.removeErr = nil
		if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
			t.Fatalf("disable Hysteria before add failure = %d %s", response.Code, response.Body.String())
		}
		handler.addErr = errors.New("add Hysteria peer rejected")
		response = requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "add Hysteria peer rejected") {
			t.Fatalf("Hysteria add failure = %d %s", response.Code, response.Body.String())
		}
		stored, err = app.server.store.GetClient(t.Context(), client.ID)
		if err != nil || stored.HysteriaEnabled {
			t.Fatalf("failed Hysteria add changed persisted state: %+v, %v", stored, err)
		}
	})
	t.Run("VMess add and remove failures", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		client := createRuntimeVMessClient(t, app, "vmess-failure")
		handler.removeErr = errors.New("remove VMess peer rejected")
		response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "remove VMess peer rejected") {
			t.Fatalf("VMess remove failure = %d %s", response.Code, response.Body.String())
		}
		stored, err := app.server.store.GetClient(t.Context(), client.ID)
		if err != nil || !stored.VMessEnabled {
			t.Fatalf("failed VMess remove changed persisted state: %+v, %v", stored, err)
		}
		handler.removeErr = nil
		if response := requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/disable", nil, true); response.Code != http.StatusOK {
			t.Fatalf("disable VMess before add failure = %d %s", response.Code, response.Body.String())
		}
		handler.addErr = errors.New("add VMess peer rejected")
		response = requestJSON(t, app, http.MethodPost, "/api/clients/"+client.ID+"/enable", nil, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "add VMess peer rejected") {
			t.Fatalf("VMess add failure = %d %s", response.Code, response.Body.String())
		}
		stored, err = app.server.store.GetClient(t.Context(), client.ID)
		if err != nil || stored.VMessEnabled {
			t.Fatalf("failed VMess add changed persisted state: %+v, %v", stored, err)
		}
	})
}

func containsEmail(emails []string, target string) bool {
	for _, email := range emails {
		if email == target {
			return true
		}
	}
	return false
}

func TestRuntimeReconcilerHandlesVMessApiAvailabilityAndRosterFailures(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeVMessClient(t, app, "vmess-phone")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "VMess HandlerService is unavailable") {
		t.Fatalf("reconcile without VMess API = %v", err)
	}

	handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	handler.listErr = errors.New("VMess inbound unavailable")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "VMess inbound unavailable") {
		t.Fatalf("VMess list failure = %v", err)
	}
	handler.listErr = nil
	handler.users = []string{"stray@xray-easy"}
	handler.removeErr = errors.New("VMess user removal failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "VMess user removal failed") {
		t.Fatalf("VMess removal failure = %v", err)
	}
	handler.removeErr = nil
	handler.users = nil
	handler.addErr = errors.New("VMess user addition failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "VMess user addition failed") {
		t.Fatalf("VMess addition failure = %v", err)
	}
	handler.addErr = nil
	if err := app.server.reconcileRunning(t.Context()); err != nil {
		t.Fatalf("VMess roster did not recover after transient errors: %v", err)
	}
	if len(handler.added) == 0 || handler.added[len(handler.added)-1] != client.Email {
		t.Fatalf("VMess client was not restored to live inbound: %+v", handler.added)
	}
}

func TestRuntimeReconcilerReportsStoreAndShortIDFailures(t *testing.T) {
	t.Run("client query", func(t *testing.T) {
		app := newTestApp(t, true)
		if err := app.server.store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := app.server.reconcileRunning(t.Context()); err == nil {
			t.Fatal("reconcile succeeded with a closed store")
		}
	})
	t.Run("short ID reserve query", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTestClient(t, app, "reserve-phone")
		execSQLiteTestMutation(t, app, "drop short IDs", `DROP TABLE reality_short_ids`)
		if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "reconcile REALITY short IDs") {
			t.Fatalf("reconcile without short ID table = %v", err)
		}
	})
}

func TestProtocolClientCreationRollsBackFailedVMessAndCandidateValidation(t *testing.T) {
	t.Run("live VMess registration rejected", func(t *testing.T) {
		app := newTestApp(t, true)
		handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
		app.server.handler = handler
		createRuntimeVMessClient(t, app, "first-phone")
		handler.addErr = errors.New("VMess user rejected")
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolVMess), Name: "second-phone"}, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "VMess user rejected") {
			t.Fatalf("failed live VMess create = %d %s", response.Code, response.Body.String())
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 1 {
			t.Fatalf("failed VMess profile remained persisted: %v, %v", clients, err)
		}
	})
	t.Run("candidate rejected", func(t *testing.T) {
		app := newTestApp(t, true)
		app.sup.validateErr = errors.New("candidate rejected")
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone"}, true)
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "candidate rejected") {
			t.Fatalf("candidate validation create = %d %s", response.Code, response.Body.String())
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 0 {
			t.Fatalf("candidate-rejected profile remained persisted: %v, %v", clients, err)
		}
	})
}

func TestVLESSInboundReplacementFailureLeavesExistingClientsAndRuntimeIntact(t *testing.T) {
	app := newTestApp(t, true)
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer
	for i := 1; i <= 5; i++ {
		createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
	}
	replacer.err = errors.New("inbound replacement rejected")
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone-6"}, true)
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "inbound replacement rejected") {
		t.Fatalf("reserve-exhaustion replacement failure = %d %s", failed.Code, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 5 {
		t.Fatalf("failed inbound replacement changed profile set: %d, %v", len(clients), err)
	}
	active, err := os.ReadFile(filepath.Join(app.server.configDir, "active.json"))
	if err != nil || !strings.Contains(string(active), clients[0].ShortID) {
		t.Fatalf("failed inbound replacement changed active config: %v", err)
	}
}

func TestPersistedClientReconciliationRepairsDriftAndReportsFailures(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	active := filepath.Join(app.server.configDir, "active.json")
	stale := []byte(`{"inbounds":[{"tag":"vless-reality","settings":{"clients":[]}}]}`)
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatal(err)
	}
	if !activeConfigUsersMatch(active, []domain.Client{client}, false) {
		t.Fatal("persisted client list was not repaired")
	}
	validated := len(app.sup.validatedPath)
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err != nil || len(app.sup.validatedPath) != validated {
		t.Fatalf("matching config was needlessly rewritten: %v", err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	app.sup.validateErr = errors.New("candidate rejected")
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "candidate rejected") {
		t.Fatalf("candidate validation failure = %v", err)
	}
	app.sup.validateErr = nil
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(active, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcilePersistedClientConfigLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "promote reconciled") {
		t.Fatalf("config promotion failure = %v", err)
	}
}

func TestRealityShortIDReconciliationUsesInboundReplacementAndPreservesActiveOnFailure(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	app.server.xrayRuntime = replacer
	active := filepath.Join(app.server.configDir, "active.json")
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatalf("matching REALITY short IDs should not be replaced: %v", err)
	}
	if len(replacer.calls) != 0 {
		t.Fatal("matching inbound was replaced")
	}
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	settings := inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	settings["shortIds"] = []string{client.ShortID}
	stale, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err != nil {
		t.Fatal(err)
	}
	if len(replacer.calls) != 1 || replacer.calls[0][2] != "vless-reality" {
		t.Fatalf("REALITY drift did not replace only the VLESS inbound: %v", replacer.calls)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	replacer.err = errors.New("Xray rejected replacement")
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "Xray rejected") {
		t.Fatalf("failed replacement = %v", err)
	}
	unchanged, err := os.ReadFile(active)
	if err != nil || string(unchanged) != string(stale) {
		t.Fatalf("failed replacement changed active config: %v", err)
	}
	if err := os.WriteFile(active, []byte("invalid JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("invalid active config error = %v", err)
	}
}

func TestClientCreateFallsBackToValidatedApplyWhenLiveAPIIsUnavailable(t *testing.T) {
	t.Run("first apply failure", func(t *testing.T) {
		app := newTestApp(t, true)
		app.sup.applyErrors = []error{errors.New("first apply failed")}
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "phone"}, true)
		if response.Code != http.StatusBadGateway {
			t.Fatalf("failed initial apply status = %d %s", response.Code, response.Body.String())
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 0 {
			t.Fatalf("failed initial apply persisted a client: %v, %v", clients, err)
		}
	})
	t.Run("missing live handler", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTestClient(t, app, "first")
		app.server.handler = nil
		createRuntimeTestClient(t, app, "second")
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("missing live handler did not use Xray runtime apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("AddUser failure", func(t *testing.T) {
		app := newTestApp(t, true)
		createRuntimeTestClient(t, app, "first")
		app.handler.addErr = errors.New("live AddUser unavailable")
		createRuntimeTestClient(t, app, "second")
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("AddUser failure did not use Xray runtime apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("reserve exhaustion without replacer", func(t *testing.T) {
		app := newTestApp(t, true)
		for i := 0; i < 6; i++ {
			createRuntimeTestClient(t, app, fmt.Sprintf("phone-%d", i))
		}
		if len(app.sup.applyCalls) != 2 {
			t.Fatalf("reserve exhaustion did not fall back to Xray runtime apply: %v", app.sup.applyCalls)
		}
	})
	t.Run("missing Hysteria handler", func(t *testing.T) {
		t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
		app := newTestApp(t, true)
		first := createRuntimeHysteriaClient(t, app, "first")
		response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "second"}, true)
		if response.Code != http.StatusCreated || len(app.handler.users) != 0 || len(app.sup.applyCalls) != 2 {
			t.Fatalf("missing Hysteria API should use validated apply fallback = %d, VLESS users=%v applies=%v", response.Code, app.handler.users, app.sup.applyCalls)
		}
		clients, err := app.server.store.ListClients(t.Context())
		if err != nil || len(clients) != 2 || clients[0].Protocol != domain.ProtocolHysteria2 || clients[1].Protocol != domain.ProtocolHysteria2 || first.UUID != "" {
			t.Fatalf("missing Hysteria API fallback created wrong profiles: %+v, %v", clients, err)
		}
	})
}

func TestHysteriaClientCreateRollsBackLiveUserWhenConfigPromotionFails(t *testing.T) {
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeTestClient(t, app, "first-vless")
	active := filepath.Join(app.server.configDir, "active.json")
	handler.afterAdd = func() {
		if err := os.Remove(active); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(active, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolHysteria2), Name: "second"}, true)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("failed config promotion status = %d %s", response.Code, response.Body.String())
	}
	if len(handler.removed) != 1 || len(handler.users) != 0 || len(app.handler.users) != 0 {
		t.Fatalf("live users were not rolled back: Hysteria=%v VLESS=%v", handler.removed, app.handler.users)
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 1 {
		t.Fatalf("failed config promotion persisted a client: %v, %v", clients, err)
	}
}

func TestRealityShortIDReconciliationRollsBackInboundWhenPromotionFails(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	active := filepath.Join(app.server.configDir, "active.json")
	content, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(content, &config); err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["shortIds"] = []string{client.ShortID}
	stale, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	replacer := &recordingInboundReplacer{fakeXrayRuntime: app.sup}
	changed := false
	replacer.hook = func() {
		if changed {
			return
		}
		changed = true
		if err := os.Remove(active); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(active, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	app.server.xrayRuntime = replacer
	if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "promote reconciled") {
		t.Fatalf("failed promotion = %v", err)
	}
	if len(replacer.calls) != 2 || !strings.HasSuffix(replacer.calls[1][3], "-rollback") {
		t.Fatalf("inbound was not rolled back after failed promotion: %v", replacer.calls)
	}
}

func TestRuntimeReconcilerHandlesFirstSetupAndHysteriaAPIFailures(t *testing.T) {
	firstRun := newTestApp(t, false)
	if err := firstRun.server.reconcileRunning(t.Context()); err != nil {
		t.Fatalf("reconciliation before first setup: %v", err)
	}
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "true")
	app := newTestApp(t, true)
	handler := &recordingHysteriaHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	createRuntimeHysteriaClient(t, app, "phone")
	app.server.handler = app.handler
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "Hysteria 2 HandlerService") {
		t.Fatalf("missing Hysteria API = %v", err)
	}
	app.server.handler = handler
	handler.users = []string{"stray@example.test"}
	handler.removeErr = errors.New("remove Hysteria user failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "remove Hysteria user failed") {
		t.Fatalf("Hysteria removal failure = %v", err)
	}
	handler.removeErr = nil
	handler.users = nil
	handler.addErr = errors.New("add Hysteria user failed")
	if err := app.server.reconcileRunning(t.Context()); err == nil || !strings.Contains(err.Error(), "add Hysteria user failed") {
		t.Fatalf("Hysteria addition failure = %v", err)
	}
}

func TestProfileRejectsHysteriaQRWhenOptionalInboundIsDisabled(t *testing.T) {
	app := newTestApp(t, true)
	client := createRuntimeTestClient(t, app, "phone")
	response := requestJSON(t, app, http.MethodGet, "/api/clients/"+client.ID+"/profile?format=hysteria-qr", nil, true)
	if response.Code != http.StatusConflict {
		t.Fatalf("disabled Hysteria QR status = %d %s", response.Code, response.Body.String())
	}
}
