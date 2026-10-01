package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xray-easy/internal/auth"
	"xray-easy/internal/diagnostics"
	"xray-easy/internal/domain"
	"xray-easy/internal/secret"
	"xray-easy/internal/store"
	"xray-easy/internal/xray"
)

type fakeXrayRuntime struct {
	mu            sync.Mutex
	status        domain.XrayRuntimeStatus
	logs          []string
	probeErr      error
	validateErr   error
	statusErr     error
	logsErr       error
	applyErrors   []error
	applyHook     func(string, string)
	probes        [][2]string
	validatedPath []string
	applyCalls    [][2]string
}

func (f *fakeXrayRuntime) Validate(_ context.Context, path, operationID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validatedPath = append(f.validatedPath, path)
	return f.validateErr
}

func (f *fakeXrayRuntime) Apply(_ context.Context, path, operationID string) error {
	f.mu.Lock()
	f.applyCalls = append(f.applyCalls, [2]string{path, operationID})
	hook := f.applyHook
	if len(f.applyErrors) == 0 {
		f.mu.Unlock()
		if hook != nil {
			hook(path, operationID)
		}
		return nil
	}
	err := f.applyErrors[0]
	f.applyErrors = f.applyErrors[1:]
	f.mu.Unlock()
	if hook != nil {
		hook(path, operationID)
	}
	return err
}

func (f *fakeXrayRuntime) ProbeTarget(_ context.Context, target, sni string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes = append(f.probes, [2]string{target, sni})
	return f.probeErr
}

func (f *fakeXrayRuntime) Status(context.Context) (domain.XrayRuntimeStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *fakeXrayRuntime) Logs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.logs...), f.logsErr
}

type fakeXrayHandler struct {
	mu        sync.Mutex
	users     []string
	usersErr  error
	addErr    error
	remove    map[string]bool
	addCall   [][3]string
	userAdded chan string
}

func (f *fakeXrayHandler) Users(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.usersErr != nil {
		return nil, f.usersErr
	}
	return append([]string(nil), f.users...), nil
}

func (f *fakeXrayHandler) AddUser(_ context.Context, email, uuid, flow string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCall = append(f.addCall, [3]string{email, uuid, flow})
	if f.addErr != nil {
		return f.addErr
	}
	f.users = append(f.users, email)
	if f.userAdded != nil {
		select {
		case f.userAdded <- email:
		default:
		}
	}
	return nil
}

func (f *fakeXrayHandler) RemoveUser(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remove != nil && f.remove[email] {
		return errors.New("remove failed")
	}
	filtered := f.users[:0]
	for _, current := range f.users {
		if current != email {
			filtered = append(filtered, current)
		}
	}
	f.users = filtered
	return nil
}

type testApp struct {
	server  *server
	admin   store.Admin
	token   string
	sup     *fakeXrayRuntime
	handler *fakeXrayHandler
}

var (
	testAdminPasswordHashOnce sync.Once
	testAdminPasswordHash     string
	testAdminPasswordHashErr  error
)

func sharedTestAdminPasswordHash(t *testing.T) string {
	t.Helper()
	testAdminPasswordHashOnce.Do(func() {
		testAdminPasswordHash, testAdminPasswordHashErr = auth.HashPassword("correct horse battery")
	})
	if testAdminPasswordHashErr != nil {
		t.Fatalf("hash test admin password: %v", testAdminPasswordHashErr)
	}
	return testAdminPasswordHash
}

func newTestApp(t *testing.T, initialized bool) testApp {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "xray")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestHysteriaCertificate(t, filepath.Join(dataDir, "hysteria-tls"))
	db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sup := &fakeXrayRuntime{status: domain.XrayRuntimeStatus{Protocol: "embedded-core", State: "running", StartedAt: time.Now().UTC()}, logs: []string{"Info: connected", "Warning: sample", `error privateKey="hidden"`}}
	handler := &fakeXrayHandler{}
	app := testApp{sup: sup, handler: handler}
	s := &server{
		store: db, masterKey: []byte("0123456789abcdef0123456789abcdef"), configDir: configDir,
		publicPort: 443, vmessPort: 9443, dataDir: dataDir, maintenancePath: filepath.Join(dataDir, "maintenance.lock"),
		defaultAPIListen: "127.0.0.1:10085", xrayRuntime: sup, handler: handler,
		pendingSettings: make(map[string]pendingSettingsChange), eventSubs: make(map[chan struct{}]struct{}),
		diagnosticBuffer: diagnostics.NewBuffer(200), pendingTOTP: make(map[string]pendingTOTP),
	}
	app.server = s
	if initialized {
		admin, err := db.Initialize(context.Background(), "admin", sharedTestAdminPasswordHash(t), "vpn.example.test", 443)
		if err != nil {
			t.Fatal(err)
		}
		privateKey, publicKey, err := xray.NewRealityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := secret.Seal(s.masterKey, privateKey, "reality_private_key")
		if err != nil {
			t.Fatal(err)
		}
		settings, err := db.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		settings.XrayAPIListen = "127.0.0.1:10085"
		settings.RealityTarget = "www.example.com:443"
		settings.RealitySNI = "www.example.com"
		settings.RealityPrivateKeyEnc = encrypted
		settings.RealityPublicKey = publicKey
		settings.ClientFingerprint = "chrome"
		if err := db.UpdateSettings(context.Background(), settings); err != nil {
			t.Fatal(err)
		}
		token, err := db.CreateSession(context.Background(), admin.ID, 3*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		app.admin, app.token = admin, token
	}
	return app
}

func writeTestHysteriaCertificate(t *testing.T, directory string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn.example.test"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		DNSNames:    []string{"vpn.example.test", "cert.example.test"},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"fullchain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"privkey.pem":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTestMkcertMaterial(t *testing.T, directory string, ipv4 string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	certificate := x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ipv4},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ipv4)},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, content := range map[string][]byte{"leaf.pem": certPEM, "key.pem": keyPEM, "ca.pem": certPEM} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func requestJSON(t *testing.T, app testApp, method, path string, payload any, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if authenticated {
		request.AddCookie(&http.Cookie{Name: "xray_easy_session", Value: app.token})
	}
	response := httptest.NewRecorder()
	newMux(app.server).ServeHTTP(response, request)
	return response
}

func decodeResponse[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var decoded T
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response (%d): %v; body=%s", response.Code, err, response.Body.String())
	}
	return decoded
}
