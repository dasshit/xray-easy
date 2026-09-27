package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"xray-easy/internal/auth"
	"xray-easy/internal/secret"
	"xray-easy/internal/stats"
	"xray-easy/internal/store"
	"xray-easy/internal/supervisor"
	"xray-easy/internal/totp"
	"xray-easy/internal/ui"
	"xray-easy/internal/xray"
	"xray-easy/internal/xrayapi"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)
var deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
var fingerprints = map[string]bool{"chrome": true, "firefox": true, "safari": true, "edge": true, "ios": true, "android": true, "random": true}

type server struct {
	store            *store.Store
	masterKey        []byte
	configDir        string
	publicPort       int
	defaultAPIListen string
	supervisor       supervisor.Client
	stats            *stats.Manager
	handler          *xrayapi.HandlerClient
	applyMu          sync.Mutex
	totpMu           sync.Mutex
	pendingTOTP      map[string]pendingTOTP
}

type initializeRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	PublicHost    string `json:"public_host"`
	PublicPort    int    `json:"public_port"`
	RealityTarget string `json:"reality_target"`
	RealitySNI    string `json:"reality_sni"`
}

type loginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	TOTPCode     string `json:"totp_code"`
	RecoveryCode string `json:"recovery_code"`
}

type totpSetupRequest struct {
	SetupToken string `json:"setup_token"`
	Code       string `json:"code"`
}

type totpDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

type pendingTOTP struct {
	Token     string
	Secret    string
	Codes     []string
	ExpiresAt time.Time
}

type clientRequest struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

type clientResponse struct {
	store.Client
	stats.ClientStats
}

func main() {
	if len(os.Args) > 1 {
		if err := runCLI(context.Background(), os.Args[1:]); err != nil {
			fatal(err)
		}
		return
	}
	ctx := context.Background()
	dataDir := envOr("XRAY_EASY_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		fatal(err)
	}
	masterKey, err := loadMasterKey()
	if err != nil {
		fatal(err)
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		fatal(err)
	}
	defer db.Close()
	configDir := envOr("XRAY_EASY_CONFIG_DIR", "/etc/xray")
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		fatal(err)
	}
	publicPort, err := configuredPublicPort()
	if err != nil {
		fatal(err)
	}
	apiListen := envOr("XRAY_API_LISTEN", "127.0.0.1:10085")
	statsClient := xrayapi.NewStatsClient(apiListen)
	defer statsClient.Close()
	handlerClient := xrayapi.NewHandlerClient(apiListen)
	defer handlerClient.Close()
	s := &server{
		store:            db,
		masterKey:        masterKey,
		configDir:        configDir,
		publicPort:       publicPort,
		defaultAPIListen: apiListen,
		supervisor: supervisor.Client{
			BaseURL:   envOr("XRAY_SUPERVISOR_URL", "http://127.0.0.1:10086"),
			TokenFile: envOr("XRAY_SUPERVISOR_TOKEN_FILE", "/run/secrets/xray_supervisor_token"),
		},
		handler:     handlerClient,
		pendingTOTP: make(map[string]pendingTOTP),
	}
	s.stats = stats.NewManager(db, statsClient)
	s.stats.Start(ctx)
	s.startReconciler(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", s.healthz)
	mux.HandleFunc("/api/readyz", s.readyz)
	mux.HandleFunc("/api/setup/status", s.setupStatus)
	mux.HandleFunc("/api/setup/initialize", s.initialize)
	mux.HandleFunc("/api/auth/login", s.login)
	mux.HandleFunc("/api/auth/login/totp", s.loginTOTP)
	mux.HandleFunc("/api/auth/login/recovery", s.loginRecovery)
	mux.HandleFunc("/api/auth/logout", s.logout)
	mux.HandleFunc("/api/auth/logout-all", s.logoutAll)
	mux.HandleFunc("/api/auth/totp/status", s.totpStatus)
	mux.HandleFunc("/api/auth/totp/setup", s.totpSetup)
	mux.HandleFunc("/api/auth/totp/enable", s.totpEnable)
	mux.HandleFunc("/api/auth/totp/disable", s.totpDisable)
	mux.HandleFunc("/api/me", s.me)
	mux.HandleFunc("/api/settings", s.settings)
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/clients", s.clients)
	mux.HandleFunc("/api/clients/", s.clientRoute)
	mux.Handle("/", ui.Handler())
	serverHTTP := &http.Server{Addr: envOr("XRAY_EASY_LISTEN", "127.0.0.1:8080"), Handler: requestLimit(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second}
	fmt.Fprintf(os.Stderr, "xray-easy control plane listening on %s\n", serverHTTP.Addr)
	if err := serverHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func loadMasterKey() ([]byte, error) {
	encoded := strings.TrimSpace(os.Getenv("XRAY_EASY_MASTER_KEY"))
	if encoded == "" {
		return nil, errors.New("XRAY_EASY_MASTER_KEY is required; generate one with: openssl rand -base64 32")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) < 32 {
		return nil, errors.New("XRAY_EASY_MASTER_KEY must be base64 and decode to at least 32 bytes")
	}
	return key, nil
}

func runCLI(ctx context.Context, args []string) error {
	if len(args) < 2 || args[0] != "admin" {
		return errors.New("usage: xray-easy admin <logout-all|reset-totp|recovery-codes>")
	}
	dataDir := envOr("XRAY_EASY_DATA_DIR", "/data")
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	admin, err := db.FirstAdmin(ctx)
	if err != nil {
		return err
	}
	switch args[1] {
	case "logout-all":
		if err := db.DeleteAllSessions(ctx, admin.ID); err != nil {
			return fmt.Errorf("logout all sessions: %w", err)
		}
		_ = db.AddAudit(ctx, admin.ID, "auth.logout_all_cli", "admin", admin.ID, "all sessions revoked")
		fmt.Println("all admin sessions revoked")
		return nil
	case "reset-totp":
		if err := db.DisableTOTP(ctx, admin.ID); err != nil {
			return fmt.Errorf("reset TOTP: %w", err)
		}
		if err := db.DeleteAllSessions(ctx, admin.ID); err != nil {
			return fmt.Errorf("revoke sessions: %w", err)
		}
		_ = db.AddAudit(ctx, admin.ID, "auth.totp_reset_cli", "admin", admin.ID, "TOTP disabled and sessions revoked")
		fmt.Println("TOTP disabled and all admin sessions revoked")
		return nil
	case "recovery-codes":
		if !admin.TOTPEnabled {
			return errors.New("TOTP is not enabled")
		}
		codes := make([]string, 10)
		hashes := make([]string, 0, len(codes))
		for i := range codes {
			codes[i], err = totp.NewRecoveryCode()
			if err != nil {
				return err
			}
			hashes = append(hashes, auth.HashRecoveryCode(codes[i]))
		}
		if err := db.ReplaceRecoveryCodes(ctx, admin.ID, hashes); err != nil {
			return fmt.Errorf("replace recovery codes: %w", err)
		}
		_ = db.AddAudit(ctx, admin.ID, "auth.recovery_rotate_cli", "admin", admin.ID, "recovery codes replaced")
		fmt.Println("New one-time recovery codes:")
		for _, code := range codes {
			fmt.Println(code)
		}
		return nil
	default:
		return errors.New("usage: xray-easy admin <logout-all|reset-totp|recovery-codes>")
	}
}

func configuredPublicPort() (int, error) {
	value := envOr("XRAY_PUBLIC_PORT", "443")
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("XRAY_PUBLIC_PORT must be an integer between 1 and 65535")
	}
	return port, nil
}

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "database unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "master_key_loaded": len(s.masterKey) >= 32})
}

func (s *server) readyz(w http.ResponseWriter, r *http.Request) {
	s.healthz(w, r)
}

func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.store.SetupStatus(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read setup status"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"initialized": status.Initialized, "public_port": s.publicPort})
}

func (s *server) initialize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	var req initializeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if !usernamePattern.MatchString(req.Username) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "username must contain Latin letters, digits, '-' or '_' and be 3-32 characters"})
		return
	}
	if len(req.Password) < 12 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "password must contain at least 12 characters"})
		return
	}
	if req.PublicPort != 0 && req.PublicPort != s.publicPort {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_port is controlled by XRAY_PUBLIC_PORT"})
		return
	}
	req.PublicPort = s.publicPort
	if strings.TrimSpace(req.PublicHost) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_host is required"})
		return
	}
	req.RealityTarget = strings.TrimSpace(req.RealityTarget)
	req.RealitySNI = strings.TrimSpace(req.RealitySNI)
	if err := xray.ValidateTarget(req.RealityTarget, req.RealitySNI); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := s.supervisor.ProbeTarget(r.Context(), req.RealityTarget, req.RealitySNI); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "REALITY target probe failed", "detail": err.Error()})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	privateKey, publicKey, err := xray.NewRealityKeyPair()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not generate REALITY key pair"})
		return
	}
	encryptedPrivateKey, err := secret.Seal(s.masterKey, privateKey, "reality_private_key")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encrypt REALITY private key"})
		return
	}
	admin, err := s.store.Initialize(r.Context(), req.Username, hash, strings.TrimSpace(req.PublicHost), req.PublicPort)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already initialized") {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}
	settings, err := s.store.GetSettings(r.Context())
	if err == nil {
		settings.XrayAPIListen = s.defaultAPIListen
		settings.RealityTarget = req.RealityTarget
		settings.RealitySNI = req.RealitySNI
		settings.RealityPrivateKeyEnc = encryptedPrivateKey
		settings.RealityPublicKey = publicKey
		settings.ClientFingerprint = "chrome"
		if err := s.store.UpdateSettings(r.Context(), settings); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not save Xray API settings"})
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": admin.ID, "username": admin.Username})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	admin, err := s.passwordAdmin(r.Context(), req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if admin.TOTPEnabled {
		if req.TOTPCode == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "TOTP code required", "code": "totp_required"})
			return
		}
		if err := s.verifyTOTP(admin, req.TOTPCode); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid TOTP code", "code": "totp_invalid"})
			return
		}
	}
	s.issueSession(w, r, admin)
}

func (s *server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	admin, err := s.passwordAdmin(r.Context(), req.Username, req.Password)
	if err != nil || !admin.TOTPEnabled {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if err := s.verifyTOTP(admin, req.TOTPCode); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid TOTP code", "code": "totp_invalid"})
		return
	}
	s.issueSession(w, r, admin)
}

func (s *server) loginRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	admin, err := s.passwordAdmin(r.Context(), req.Username, req.Password)
	if err != nil || !admin.TOTPEnabled || auth.ValidateRecoveryCode(req.RecoveryCode) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials or recovery code"})
		return
	}
	consumed, err := s.store.ConsumeRecoveryCode(r.Context(), admin.ID, auth.HashRecoveryCode(req.RecoveryCode))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not consume recovery code"})
		return
	}
	if !consumed {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials or recovery code"})
		return
	}
	s.issueSession(w, r, admin)
}

func (s *server) passwordAdmin(ctx context.Context, username, password string) (store.Admin, error) {
	admin, err := s.store.FindAdmin(ctx, username)
	if err != nil || !auth.VerifyPassword(password, admin.PasswordHash) {
		return store.Admin{}, errors.New("invalid credentials")
	}
	return admin, nil
}

func (s *server) verifyTOTP(admin store.Admin, code string) error {
	if !admin.TOTPEnabled || admin.TOTPSecretEnc == "" {
		return errors.New("TOTP is not enabled")
	}
	secretValue, err := secret.Open(s.masterKey, admin.TOTPSecretEnc, "totp_secret")
	if err != nil || !totp.Validate(secretValue, strings.TrimSpace(code), time.Now().UTC()) {
		return errors.New("invalid TOTP code")
	}
	return nil
}

func (s *server) issueSession(w http.ResponseWriter, r *http.Request, admin store.Admin) {
	const sessionTTL = 3 * time.Hour
	token, err := s.store.CreateSession(r.Context(), admin.ID, sessionTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL / time.Second)})
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "totp_enabled": admin.TOTPEnabled, "expires_in": int(sessionTTL / time.Second)})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if token := sessionToken(r); token != "" {
		_ = s.store.DeleteSession(r.Context(), token)
	}
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) logoutAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if err := s.store.DeleteAllSessions(r.Context(), admin.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not revoke sessions"})
		return
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, "auth.logout_all", "admin", admin.ID, "all sessions revoked")
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	count, _ := s.store.RecoveryCodeCount(r.Context(), admin.ID)
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "totp_enabled": admin.TOTPEnabled, "recovery_codes_remaining": count})
}

func (s *server) totpStatus(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	count, err := s.store.RecoveryCodeCount(r.Context(), admin.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read TOTP status"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": admin.TOTPEnabled, "recovery_codes_remaining": count})
}

func (s *server) totpSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if admin.TOTPEnabled {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "TOTP is already enabled"})
		return
	}
	secretValue, err := totp.NewSecret()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	token, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create TOTP setup token"})
		return
	}
	codes := make([]string, 10)
	for i := range codes {
		codes[i], err = totp.NewRecoveryCode()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
	}
	s.totpMu.Lock()
	s.pendingTOTP[admin.ID] = pendingTOTP{Token: token, Secret: secretValue, Codes: codes, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	s.totpMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_token":    token,
		"secret":         secretValue,
		"otpauth_uri":    totp.OTPAuthURI(secretValue, "xray-easy", admin.Username),
		"recovery_codes": codes,
		"expires_in":     600,
	})
}

func (s *server) totpEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var req totpSetupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.totpMu.Lock()
	pending, ok := s.pendingTOTP[admin.ID]
	if ok && (pending.Token != req.SetupToken || time.Now().UTC().After(pending.ExpiresAt)) {
		ok = false
	}
	s.totpMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "TOTP setup expired; start again"})
		return
	}
	if !totp.Validate(pending.Secret, req.Code, time.Now().UTC()) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid TOTP code"})
		return
	}
	encrypted, err := secret.Seal(s.masterKey, pending.Secret, "totp_secret")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encrypt TOTP secret"})
		return
	}
	hashes := make([]string, 0, len(pending.Codes))
	for _, code := range pending.Codes {
		hashes = append(hashes, auth.HashRecoveryCode(code))
	}
	if err := s.store.SetTOTP(r.Context(), admin.ID, encrypted, hashes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not save TOTP settings"})
		return
	}
	s.totpMu.Lock()
	delete(s.pendingTOTP, admin.ID)
	s.totpMu.Unlock()
	_ = s.store.AddAudit(r.Context(), admin.ID, "auth.totp_enable", "admin", admin.ID, "TOTP enabled")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes_remaining": len(hashes)})
}

func (s *server) totpDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var req totpDisableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !admin.TOTPEnabled || !auth.VerifyPassword(req.Password, admin.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "password or TOTP code is invalid"})
		return
	}
	if err := s.verifyTOTP(admin, req.Code); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "password or TOTP code is invalid"})
		return
	}
	if err := s.store.DisableTOTP(r.Context(), admin.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not disable TOTP"})
		return
	}
	if err := s.store.DeleteAllSessions(r.Context(), admin.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not revoke sessions"})
		return
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, "auth.totp_disable", "admin", admin.ID, "TOTP disabled")
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if s.stats == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "statistics are unavailable"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming is unavailable"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	notifications, unsubscribe := s.stats.Subscribe()
	defer unsubscribe()

	send := func() error {
		if _, err := s.authenticated(r); err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{"type": "stats", "at": time.Now().UTC(), "clients": s.stats.Snapshot()})
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: stats\ndata: %s\n\n", payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	if err := send(); err != nil {
		return
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-notifications:
			if err := send(); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := s.authenticated(r); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *server) settings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	settings.PublicPort = s.publicPort
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, publicSettings(settings))
		return
	}
	if r.Method == http.MethodPatch {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "settings rotation is not implemented in this slice"})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, nil)
}

func (s *server) clients(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if r.Method == http.MethodGet {
		clients, err := s.store.ListClients(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list clients"})
			return
		}
		writeJSON(w, http.StatusOK, s.withStats(clients))
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	var req clientRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if !deviceNamePattern.MatchString(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name must contain ASCII letters, digits or '-' and be 1-64 characters"})
		return
	}
	fingerprint := strings.TrimSpace(req.Fingerprint)
	settings, err := s.store.GetSettings(r.Context())
	if err != nil || settings.RealityPrivateKeyEnc == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "REALITY setup is incomplete"})
		return
	}
	settings.PublicPort = s.publicPort
	if fingerprint != "" && !fingerprints[fingerprint] {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported client fingerprint"})
		return
	}
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
		return
	}
	client, err := s.createClient(r.Context(), settings, privateKey, name, fingerprint, admin.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, s.withStats([]store.Client{client})[0])
}

func (s *server) clientRoute(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client not found"})
		return
	}
	id := parts[0]
	client, err := s.store.GetClient(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.withStats([]store.Client{client})[0])
		return
	}
	if len(parts) == 2 && parts[1] == "profile" && r.Method == http.MethodGet {
		s.profile(w, r, client)
		return
	}
	if len(parts) == 2 && parts[1] == "enable" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, true, false, admin.ID)
		return
	}
	if len(parts) == 2 && parts[1] == "disable" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, false, false, admin.ID)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, false, true, admin.ID)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
}

func (s *server) createClient(ctx context.Context, settings store.Settings, privateKey, name, fingerprint, actorID string) (store.Client, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	clients, err := s.store.ListClients(ctx)
	if err != nil {
		return store.Client{}, fmt.Errorf("list clients: %w", err)
	}
	clientID, err := randomID()
	if err != nil {
		return store.Client{}, err
	}
	uuid, err := xray.NewUUID()
	if err != nil {
		return store.Client{}, err
	}
	shortID, err := xray.NewShortID()
	if err != nil {
		return store.Client{}, err
	}
	if fingerprint == "" {
		fingerprint = settings.ClientFingerprint
	}
	client := store.Client{ID: clientID, Name: name, ClientFingerprint: fingerprint, Enabled: true}
	clientEmail := "device-" + clientID + "@xray-easy"
	if err := s.store.CreateClient(ctx, client, uuid, clientEmail, shortID); err != nil {
		return store.Client{}, fmt.Errorf("create client: %w", err)
	}
	client.UUID, client.Email, client.ShortID = uuid, clientEmail, shortID
	clients = append(clients, client)
	if err := s.applyClientsLiveLocked(ctx, settings, privateKey, clients, actorID, "client.create", clientID,
		func() error { return s.handler.AddUser(ctx, client.Email, client.UUID, xray.Flow) },
		func() error { return s.handler.RemoveUser(ctx, client.Email) },
		nil, nil,
	); err != nil {
		_ = s.store.DeleteClient(ctx, clientID)
		return store.Client{}, err
	}
	return s.store.GetClient(ctx, clientID)
}

func (s *server) changeClientState(w http.ResponseWriter, r *http.Request, client store.Client, enabled, revoked bool, actorID string) {
	if client.Revoked && !revoked {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "revoked client cannot be enabled"})
		return
	}
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "settings are incomplete"})
		return
	}
	settings.PublicPort = s.publicPort
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
		return
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list clients"})
		return
	}
	for i := range clients {
		if clients[i].ID == client.ID {
			clients[i].Enabled, clients[i].Revoked = enabled, revoked
		}
	}
	oldEnabled, oldRevoked := client.Enabled, client.Revoked
	wasActive, willBeActive := oldEnabled && !oldRevoked, enabled && !revoked
	mutate := func() error { return nil }
	rollback := func() error { return nil }
	if willBeActive && !wasActive {
		mutate = func() error { return s.handler.AddUser(r.Context(), client.Email, client.UUID, xray.Flow) }
		rollback = func() error { return s.handler.RemoveUser(r.Context(), client.Email) }
	} else if wasActive && !willBeActive {
		mutate = func() error { return s.handler.RemoveUser(r.Context(), client.Email) }
		rollback = func() error { return s.handler.AddUser(r.Context(), client.Email, client.UUID, xray.Flow) }
	}
	persist := func() error { return s.store.SetClientState(r.Context(), client.ID, enabled, revoked) }
	rollbackPersist := func() error { return s.store.SetClientState(r.Context(), client.ID, oldEnabled, oldRevoked) }
	if err := s.applyClientsLiveLocked(r.Context(), settings, privateKey, clients, actorID, "client.state", client.ID, mutate, rollback, persist, rollbackPersist); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	updated, _ := s.store.GetClient(r.Context(), client.ID)
	writeJSON(w, http.StatusOK, s.withStats([]store.Client{updated})[0])
}

func (s *server) withStats(clients []store.Client) []clientResponse {
	snapshot := map[string]stats.ClientStats{}
	if s.stats != nil {
		snapshot = s.stats.Snapshot()
	}
	result := make([]clientResponse, 0, len(clients))
	for _, client := range clients {
		result = append(result, clientResponse{Client: client, ClientStats: snapshot[client.ID]})
	}
	return result
}

func (s *server) startReconciler(ctx context.Context) {
	go func() {
		reconcileCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		if err := s.reconcileRunning(reconcileCtx); err != nil {
			fmt.Fprintf(os.Stderr, "xray handler reconciliation skipped: %v\n", err)
		}
		cancel()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcileCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				if err := s.reconcileRunning(reconcileCtx); err != nil {
					fmt.Fprintf(os.Stderr, "xray handler reconciliation skipped: %v\n", err)
				}
				cancel()
			}
		}
	}()
}

func (s *server) reconcileRunning(ctx context.Context) error {
	if s.handler == nil {
		return nil
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	clients, err := s.store.ListClients(ctx)
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		return nil
	}
	running, err := s.handler.Users(ctx)
	if err != nil {
		return err
	}
	active := make(map[string]store.Client)
	for _, client := range clients {
		if client.Enabled && !client.Revoked {
			active[client.Email] = client
		}
	}
	runningSet := make(map[string]struct{}, len(running))
	for _, email := range running {
		runningSet[email] = struct{}{}
		if _, ok := active[email]; !ok {
			if err := s.handler.RemoveUser(ctx, email); err != nil {
				return err
			}
		}
	}
	for email, client := range active {
		if _, ok := runningSet[email]; ok {
			continue
		}
		if err := s.handler.AddUser(ctx, email, client.UUID, xray.Flow); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) applyClientsLocked(ctx context.Context, settings store.Settings, privateKey string, clients []store.Client, actorID, action, entityID string) error {
	path, operationID, err := s.prepareCandidateLocked(ctx, settings, privateKey, clients)
	if err != nil {
		return err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "validated", "")
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")
	if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return err
	}
	if err := s.promoteCandidateLocked(ctx, path, operationID, actorID, action, entityID); err != nil {
		// The candidate is running, but it was not promoted to the durable
		// active path. Ask the supervisor to restore the previous active file.
		_ = s.supervisor.Apply(ctx, filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
		return err
	}
	return nil
}

func (s *server) applyClientsLiveLocked(ctx context.Context, settings store.Settings, privateKey string, clients []store.Client, actorID, action, entityID string, mutate, rollback, persist, rollbackPersist func() error) error {
	path, operationID, err := s.prepareCandidateLocked(ctx, settings, privateKey, clients)
	if err != nil {
		return err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "validated", "")
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")

	liveApplied := mutate == nil
	if mutate != nil {
		if err := mutate(); err != nil {
			// A down or older Xray API must not block administration. Applying the
			// already validated full config is the recovery-compatible fallback.
			if fallbackErr := s.supervisor.Apply(ctx, path, operationID); fallbackErr != nil {
				_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", fallbackErr.Error())
				return fmt.Errorf("dynamic Xray update failed (%v), config apply failed: %w", err, fallbackErr)
			}
			liveApplied = false
		} else {
			liveApplied = true
		}
	}
	if persist != nil {
		if err := persist(); err != nil {
			if liveApplied && rollback != nil {
				_ = rollback()
			} else if !liveApplied {
				_ = s.supervisor.Apply(ctx, filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
			}
			_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
			return fmt.Errorf("persist client change: %w", err)
		}
	}
	if err := os.Rename(path, filepath.Join(s.configDir, "active.json")); err != nil {
		if rollbackPersist != nil {
			_ = rollbackPersist()
		}
		if liveApplied && rollback != nil {
			_ = rollback()
		} else if !liveApplied {
			_ = s.supervisor.Apply(ctx, filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
		}
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return fmt.Errorf("promote Xray config: %w", err)
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	_ = s.store.AddAudit(ctx, actorID, action, "client", entityID, "configuration applied")
	return nil
}

func (s *server) prepareCandidateLocked(ctx context.Context, settings store.Settings, privateKey string, clients []store.Client) (string, string, error) {
	xrayClients := make([]xray.Client, 0, len(clients))
	for _, client := range clients {
		xrayClients = append(xrayClients, xray.Client{ID: client.ID, Name: client.Name, UUID: client.UUID, Email: client.Email, ShortID: client.ShortID, ClientFingerprint: client.ClientFingerprint, Enabled: client.Enabled, Revoked: client.Revoked})
	}
	rendered, err := xray.RenderServerConfig(xray.Settings{PublicHost: settings.PublicHost, PublicPort: settings.PublicPort, XrayAPIListen: settings.XrayAPIListen, RealityTarget: settings.RealityTarget, RealitySNI: settings.RealitySNI, RealityPrivateKey: privateKey, RealityPublicKey: settings.RealityPublicKey, ClientFingerprint: settings.ClientFingerprint, InternalInboundPort: settings.InternalInboundPort}, xrayClients)
	if err != nil {
		return "", "", fmt.Errorf("render Xray config: %w", err)
	}
	operationID, err := randomID()
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	operation := store.ApplyOperation{ID: operationID, Revision: now.UnixNano(), State: "pending", CreatedAt: now, UpdatedAt: now}
	if err := s.store.CreateApplyOperation(ctx, operation); err != nil {
		return "", "", err
	}
	path := filepath.Join(s.configDir, "candidates", operationID+".json")
	if err := writeAtomic(path, rendered); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return "", "", err
	}
	if err := s.supervisor.Validate(ctx, path, operationID); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return "", "", err
	}
	return path, operationID, nil
}

func (s *server) promoteCandidateLocked(ctx context.Context, path, operationID, actorID, action, entityID string) error {
	if err := os.Rename(path, filepath.Join(s.configDir, "active.json")); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return fmt.Errorf("promote Xray config: %w", err)
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	_ = s.store.AddAudit(ctx, actorID, action, "client", entityID, "configuration applied")
	return nil
}

func (s *server) profile(w http.ResponseWriter, r *http.Request, client store.Client) {
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "settings are incomplete"})
		return
	}
	settings.PublicPort = s.publicPort
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
		return
	}
	_ = privateKey
	profile, err := xray.BuildProfile(xray.Settings{PublicHost: settings.PublicHost, PublicPort: settings.PublicPort, XrayAPIListen: settings.XrayAPIListen, RealityTarget: settings.RealityTarget, RealitySNI: settings.RealitySNI, RealityPrivateKey: "server-secret-not-exported", RealityPublicKey: settings.RealityPublicKey, ClientFingerprint: settings.ClientFingerprint, InternalInboundPort: settings.InternalInboundPort}, xray.Client{ID: client.ID, Name: client.Name, UUID: client.UUID, Email: client.Email, ShortID: client.ShortID, ClientFingerprint: client.ClientFingerprint, Enabled: client.Enabled, Revoked: client.Revoked})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	format := r.URL.Query().Get("format")
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+client.Name+`.json"`)
		_, _ = w.Write(profile.JSON)
	case "qr":
		png, err := qrcode.Encode(profile.URI, qrcode.Medium, 512)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encode QR"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"client_id": client.ID, "uri": profile.URI, "name": profile.Name, "json": json.RawMessage(profile.JSON)})
	}
}

func (s *server) authenticated(r *http.Request) (store.Admin, error) {
	token := sessionToken(r)
	if token == "" {
		return store.Admin{}, errors.New("missing session")
	}
	return s.store.SessionAdmin(r.Context(), token)
}

func sessionToken(r *http.Request) string {
	cookie, err := r.Cookie("xray_easy_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func decodeJSON(r *http.Request, target any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 1<<20 {
		return errors.New("request body is too large")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func requestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func publicSettings(settings store.Settings) map[string]any {
	return map[string]any{"public_host": settings.PublicHost, "public_port": settings.PublicPort, "reality_target": settings.RealityTarget, "reality_sni": settings.RealitySNI, "client_fingerprint": settings.ClientFingerprint, "protocol": xray.Protocol, "network": xray.Network, "security": xray.Security, "flow": xray.Flow}
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".candidate-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
