package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"xray-easy/internal/auth"
	"xray-easy/internal/store"
	"xray-easy/internal/ui"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

type server struct {
	store     *store.Store
	masterKey []byte
}

type initializeRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PublicHost string `json:"public_host"`
	PublicPort int    `json:"public_port"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
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
	s := &server{store: db, masterKey: masterKey}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", s.healthz)
	mux.HandleFunc("/api/readyz", s.readyz)
	mux.HandleFunc("/api/setup/status", s.setupStatus)
	mux.HandleFunc("/api/setup/initialize", s.initialize)
	mux.HandleFunc("/api/auth/login", s.login)
	mux.HandleFunc("/api/auth/logout", s.logout)
	mux.HandleFunc("/api/me", s.me)
	mux.Handle("/", ui.Handler())
	serverHTTP := &http.Server{Addr: envOr("XRAY_EASY_LISTEN", "127.0.0.1:8080"), Handler: requestLimit(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
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
	writeJSON(w, http.StatusOK, status)
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
	if req.PublicPort == 0 {
		req.PublicPort = 443
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 || strings.TrimSpace(req.PublicHost) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_host and a valid public_port are required"})
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
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
	admin, err := s.store.FindAdmin(r.Context(), req.Username)
	if err != nil || !auth.VerifyPassword(req.Password, admin.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	token, err := s.store.CreateSession(r.Context(), admin.ID, 3*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int((3 * time.Hour) / time.Second)})
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username, "expires_in": int((3 * time.Hour) / time.Second)})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if token := sessionToken(r); token != "" {
		_ = s.store.DeleteSession(r.Context(), token)
	}
	http.SetCookie(w, &http.Cookie{Name: "xray_easy_session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": admin.Username})
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
