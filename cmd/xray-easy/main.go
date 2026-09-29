package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"xray-easy/internal/auth"
	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/backup"
	"xray-easy/internal/diagnostics"
	"xray-easy/internal/domain"
	"xray-easy/internal/hysteria"
	"xray-easy/internal/maintenance"
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

type server struct {
	store            *store.Store
	masterKey        []byte
	configDir        string
	publicPort       int
	vmessPort        int
	dataDir          string
	maintenancePath  string
	defaultAPIListen string
	supervisor       supervisorAPI
	stats            *stats.Manager
	awg              awgcontrol.Gateway
	handler          xrayHandlerAPI
	applyMu          sync.Mutex
	settingsMu       sync.Mutex
	pendingSettings  map[string]pendingSettingsChange
	hysteriaMu       sync.Mutex
	pendingHysteria  map[string]pendingHysteriaChange
	eventsMu         sync.Mutex
	eventSubs        map[chan struct{}]struct{}
	diagnosticBuffer *diagnostics.Buffer
	totpMu           sync.Mutex
	pendingTOTP      map[string]pendingTOTP
}

type supervisorAPI interface {
	Validate(context.Context, string, string) error
	Apply(context.Context, string, string) error
	ProbeTarget(context.Context, string, string) error
	Status(context.Context) (supervisor.Status, error)
	Logs(context.Context) ([]string, error)
}

type xrayHandlerAPI interface {
	AddUser(context.Context, string, string, string) error
	RemoveUser(context.Context, string) error
	Users(context.Context) ([]string, error)
}

type hysteriaHandlerAPI interface {
	AddHysteriaUser(context.Context, string, string) error
	RemoveHysteriaUser(context.Context, string) error
	UsersInInbound(context.Context, string) ([]string, error)
}

type vmessHandlerAPI interface {
	AddVMessUser(context.Context, string, string) error
	RemoveVMessUser(context.Context, string) error
	UsersInInbound(context.Context, string) ([]string, error)
}

type inboundReplacer interface {
	ReplaceInbound(context.Context, string, string, string, string) error
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

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type pendingTOTP struct {
	Token     string
	Secret    string
	Codes     []string
	ExpiresAt time.Time
}

type clientRequest struct {
	Protocol    string `json:"protocol"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Auth        string `json:"auth"`
}

type hysteriaSettingsRequest struct {
	Enabled          bool   `json:"enabled"`
	Host             string `json:"host"`
	TLSMode          string `json:"tls_mode"`
	TLSCertIP        string `json:"tls_cert_ip"`
	TLSServerName    string `json:"tls_server_name"`
	CertificateID    string `json:"certificate_id"`
	UDPIdleTimeout   int    `json:"udp_idle_timeout"`
	MasqueradeType   string `json:"masquerade_type"`
	MasqueradeString string `json:"masquerade_string"`
}

type hysteriaApplyRequest struct {
	ChangeID     string `json:"change_id"`
	Confirmation string `json:"confirmation"`
}

type pendingHysteriaChange struct {
	ID                   string
	AdminID              string
	Base                 domain.HysteriaSettings
	Candidate            domain.HysteriaSettings
	ExpectedConfirmation string
	Diff                 []settingsDiff
	Consequences         []string
	ExpiresAt            time.Time
	Applying             bool
}

type hysteriaSettingsResponse struct {
	Enabled          bool                      `json:"enabled"`
	State            string                    `json:"state"`
	Host             string                    `json:"host"`
	UDPPort          int                       `json:"udp_port"`
	TLSMode          string                    `json:"tls_mode"`
	TLSServerName    string                    `json:"tls_server_name"`
	TLSCertIP        string                    `json:"tls_cert_ip,omitempty"`
	CertificateID    string                    `json:"certificate_id,omitempty"`
	Certificate      *hysteria.CertificateInfo `json:"certificate,omitempty"`
	CertificateError string                    `json:"certificate_error,omitempty"`
	RuntimeError     string                    `json:"runtime_error,omitempty"`
	UDPIdleTimeout   int                       `json:"udp_idle_timeout"`
	MasqueradeType   string                    `json:"masquerade_type"`
	MasqueradeString string                    `json:"masquerade_string,omitempty"`
	InsecureURI      bool                      `json:"insecure_uri"`
}

type settingsPatchRequest struct {
	PublicHost        *string `json:"public_host"`
	RealityTarget     *string `json:"reality_target"`
	RealitySNI        *string `json:"reality_sni"`
	ClientFingerprint *string `json:"client_fingerprint"`
	LogLevel          *string `json:"log_level"`
	RotatePrivateKey  bool    `json:"rotate_private_key"`
}

type settingsApplyRequest struct {
	ChangeID     string `json:"change_id"`
	Confirmation string `json:"confirmation"`
}

type settingsDiff struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

type pendingSettingsChange struct {
	ID                   string
	AdminID              string
	BaseFingerprint      string
	ClientsFingerprint   string
	Settings             domain.Settings
	ExpectedConfirmation string
	RequiresXrayApply    bool
	Diff                 []settingsDiff
	Consequences         []string
	RevokedClients       int
	ExpiresAt            time.Time
	Applying             bool
}

type clientResponse struct {
	Protocol          domain.ClientProtocol `json:"protocol"`
	Protocols         []string              `json:"protocols"`
	VLESS             *clientAccessResponse `json:"vless,omitempty"`
	Hysteria2         *clientAccessResponse `json:"hysteria2,omitempty"`
	VMess             *clientAccessResponse `json:"vmess,omitempty"`
	ID                string                `json:"id"`
	Name              string                `json:"name"`
	ClientFingerprint string                `json:"fingerprint,omitempty"`
	Enabled           bool                  `json:"enabled"`
	Revoked           bool                  `json:"revoked"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
	Online            bool                  `json:"online"`
	LastSeen          *time.Time            `json:"last_seen,omitempty"`
	UploadBytes       int64                 `json:"upload_bytes"`
	DownloadBytes     int64                 `json:"download_bytes"`
	SourceIPs         []string              `json:"source_ips,omitempty"`
	UploadRate        float64               `json:"upload_bytes_per_second"`
	DownloadRate      float64               `json:"download_bytes_per_second"`
}

type clientAccessResponse struct {
	Enabled bool `json:"enabled"`
	Revoked bool `json:"revoked"`
}

func main() {
	if len(os.Args) > 1 {
		if err := runCLI(context.Background(), os.Args[1:]); err != nil {
			fatal(err)
		}
		return
	}
	ctx := context.Background()
	s, cleanup, err := initializeControlPlane(ctx)
	if err != nil {
		fatal(err)
	}
	defer cleanup()
	s.stats.Start(ctx)
	s.startReconciler(ctx)
	mux := newMux(s)
	serverHTTP := &http.Server{Addr: envOr("XRAY_EASY_LISTEN", "127.0.0.1:8080"), Handler: requestLimit(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second}
	fmt.Fprintf(os.Stderr, "xray-easy control plane listening on %s\n", serverHTTP.Addr)
	if err := serverHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func initializeControlPlane(ctx context.Context) (*server, func(), error) {
	dataDir := envOr("XRAY_EASY_DATA_DIR", "/data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, nil, err
	}
	masterKey, err := loadMasterKey()
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		return nil, nil, err
	}
	if err := db.InitializeHysteriaSettings(ctx, hysteriaSettingsFromEnvironment()); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("initialize Hysteria 2 settings: %w", err)
	}
	configDir := envOr("XRAY_EASY_CONFIG_DIR", "/etc/xray")
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	publicPort, err := configuredPublicPort()
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	vmessPort, err := configuredVMessPort()
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	apiListen := envOr("XRAY_API_LISTEN", "127.0.0.1:10085")
	statsClient := xrayapi.NewStatsClient(apiListen)
	defer statsClient.Close()
	handlerClient := xrayapi.NewHandlerClient(apiListen)
	defer handlerClient.Close()
	var awgClient *awgcontrol.Client
	awgAddress := strings.TrimSpace(os.Getenv("AWG_CONTROL_ADDR"))
	awgTokenPath := envOr("AWG_CONTROL_TOKEN_FILE", "/run/awg-auth/control.token")
	if awgAddress != "" && strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		if _, statErr := os.Stat(awgTokenPath); statErr == nil {
			awgClient, err = awgcontrol.Dial(awgAddress, awgTokenPath)
			if err != nil {
				_ = db.Close()
				return nil, nil, fmt.Errorf("initialize AmneziaWG control client: %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			_ = db.Close()
			return nil, nil, fmt.Errorf("inspect AmneziaWG control token: %w", statErr)
		}
	}
	s := &server{
		store:            db,
		masterKey:        masterKey,
		configDir:        configDir,
		publicPort:       publicPort,
		vmessPort:        vmessPort,
		dataDir:          dataDir,
		maintenancePath:  filepath.Join(dataDir, "maintenance.lock"),
		defaultAPIListen: apiListen,
		supervisor: supervisor.Client{
			BaseURL:   envOr("XRAY_SUPERVISOR_URL", "http://127.0.0.1:10086"),
			TokenFile: envOr("XRAY_SUPERVISOR_TOKEN_FILE", "/run/secrets/xray_supervisor_token"),
		},
		handler:          handlerClient,
		awg:              awgClient,
		pendingSettings:  make(map[string]pendingSettingsChange),
		pendingHysteria:  make(map[string]pendingHysteriaChange),
		eventSubs:        make(map[chan struct{}]struct{}),
		diagnosticBuffer: diagnostics.NewBuffer(200),
		pendingTOTP:      make(map[string]pendingTOTP),
	}
	if awgClient != nil {
		s.stats = stats.NewManager(db, statsClient, awgClient)
	} else {
		s.stats = stats.NewManager(db, statsClient)
	}
	cleanup := func() {
		_ = statsClient.Close()
		_ = handlerClient.Close()
		if awgClient != nil {
			_ = awgClient.Close()
		}
		_ = db.Close()
	}
	return s, cleanup, nil
}

func newMux(s *server) *http.ServeMux {
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
	mux.HandleFunc("/api/auth/password", s.changePassword)
	mux.HandleFunc("/api/auth/totp/status", s.totpStatus)
	mux.HandleFunc("/api/auth/totp/setup", s.totpSetup)
	mux.HandleFunc("/api/auth/totp/enable", s.totpEnable)
	mux.HandleFunc("/api/auth/totp/disable", s.totpDisable)
	mux.HandleFunc("/api/me", s.me)
	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/api/logs", s.logs)
	mux.HandleFunc("/api/settings", s.settings)
	mux.HandleFunc("/api/settings/validate", s.settingsValidate)
	mux.HandleFunc("/api/settings/apply", s.settingsApply)
	mux.HandleFunc("/api/transports/hysteria2", s.hysteriaSettingsRoute)
	mux.HandleFunc("/api/transports/hysteria2/certificate", s.hysteriaCertificateUpload)
	mux.HandleFunc("/api/transports/hysteria2/certificate/mkcert", s.hysteriaCertificateGenerate)
	mux.HandleFunc("/api/transports/hysteria2/preview", s.hysteriaSettingsPreview)
	mux.HandleFunc("/api/transports/hysteria2/apply", s.hysteriaSettingsApply)
	mux.HandleFunc("/api/transports/amneziawg", s.amneziaWGStatus)
	mux.HandleFunc("/api/transports/amneziawg/peers", s.amneziaWGPeers)
	mux.HandleFunc("/api/transports/amneziawg/peers/", s.amneziaWGPeerRoute)
	mux.HandleFunc("/api/backups", s.backups)
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/clients", s.clients)
	mux.HandleFunc("/api/clients/", s.clientRoute)
	mux.Handle("/", ui.Handler())
	return mux
}

func (s *server) backupManager() *backup.Manager {
	manager := backup.NewManager(s.store, s.dataDir, s.configDir, s.masterKey)
	if awgBackup, ok := s.awg.(backup.AWGBackup); ok {
		manager.AWG = awgBackup
	}
	return manager
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
	if len(args) == 0 {
		return cliUsageError()
	}
	dataDir := envOr("XRAY_EASY_DATA_DIR", "/data")
	configDir := envOr("XRAY_EASY_CONFIG_DIR", "/etc/xray")
	switch args[0] {
	case "doctor":
		return runDoctorCLI(ctx, args[1:], dataDir, configDir, os.Stdout)
	case "admin":
		return runAdminCLI(ctx, dataDir, args[1:])
	case "backup":
		return runBackupCLI(ctx, dataDir, configDir, args[1:])
	case "restore":
		return runRestoreCLI(ctx, dataDir, configDir, args[1:])
	default:
		return cliUsageError()
	}
}

func runAdminCLI(ctx context.Context, dataDir string, args []string) error {
	if len(args) != 1 {
		return cliUsageError()
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	admin, err := db.FirstAdmin(ctx)
	if err != nil {
		return err
	}
	switch args[0] {
	case "reset-password":
		lock, err := maintenance.Acquire(ctx, filepath.Join(dataDir, "maintenance.lock"))
		if err != nil {
			return fmt.Errorf("acquire maintenance lock: %w", err)
		}
		defer lock.Close()
		newPassword, err := readNewPassword()
		if err != nil {
			return err
		}
		defer clear(newPassword)
		passwordHash, err := auth.HashPassword(string(newPassword))
		if err != nil {
			return err
		}
		if err := db.ChangeAdminPassword(ctx, admin.ID, passwordHash); err != nil {
			return fmt.Errorf("reset administrator password: %w", err)
		}
		_ = db.AddAudit(ctx, admin.ID, "auth.password_reset_cli", "admin", admin.ID, "administrator password reset; all sessions revoked")
		fmt.Println("administrator password changed; all sessions were revoked")
		return nil
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
		return cliUsageError()
	}
}

var readCLIPassword = readPasswordLineNoEcho

func readNewPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, "New administrator password (at least 12 characters): ")
	password, err := readCLIPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read new password (use an interactive terminal; run docker compose exec without -T): %w", err)
	}
	if len(password) < 12 {
		clear(password)
		return nil, errors.New("password must contain at least 12 characters")
	}
	fmt.Fprint(os.Stderr, "Confirm new password: ")
	confirmation, err := readCLIPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		clear(password)
		return nil, fmt.Errorf("read password confirmation: %w", err)
	}
	defer clear(confirmation)
	if subtle.ConstantTimeCompare(password, confirmation) != 1 {
		clear(password)
		return nil, errors.New("passwords do not match")
	}
	return password, nil
}

func runBackupCLI(ctx context.Context, dataDir, configDir string, args []string) error {
	if len(args) != 1 || args[0] != "create" && args[0] != "list" {
		return cliUsageError()
	}
	masterKey, err := loadMasterKey()
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	lock, err := maintenance.Acquire(ctx, filepath.Join(dataDir, "maintenance.lock"))
	if err != nil {
		return fmt.Errorf("acquire maintenance lock: %w", err)
	}
	defer lock.Close()
	manager := backup.NewManager(db, dataDir, configDir, masterKey)
	if args[0] == "list" {
		items, err := manager.List()
		if err != nil {
			return err
		}
		for _, item := range items {
			fmt.Printf("%s\t%s\n", item.Name, item.CreatedAt.UTC().Format(time.RFC3339))
		}
		return nil
	}
	awgClient, err := dialConfiguredAWGBackup()
	if err != nil {
		return err
	}
	if awgClient != nil {
		defer awgClient.Close()
		manager.AWG = awgClient
	}
	item, err := manager.CreateContext(ctx, "manual")
	if err != nil {
		return err
	}
	fmt.Println(item.Name)
	return nil
}

func runRestoreCLI(ctx context.Context, dataDir, configDir string, args []string) error {
	awgClient, err := dialConfiguredAWGBackup()
	if err != nil {
		return err
	}
	if awgClient != nil {
		defer awgClient.Close()
	}
	return runRestoreCLIWithApplierAndAWG(ctx, dataDir, configDir, args, applyRestoredState, awgClient)
}

func runRestoreCLIWithApplier(ctx context.Context, dataDir, configDir string, args []string, applyState func(context.Context, *store.Store, []byte, string, int) error) error {
	return runRestoreCLIWithApplierAndAWG(ctx, dataDir, configDir, args, applyState, nil)
}

func runRestoreCLIWithApplierAndAWG(ctx context.Context, dataDir, configDir string, args []string, applyState func(context.Context, *store.Store, []byte, string, int) error, awgBackup backup.AWGBackup) error {
	if len(args) != 2 || args[1] != "RESTORE" {
		return errors.New("usage: xray-easy restore <backup-name> RESTORE")
	}
	masterKey, err := loadMasterKey()
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, filepath.Join(dataDir, "state.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	lock, err := maintenance.Acquire(ctx, filepath.Join(dataDir, "maintenance.lock"))
	if err != nil {
		return fmt.Errorf("acquire maintenance lock: %w", err)
	}
	defer lock.Close()
	manager := backup.NewManager(db, dataDir, configDir, masterKey)
	manager.AWG = awgBackup
	target, err := manager.Verify(args[0])
	if err != nil {
		return err
	}
	if err := verifyBackupMasterKey(target, masterKey); err != nil {
		return err
	}
	preRestore, err := manager.CreatePreservingContext(ctx, "pre-restore", target.Name)
	if err != nil {
		return fmt.Errorf("create pre-restore backup: %w", err)
	}
	if err := manager.RestoreStateContext(ctx, target); err != nil {
		return fmt.Errorf("restore state: %w", err)
	}
	publicPort, err := configuredPublicPort()
	if err != nil {
		return err
	}
	if err := applyState(ctx, db, masterKey, configDir, publicPort); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var rollbackErrors []string
		if rollbackErr := manager.RestoreStateContext(rollbackCtx, preRestore); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, "restore pre-restore snapshot: "+rollbackErr.Error())
		} else if applyErr := applyState(rollbackCtx, db, masterKey, configDir, publicPort); applyErr != nil {
			rollbackErrors = append(rollbackErrors, "apply pre-restore snapshot: "+applyErr.Error())
		}
		if len(rollbackErrors) > 0 {
			return fmt.Errorf("apply restored state: %w; rollback from %s failed: %s", err, preRestore.Name, strings.Join(rollbackErrors, "; "))
		}
		return fmt.Errorf("apply restored state: %w (state rolled back from %s)", err, preRestore.Name)
	}
	admin, _ := db.FirstAdmin(ctx)
	_ = db.AddAudit(ctx, admin.ID, "backup.restore", "backup", target.Name, "backup restored and applied")
	fmt.Printf("restored %s\n", target.Name)
	return nil
}

func dialConfiguredAWGBackup() (*awgcontrol.Client, error) {
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) == "" {
		return nil, nil
	}
	client, err := awgcontrol.Dial(
		envOr("AWG_CONTROL_ADDR", "172.31.241.4:10087"),
		envOr("AWG_CONTROL_TOKEN_FILE", "/run/awg-auth/control.token"),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize AmneziaWG backup client: %w", err)
	}
	return client, nil
}

func verifyBackupMasterKey(info backup.Info, masterKey []byte) error {
	settings, err := store.ReadSettingsFromDatabase(info.StatePath)
	if err != nil {
		return err
	}
	if settings.RealityPrivateKeyEnc != "" {
		if _, err := secret.Open(masterKey, settings.RealityPrivateKeyEnc, "reality_private_key"); err != nil {
			return errors.New("backup was created with a different XRAY_EASY_MASTER_KEY")
		}
	}
	return nil
}

func applyRestoredState(ctx context.Context, db *store.Store, masterKey []byte, configDir string, publicPort int) error {
	sup := supervisor.Client{BaseURL: envOr("XRAY_SUPERVISOR_URL", "http://127.0.0.1:10086"), TokenFile: envOr("XRAY_SUPERVISOR_TOKEN_FILE", "/run/secrets/xray_supervisor_token")}
	return applyRestoredStateWithSupervisor(ctx, db, masterKey, configDir, publicPort, sup)
}

func applyRestoredStateWithSupervisor(ctx context.Context, db *store.Store, masterKey []byte, configDir string, publicPort int, sup supervisorAPI) error {
	settings, err := db.GetSettings(ctx)
	if err != nil {
		return err
	}
	settings.PublicPort = publicPort
	privateKey, err := secret.Open(masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		return fmt.Errorf("decrypt restored REALITY key: %w", err)
	}
	clients, err := db.ListClients(ctx)
	if err != nil {
		return err
	}
	xrayClients := xray.ClientsFromDomain(clients)
	if err := db.SeedReservedShortIDs(ctx, xray.ReservedShortIDCount, xray.NewShortID); err != nil {
		return err
	}
	reservedShortIDs, err := db.ListReservedShortIDs(ctx)
	if err != nil {
		return err
	}
	hysteriaSettings, err := loadHysteriaSettings(ctx, db)
	if err != nil {
		return err
	}
	renderSettings := rendererSettingsWithHysteria(settings, privateKey, hysteriaSettings)
	renderSettings.ReservedShortIDs = reservedShortIDs
	rendered, err := xray.RenderServerConfig(renderSettings, xrayClients)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(configDir, "candidates"), 0o700); err != nil {
		return err
	}
	operationID, err := randomID()
	if err != nil {
		return err
	}
	candidate := filepath.Join(configDir, "candidates", operationID+".json")
	defer os.Remove(candidate)
	if err := writeAtomic(candidate, rendered); err != nil {
		return err
	}
	if err := sup.Validate(ctx, candidate, operationID); err != nil {
		return err
	}
	if err := sup.Apply(ctx, candidate, operationID); err != nil {
		return err
	}
	if err := os.Rename(candidate, filepath.Join(configDir, "active.json")); err != nil {
		return err
	}
	return nil
}

func cliUsageError() error {
	return errors.New("usage: xray-easy doctor [bundle] | admin <logout-all|reset-password|reset-totp|recovery-codes> | backup <create|list> | restore <backup-name> RESTORE")
}

func configuredPublicPort() (int, error) {
	value := envOr("XRAY_PUBLIC_PORT", "443")
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("XRAY_PUBLIC_PORT must be an integer between 1 and 65535")
	}
	return port, nil
}

func configuredVMessPort() (int, error) {
	value := envOr("XRAY_VMESS_PORT", "9443")
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("XRAY_VMESS_PORT must be an integer between 1 and 65535")
	}
	publicPort, err := configuredPublicPort()
	if err != nil {
		return 0, err
	}
	if port == publicPort {
		return 0, errors.New("XRAY_VMESS_PORT must differ from XRAY_PUBLIC_PORT")
	}
	uiPort, err := strconv.Atoi(envOr("XRAY_EASY_UI_PORT", "8080"))
	if err != nil || uiPort < 1 || uiPort > 65535 {
		return 0, errors.New("XRAY_EASY_UI_PORT must be an integer between 1 and 65535")
	}
	if port == uiPort {
		return 0, errors.New("XRAY_VMESS_PORT must differ from XRAY_EASY_UI_PORT")
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
	response := map[string]any{"initialized": status.Initialized, "public_port": s.publicPort}
	if !status.Initialized {
		if hysteriaSettings, err := loadHysteriaSettings(r.Context(), s.store); err == nil && hysteriaSettings.Enabled && hysteriaSettings.TLSMode == domain.HysteriaTLSSelfSigned && hysteriaSettings.TLSCertIP != "" {
			response["suggested_public_host"] = hysteriaSettings.TLSCertIP
		}
	}
	writeJSON(w, http.StatusOK, response)
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
	req.PublicHost = strings.TrimSpace(req.PublicHost)
	if strings.TrimSpace(req.PublicHost) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "public_host is required"})
		return
	}
	publicHost, err := domain.NormalizePublicHost(req.PublicHost)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.PublicHost = publicHost
	if err := s.validateHysteriaHost(r.Context(), req.PublicHost); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.RealityTarget = strings.TrimSpace(req.RealityTarget)
	req.RealitySNI = strings.TrimSpace(req.RealitySNI)
	if err := domain.ValidateRealityTarget(req.RealityTarget, req.RealitySNI); err != nil {
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
	admin, err := s.store.Initialize(r.Context(), req.Username, hash, req.PublicHost, req.PublicPort)
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

func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var req passwordChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	if !auth.VerifyPassword(req.CurrentPassword, admin.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"code": "invalid_credentials", "error": "current password is incorrect"})
		return
	}
	passwordHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	if err := s.store.ChangeAdminPassword(r.Context(), admin.ID, passwordHash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not change administrator password"})
		return
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, "auth.password_change", "admin", admin.ID, "administrator password changed; all sessions revoked")
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

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	status, err := s.supervisor.Status(r.Context())
	response := map[string]any{
		"state":                   status.State,
		"xray_version":            status.XrayVersion,
		"configured_xray_version": envOr("XRAY_VERSION", "unknown"),
		"xray_version_verified":   xrayVersionVerified(status.XrayVersion, envOr("XRAY_VERSION", "unknown")),
		"pid":                     status.PID,
		"restart_count":           status.RestartCount,
		"started_at":              status.StartedAt,
		"last_error":              diagnostics.Redact(status.LastError),
		"last_exit":               diagnostics.Redact(status.LastExit),
		"stats_last_error":        "",
	}
	if s.stats != nil {
		response["stats_last_error"] = diagnostics.Redact(s.stats.LastError())
	}
	if err != nil {
		response["state"] = "unavailable"
		response["supervisor_error"] = diagnostics.Redact(err.Error())
	}
	writeJSON(w, http.StatusOK, response)
}

func xrayVersionVerified(runtimeVersion, configuredVersion string) bool {
	return safeRuntimeXrayVersion(runtimeVersion) == xray.VerifiedCoreVersion && safeRuntimeXrayVersion(configuredVersion) == xray.VerifiedCoreVersion
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	component := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("component")))
	if component == "" {
		component = "xray"
	}
	if component != "xray" && component != "app" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "component must be xray or app"})
		return
	}
	limit := 100
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "limit must be between 1 and 200"})
			return
		}
		limit = parsed
	}
	entries := make([]diagnostics.Entry, 0, limit)
	if component == "app" {
		entries = append(entries, s.diagnosticBuffer.Snapshot(limit)...)
	} else {
		lines, err := s.supervisor.Logs(r.Context())
		if err != nil {
			s.recordDiagnostic("warn", "could not read supervisor logs: "+err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": "diagnostics_unavailable", "error": "could not read Xray diagnostics"})
			return
		}
		for _, line := range lines {
			level := diagnosticLevel(line)
			if level == "info" {
				continue
			}
			entries = append(entries, diagnostics.Entry{At: time.Now().UTC(), Component: "xray", Level: level, Message: diagnostics.Redact(line)})
		}
		if len(entries) > limit {
			entries = entries[len(entries)-limit:]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"component": component, "entries": entries, "next_cursor": ""})
}

func diagnosticLevel(line string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "error") || strings.Contains(lower, "fail") || strings.Contains(lower, "fatal") || strings.Contains(lower, "panic") || strings.Contains(lower, "exited") {
		return "error"
	}
	if strings.Contains(lower, "warn") || strings.Contains(lower, "degraded") {
		return "warn"
	}
	return "info"
}

func (s *server) recordDiagnostic(level, message string) {
	if s.diagnosticBuffer != nil {
		s.diagnosticBuffer.Add("app", level, message)
	}
	s.notifyEvents()
}

func (s *server) subscribeEvents() (<-chan struct{}, func()) {
	channel := make(chan struct{}, 1)
	s.eventsMu.Lock()
	s.eventSubs[channel] = struct{}{}
	s.eventsMu.Unlock()
	return channel, func() {
		s.eventsMu.Lock()
		if _, ok := s.eventSubs[channel]; ok {
			delete(s.eventSubs, channel)
			close(channel)
		}
		s.eventsMu.Unlock()
	}
}

func (s *server) notifyEvents() {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	for subscriber := range s.eventSubs {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
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
	otpauthURI := totp.OTPAuthURI(secretValue, "xray-easy", admin.Username)
	qrPNG, err := qrcode.Encode(otpauthURI, qrcode.Medium, 512)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encode TOTP QR"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_token":    token,
		"secret":         secretValue,
		"otpauth_uri":    otpauthURI,
		"qr_png":         base64.StdEncoding.EncodeToString(qrPNG),
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming is unavailable"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	var statsNotifications <-chan struct{}
	unsubscribeStats := func() {}
	if s.stats != nil {
		statsNotifications, unsubscribeStats = s.stats.Subscribe()
	}
	defer unsubscribeStats()
	eventNotifications, unsubscribeEvents := s.subscribeEvents()
	defer unsubscribeEvents()

	sendStats := func() error {
		if _, err := s.authenticated(r); err != nil {
			return err
		}
		clients := map[string]stats.ClientStats{}
		if s.stats != nil {
			clients = s.stats.Snapshot()
		}
		payload, err := json.Marshal(map[string]any{"type": "stats", "at": time.Now().UTC(), "clients": clients})
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: stats\ndata: %s\n\n", payload); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
	sendStatus := func() error {
		if _, err := s.authenticated(r); err != nil {
			return err
		}
		status, err := s.supervisor.Status(r.Context())
		configuredVersion := envOr("XRAY_VERSION", "unknown")
		payload := map[string]any{"type": "status", "at": time.Now().UTC(), "state": status.State, "xray_version": status.XrayVersion, "configured_xray_version": configuredVersion, "xray_version_verified": xrayVersionVerified(status.XrayVersion, configuredVersion), "restart_count": status.RestartCount, "last_error": diagnostics.Redact(status.LastError), "stats_last_error": ""}
		if s.stats != nil {
			payload["stats_last_error"] = diagnostics.Redact(s.stats.LastError())
		}
		if err != nil {
			payload["state"] = "unavailable"
			payload["supervisor_error"] = diagnostics.Redact(err.Error())
		}
		data, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := fmt.Fprintf(w, "event: status\ndata: %s\n\n", data); writeErr != nil {
			return writeErr
		}
		flusher.Flush()
		return nil
	}
	if err := sendStats(); err != nil {
		return
	}
	if err := sendStatus(); err != nil {
		return
	}
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-statsNotifications:
			if err := sendStats(); err != nil {
				return
			}
		case <-eventNotifications:
			if err := sendStatus(); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := sendStatus(); err != nil {
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
		writeJSON(w, http.StatusOK, publicSettings(settings, s.vmessPort))
		return
	}
	if r.Method == http.MethodPatch {
		s.prepareSettingsChange(w, r)
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, nil)
}

func (s *server) settingsValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	s.prepareSettingsChange(w, r)
}

func (s *server) prepareSettingsChange(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var req settingsPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	current, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_incomplete", "error": err.Error()})
		return
	}
	current.PublicPort = s.publicPort
	candidate := current
	if req.PublicHost != nil {
		candidate.PublicHost = strings.TrimSpace(*req.PublicHost)
	}
	if req.RealityTarget != nil {
		candidate.RealityTarget = strings.TrimSpace(*req.RealityTarget)
	}
	if req.RealitySNI != nil {
		candidate.RealitySNI = strings.TrimSpace(*req.RealitySNI)
	}
	if req.ClientFingerprint != nil {
		candidate.ClientFingerprint = strings.TrimSpace(*req.ClientFingerprint)
	}
	if req.LogLevel != nil {
		candidate.LogLevel = strings.TrimSpace(*req.LogLevel)
	}
	publicHost, err := domain.NormalizePublicHost(candidate.PublicHost)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	candidate.PublicHost = publicHost
	if err := s.validateHysteriaHost(r.Context(), candidate.PublicHost); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	if candidate.ClientFingerprint == "" || !domain.SupportsFingerprint(candidate.ClientFingerprint) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "unsupported client fingerprint"})
		return
	}
	if !domain.SupportsXrayLogLevel(candidate.LogLevel) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "unsupported Xray log level"})
		return
	}
	if err := domain.ValidateRealityTarget(candidate.RealityTarget, candidate.RealitySNI); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	hostChanged := candidate.PublicHost != current.PublicHost
	targetChanged := candidate.RealityTarget != current.RealityTarget
	sniChanged := candidate.RealitySNI != current.RealitySNI
	privateKeyChanged := req.RotatePrivateKey
	logLevelChanged := candidate.LogLevel != current.LogLevel
	dangerous := hostChanged || targetChanged || sniChanged || privateKeyChanged
	if !dangerous && candidate.ClientFingerprint == current.ClientFingerprint && !logLevelChanged {
		writeJSON(w, http.StatusOK, map[string]any{"changed": false, "settings": publicSettings(current, s.vmessPort)})
		return
	}

	if dangerous && (targetChanged || sniChanged) {
		if err := s.supervisor.ProbeTarget(r.Context(), candidate.RealityTarget, candidate.RealitySNI); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": "validation_error", "error": "REALITY target probe failed", "detail": err.Error()})
			return
		}
	}
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list clients"})
		return
	}
	changeID, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create settings change"})
		return
	}
	if privateKeyChanged {
		newPrivateKey, publicKey, keyErr := xray.NewRealityKeyPair()
		if keyErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not generate REALITY key pair"})
			return
		}
		candidate.RealityPublicKey = publicKey
		candidate.RealityPrivateKeyEnc, err = secret.Seal(s.masterKey, newPrivateKey, "reality_private_key")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encrypt REALITY private key"})
			return
		}
	}
	diff := make([]settingsDiff, 0, 6)
	if hostChanged {
		diff = append(diff, settingsDiff{Field: "public_host", From: current.PublicHost, To: candidate.PublicHost})
	}
	if targetChanged {
		diff = append(diff, settingsDiff{Field: "reality_target", From: current.RealityTarget, To: candidate.RealityTarget})
	}
	if sniChanged {
		diff = append(diff, settingsDiff{Field: "reality_sni", From: current.RealitySNI, To: candidate.RealitySNI})
	}
	if privateKeyChanged {
		diff = append(diff, settingsDiff{Field: "reality_private_key", From: "current key", To: "new key generated"})
		diff = append(diff, settingsDiff{Field: "reality_public_key", From: current.RealityPublicKey, To: candidate.RealityPublicKey})
	}
	if candidate.ClientFingerprint != current.ClientFingerprint {
		diff = append(diff, settingsDiff{Field: "client_fingerprint", From: current.ClientFingerprint, To: candidate.ClientFingerprint})
	}
	if logLevelChanged {
		diff = append(diff, settingsDiff{Field: "log_level", From: current.LogLevel, To: candidate.LogLevel})
	}
	expectedConfirmation := ""
	consequences := []string{}
	if dangerous {
		expectedConfirmation = "REVOKE"
		if privateKeyChanged && !hostChanged && !targetChanged && !sniChanged {
			expectedConfirmation = "ROTATE"
		}
		consequences = append(consequences,
			"all existing VLESS accesses will be revoked and cannot be re-enabled",
			"Hysteria 2 access remains active; create a new VLESS profile after the change",
			"Xray will be validated and reloaded after an automatic backup",
		)
		for _, client := range clients {
			if client.Protocol == domain.ProtocolLegacyDual && client.HasHysteria2() {
				consequences = append(consequences, "legacy dual-protocol profiles keep Hysteria 2 access while their VLESS access is revoked")
				break
			}
		}
	} else {
		if candidate.ClientFingerprint != current.ClientFingerprint {
			consequences = append(consequences, "existing profiles remain valid; new profiles use the updated default fingerprint")
		}
		if logLevelChanged {
			consequences = append(consequences, "Xray will restart and active connections will be briefly interrupted; existing profiles remain valid")
		}
	}
	revokedClients := 0
	if dangerous {
		for _, client := range clients {
			if client.HasVLESS() && !client.VLESSRevoked {
				revokedClients++
			}
		}
	}
	pending := pendingSettingsChange{ID: changeID, AdminID: admin.ID, BaseFingerprint: settingsFingerprint(current), ClientsFingerprint: clientsFingerprint(clients), Settings: candidate, ExpectedConfirmation: expectedConfirmation, RequiresXrayApply: logLevelChanged, Diff: diff, Consequences: consequences, RevokedClients: revokedClients, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	s.settingsMu.Lock()
	for id, item := range s.pendingSettings {
		if item.AdminID == admin.ID {
			delete(s.pendingSettings, id)
		}
	}
	s.pendingSettings[changeID] = pending
	s.settingsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"changed":               true,
		"change_id":             changeID,
		"expires_in":            600,
		"expected_confirmation": expectedConfirmation,
		"requires_confirmation": expectedConfirmation != "",
		"diff":                  diff,
		"consequences":          consequences,
		"revoked_clients":       revokedClients,
		"settings":              publicSettings(candidate, s.vmessPort),
	})
}

func (s *server) settingsApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var req settingsApplyRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.ChangeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "change_id is required"})
		return
	}
	s.settingsMu.Lock()
	pending, ok := s.pendingSettings[req.ChangeID]
	if !ok || pending.AdminID != admin.ID || time.Now().UTC().After(pending.ExpiresAt) || pending.Applying {
		s.settingsMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"code": "confirmation_expired", "error": "settings change is expired or already applying"})
		return
	}
	if pending.ExpectedConfirmation != "" && strings.TrimSpace(req.Confirmation) != pending.ExpectedConfirmation {
		s.settingsMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "confirmation_required", "error": "type the requested confirmation word", "expected_confirmation": pending.ExpectedConfirmation})
		return
	}
	pending.Applying = true
	s.pendingSettings[req.ChangeID] = pending
	s.settingsMu.Unlock()

	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	lock, err := maintenance.Acquire(r.Context(), s.maintenancePath)
	if err != nil {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "apply_pending", "error": "maintenance lock is unavailable"})
		return
	}
	defer lock.Close()
	current, err := s.store.GetSettings(r.Context())
	if err != nil {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_incomplete", "error": err.Error()})
		return
	}
	current.PublicPort = s.publicPort
	if settingsFingerprint(current) != pending.BaseFingerprint {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusConflict, map[string]any{"code": "conflict", "error": "settings changed; prepare the rotation again"})
		return
	}
	if pending.ExpectedConfirmation == "" && !pending.RequiresXrayApply {
		if err := s.store.UpdateSettings(r.Context(), pending.Settings); err != nil {
			s.finishSettingsChange(req.ChangeID, false)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "persist settings: " + err.Error()})
			return
		}
		_ = s.store.AddAudit(r.Context(), admin.ID, "settings.update", "settings", "node", fmt.Sprintf("client fingerprint default changed from %s to %s", current.ClientFingerprint, pending.Settings.ClientFingerprint))
		s.finishSettingsChange(req.ChangeID, true)
		writeJSON(w, http.StatusOK, map[string]any{"applied": true, "settings": publicSettings(pending.Settings, s.vmessPort), "revoked_clients": 0})
		return
	}
	if pending.ExpectedConfirmation != "" {
		if err := s.supervisor.ProbeTarget(r.Context(), pending.Settings.RealityTarget, pending.Settings.RealitySNI); err != nil {
			s.recordDiagnostic("warn", "settings target re-probe failed: "+err.Error())
			s.finishSettingsChange(req.ChangeID, false)
			writeJSON(w, http.StatusBadGateway, map[string]any{"code": "validation_error", "error": "REALITY target probe failed", "detail": err.Error()})
			return
		}
	}
	oldClients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list clients"})
		return
	}
	if clientsFingerprint(oldClients) != pending.ClientsFingerprint {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusConflict, map[string]any{"code": "conflict", "error": "device list or states changed; review the rotation again"})
		return
	}
	backupName := ""
	if pending.ExpectedConfirmation != "" {
		manager := s.backupManager()
		backupInfo, backupErr := manager.CreateContext(r.Context(), "settings-rotation")
		if backupErr != nil {
			s.recordDiagnostic("error", "automatic settings backup failed: "+backupErr.Error())
			s.finishSettingsChange(req.ChangeID, false)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "backup_failed", "error": "could not create automatic backup", "detail": backupErr.Error()})
			return
		}
		backupName = backupInfo.Name
	}
	privateKey, err := secret.Open(s.masterKey, pending.Settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt candidate REALITY private key"})
		return
	}
	newClients := append([]domain.Client(nil), oldClients...)
	states := make(map[string]map[domain.ClientProtocol]domain.ClientState, len(oldClients))
	if pending.ExpectedConfirmation != "" {
		for i := range newClients {
			if !newClients[i].HasVLESS() || newClients[i].VLESSRevoked {
				continue
			}
			newClients[i].VLESSEnabled, newClients[i].VLESSRevoked = false, true
			newClients[i].Enabled = newClients[i].HasHysteria2() && newClients[i].HysteriaEnabled && !newClients[i].HysteriaRevoked
			newClients[i].Revoked = (!newClients[i].HasHysteria2() || newClients[i].HysteriaRevoked)
			states[newClients[i].ID] = map[domain.ClientProtocol]domain.ClientState{
				domain.ProtocolVLESS: {Enabled: false, Revoked: true},
			}
		}
	}
	path, operationID, err := s.prepareCandidateLocked(r.Context(), pending.Settings, privateKey, newClients)
	if err != nil {
		s.recordDiagnostic("error", "settings candidate validation failed: "+err.Error())
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusBadGateway, map[string]any{"code": "apply_failed", "error": err.Error()})
		return
	}
	if err := s.store.UpdateApplyOperation(r.Context(), operationID, "applying", ""); err != nil {
		_ = os.Remove(path)
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": err.Error()})
		return
	}
	if err := s.supervisor.Apply(r.Context(), path, operationID); err != nil {
		s.recordDiagnostic("error", "settings candidate apply failed: "+err.Error())
		_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
		_ = os.Remove(path)
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusBadGateway, map[string]any{"code": "apply_failed", "error": err.Error()})
		return
	}
	if err := s.store.UpdateSettingsAndClientProtocolStates(r.Context(), pending.Settings, states); err != nil {
		_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
		_ = s.supervisor.Apply(r.Context(), filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
		_ = os.Remove(path)
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "persist settings rotation: " + err.Error()})
		return
	}
	if err := os.Rename(path, filepath.Join(s.configDir, "active.json")); err != nil {
		_ = s.store.UpdateSettingsAndClientProtocolStates(r.Context(), current, clientProtocolStates(oldClients))
		_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
		_ = s.supervisor.Apply(r.Context(), filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
		s.finishSettingsChange(req.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "promote Xray config: " + err.Error()})
		return
	}
	_ = s.store.UpdateApplyOperation(r.Context(), operationID, "committed", "")
	auditAction := "settings.update"
	auditDetail := fmt.Sprintf("Xray log level changed from %s to %s", current.LogLevel, pending.Settings.LogLevel)
	if pending.ExpectedConfirmation != "" {
		auditAction = "settings.rotation"
		auditDetail = fmt.Sprintf("settings rotated; %d VLESS accesses revoked; Hysteria 2 accesses preserved; backup=%s", len(states), backupName)
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, auditAction, "settings", "node", auditDetail)
	s.finishSettingsChange(req.ChangeID, true)
	response := map[string]any{"applied": true, "settings": publicSettings(pending.Settings, s.vmessPort), "revoked_clients": len(states)}
	if backupName != "" {
		response["backup"] = backupName
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) finishSettingsChange(id string, success bool) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	if success {
		delete(s.pendingSettings, id)
		return
	}
	if pending, ok := s.pendingSettings[id]; ok {
		pending.Applying = false
		s.pendingSettings[id] = pending
	}
}

func clientProtocolStates(clients []domain.Client) map[string]map[domain.ClientProtocol]domain.ClientState {
	states := make(map[string]map[domain.ClientProtocol]domain.ClientState, len(clients))
	for _, client := range clients {
		transitions := make(map[domain.ClientProtocol]domain.ClientState, 2)
		if state, err := client.AccessState(domain.ProtocolVLESS); err == nil {
			transitions[domain.ProtocolVLESS] = state
		}
		if state, err := client.AccessState(domain.ProtocolHysteria2); err == nil {
			transitions[domain.ProtocolHysteria2] = state
		}
		if len(transitions) > 0 {
			states[client.ID] = transitions
		}
	}
	return states
}

func settingsFingerprint(settings domain.Settings) string {
	value := strings.Join([]string{settings.PublicHost, strconv.Itoa(settings.PublicPort), settings.XrayAPIListen, strconv.Itoa(settings.InternalInboundPort), settings.RealityTarget, settings.RealitySNI, settings.RealityPrivateKeyEnc, settings.RealityPublicKey, settings.ClientFingerprint, settings.LogLevel}, "\x00")
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func clientsFingerprint(clients []domain.Client) string {
	ordered := append([]domain.Client(nil), clients...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	var value strings.Builder
	for _, client := range ordered {
		fmt.Fprintf(&value, "%s\x00%s\x00%s\x00%s\x00%t\x00%t\x00%t\x00%t\x00%t\x00%t\n",
			client.ID, client.Protocol, client.UUID, client.HysteriaAuth, client.Enabled, client.Revoked,
			client.VLESSEnabled, client.VLESSRevoked, client.HysteriaEnabled, client.HysteriaRevoked)
		fmt.Fprintf(&value, "%t\x00%t\n", client.VMessEnabled, client.VMessRevoked)
	}
	hash := sha256.Sum256([]byte(value.String()))
	return hex.EncodeToString(hash[:])
}

func (s *server) backups(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	manager := s.backupManager()
	switch r.Method {
	case http.MethodGet:
		items, err := manager.List()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list backups"})
			return
		}
		response := make([]map[string]any, 0, len(items))
		for _, item := range items {
			response = append(response, map[string]any{"name": item.Name, "created_at": item.CreatedAt})
		}
		writeJSON(w, http.StatusOK, response)
	case http.MethodPost:
		lock, err := maintenance.Acquire(r.Context(), s.maintenancePath)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "maintenance lock is unavailable"})
			return
		}
		defer lock.Close()
		item, err := manager.CreateContext(r.Context(), "manual")
		if err != nil {
			s.recordDiagnostic("error", "manual backup failed: "+err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create backup", "detail": err.Error()})
			return
		}
		_ = s.store.AddAudit(r.Context(), admin.ID, "backup.create", "backup", item.Name, "manual backup created")
		writeJSON(w, http.StatusCreated, map[string]any{"name": item.Name, "created_at": item.CreatedAt})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, nil)
	}
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
		response := s.withStats(clients)
		if s.awg != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			peers, peerErr := s.awg.ListPeers(ctx)
			cancel()
			if peerErr == nil {
				response = append(response, s.withAWGStats(peers)...)
			}
		}
		sort.SliceStable(response, func(left, right int) bool {
			if response[left].Name == response[right].Name {
				return response[left].CreatedAt.Before(response[right].CreatedAt)
			}
			return strings.ToLower(response[left].Name) < strings.ToLower(response[right].Name)
		})
		writeJSON(w, http.StatusOK, response)
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
	fingerprint := strings.TrimSpace(req.Fingerprint)
	authValue := strings.TrimSpace(req.Auth)
	protocol := domain.ClientProtocol(strings.ToLower(strings.TrimSpace(req.Protocol)))
	if protocol == "" {
		protocol = domain.ProtocolVLESS
	}
	if protocol != domain.ProtocolVLESS && protocol != domain.ProtocolHysteria2 && protocol != domain.ProtocolVMess && protocol != domain.ProtocolAmneziaWG {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "protocol must be vless, vmess, hysteria2, or amneziawg"})
		return
	}
	if protocol == domain.ProtocolAmneziaWG {
		s.createAWGClient(w, r, admin, name, fingerprint, authValue)
		return
	}
	if protocol == domain.ProtocolVLESS && authValue != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "auth is only valid for Hysteria 2 profiles"})
		return
	}
	if protocol != domain.ProtocolVLESS && fingerprint != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "fingerprint is only valid for VLESS profiles"})
		return
	}
	settings, err := s.store.GetSettings(r.Context())
	if err != nil || settings.RealityPrivateKeyEnc == "" || settings.RealityPublicKey == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "setup_incomplete", "error": "Xray node setup is incomplete"})
		return
	}
	settings.PublicPort = s.publicPort
	if protocol == domain.ProtocolVLESS && fingerprint != "" && !domain.SupportsFingerprint(fingerprint) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported client fingerprint"})
		return
	}
	if protocol == domain.ProtocolVLESS {
		if settings.RealityPrivateKeyEnc == "" {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "setup_incomplete", "error": "REALITY setup is incomplete"})
			return
		}
	} else if protocol == domain.ProtocolHysteria2 {
		hysteriaSettings, settingsErr := loadHysteriaSettings(r.Context(), s.store)
		if settingsErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read Hysteria 2 settings"})
			return
		}
		if !hysteriaSettings.Enabled {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "transport_disabled", "error": "Hysteria 2 is disabled; enable it in Settings first"})
			return
		}
		status, statusErr := s.hysteriaSettingsStatus(r.Context())
		if statusErr != nil || status.CertificateError != "" {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "certificate_not_ready", "error": "Hysteria 2 TLS certificate is not ready"})
			return
		}
		if err := s.validateHysteriaHost(r.Context(), status.Host); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "certificate_not_ready", "error": err.Error()})
			return
		}
	} else {
		status, statusErr := s.hysteriaSettingsStatus(r.Context())
		if statusErr != nil || status.CertificateError != "" || status.Certificate == nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "certificate_not_ready", "error": "a valid TLS certificate matching the VMess server name must be configured in Hysteria 2 Settings"})
			return
		}
	}
	if _, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
		return
	}
	client, err := s.createProtocolClient(r.Context(), settings, protocol, name, fingerprint, authValue, admin.ID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, s.withStats([]domain.Client{client})[0])
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
	if strings.HasPrefix(id, "awg:") {
		s.amneziaWGClientRoute(w, r, admin, parts, strings.TrimPrefix(id, "awg:"))
		return
	}
	client, err := s.store.GetClient(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.withStats([]domain.Client{client})[0])
		return
	}
	if len(parts) == 2 && parts[1] == "profile" && r.Method == http.MethodGet {
		s.profile(w, r, client)
		return
	}
	if len(parts) == 2 && parts[1] == "enable" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, domain.ActionEnable, admin.ID)
		return
	}
	if len(parts) == 2 && parts[1] == "disable" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, domain.ActionDisable, admin.ID)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		s.changeClientState(w, r, client, domain.ActionRevoke, admin.ID)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
}

func (s *server) createClient(ctx context.Context, settings domain.Settings, privateKey, name, fingerprint, actorID string) (domain.Client, error) {
	return s.createProtocolClient(ctx, settings, domain.ProtocolVLESS, name, fingerprint, "", actorID)
}

func (s *server) createProtocolClient(ctx context.Context, settings domain.Settings, protocol domain.ClientProtocol, name, fingerprint, authValue, actorID string) (domain.Client, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	maintenanceLock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		return domain.Client{}, err
	}
	defer maintenanceLock.Close()
	clients, err := s.store.ListClients(ctx)
	if err != nil {
		return domain.Client{}, fmt.Errorf("list clients: %w", err)
	}
	clientID, err := randomID()
	if err != nil {
		return domain.Client{}, err
	}
	if protocol == domain.ProtocolVLESS && fingerprint == "" {
		fingerprint = settings.ClientFingerprint
	}
	if protocol == domain.ProtocolHysteria2 && authValue == "" {
		authValue, err = newHysteriaAuth()
		if err != nil {
			return domain.Client{}, fmt.Errorf("generate Hysteria 2 auth: %w", err)
		}
	}
	client, err := domain.NewProtocolClient(clientID, name, protocol, fingerprint, authValue)
	if err != nil {
		return domain.Client{}, err
	}
	client.Email = "device-" + clientID + "-" + string(protocol) + "@xray-easy"
	shortID, replaceInbound := "", false
	switch protocol {
	case domain.ProtocolVLESS:
		client.UUID, err = xray.NewUUID()
		if err != nil {
			return domain.Client{}, err
		}
		shortID, replaceInbound, err = s.store.CreateClientWithReservedShortID(ctx, client, client.UUID, client.Email, xray.ReservedShortIDCount, xray.NewShortID)
	case domain.ProtocolVMess:
		client.UUID, err = xray.NewUUID()
		if err == nil {
			err = s.store.CreateVMessClient(ctx, client)
		}
	case domain.ProtocolHysteria2:
		err = s.store.CreateHysteriaClient(ctx, client)
	default:
		return domain.Client{}, errors.New("new profiles must use VLESS, VMess, or Hysteria 2")
	}
	if err != nil {
		return domain.Client{}, fmt.Errorf("create client: %w", err)
	}
	client.ShortID = shortID
	clients = append(clients, client)
	reserved, err := s.store.ListReservedShortIDs(ctx)
	if err != nil {
		_ = s.store.DeleteClient(ctx, clientID)
		return domain.Client{}, fmt.Errorf("list reserved REALITY short IDs: %w", err)
	}
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		_ = s.store.DeleteClient(ctx, clientID)
		return domain.Client{}, errors.New("could not decrypt REALITY private key")
	}
	path, operationID, err := s.prepareCandidateWithReservedLocked(ctx, settings, privateKey, clients, reserved)
	if err != nil {
		_ = s.store.DeleteClient(ctx, clientID)
		return domain.Client{}, err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")
	activePath := filepath.Join(s.configDir, "active.json")
	usedReplace := protocol == domain.ProtocolVLESS && replaceInbound
	fullApply, vlessReplaced, vlessAdded, hysteriaAdded, vmessReplaced, vmessAdded := false, false, false, false, false, false
	rollbackRuntime := func() {
		if fullApply {
			_ = s.supervisor.Apply(ctx, activePath, operationID+"-rollback")
			return
		}
		if vlessReplaced {
			if replacer, ok := s.supervisor.(inboundReplacer); ok {
				_ = replacer.ReplaceInbound(ctx, activePath, path, "vless-reality", operationID+"-rollback")
			}
		}
		if hysteriaAdded {
			if hysteria, ok := s.handler.(hysteriaHandlerAPI); ok {
				_ = hysteria.RemoveHysteriaUser(ctx, client.Email)
			}
		}
		if vmessReplaced {
			if replacer, ok := s.supervisor.(inboundReplacer); ok {
				_ = replacer.ReplaceInbound(ctx, activePath, path, xray.VMessInboundTag, operationID+"-rollback")
			}
		}
		if vmessAdded {
			if vmess, ok := s.handler.(vmessHandlerAPI); ok {
				_ = vmess.RemoveVMessUser(ctx, client.Email)
			}
		}
		if vlessAdded {
			_ = s.handler.RemoveUser(ctx, client.Email)
		}
	}
	failCreate := func(cause error) (domain.Client, error) {
		rollbackRuntime()
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", cause.Error())
		_ = os.Remove(path)
		_ = s.store.DeleteClient(ctx, clientID)
		return domain.Client{}, cause
	}
	if !hasInboundTag(activePath, "vless-reality") || (s.hysteriaEnabled(ctx) && !hasInboundTag(activePath, xray.HysteriaInboundTag)) {
		usedReplace = false
		// First enablement of an optional inbound changes the process-level
		// topology, so use the normal validated supervisor apply once.
		if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
			return failCreate(err)
		}
		fullApply = true
	} else if usedReplace {
		replacer, ok := s.supervisor.(inboundReplacer)
		if ok {
			if err := replacer.ReplaceInbound(ctx, path, activePath, "vless-reality", operationID); err != nil {
				return failCreate(err)
			}
			vlessReplaced = true
		} else {
			if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
				return failCreate(err)
			}
			fullApply = true
		}
	} else if protocol == domain.ProtocolVLESS {
		if s.handler == nil {
			if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
				return failCreate(err)
			}
			fullApply = true
		} else if err := s.handler.AddUser(ctx, client.Email, client.UUID, xray.Flow); err != nil {
			// If Xray has no live inbound yet, a normal first start is needed.
			if applyErr := s.supervisor.Apply(ctx, path, operationID); applyErr != nil {
				return failCreate(err)
			}
			fullApply = true
		} else {
			vlessAdded = true
		}
	} else if protocol == domain.ProtocolHysteria2 {
		hysteria, ok := s.handler.(hysteriaHandlerAPI)
		if !ok {
			if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
				return failCreate(err)
			}
			fullApply = true
		} else if err := hysteria.AddHysteriaUser(ctx, client.Email, client.HysteriaAuth); err != nil {
			if applyErr := s.supervisor.Apply(ctx, path, operationID); applyErr != nil {
				return failCreate(err)
			}
			fullApply = true
		} else {
			hysteriaAdded = true
		}
	} else {
		if !hasInboundTag(activePath, xray.VMessInboundTag) {
			replacer, ok := s.supervisor.(inboundReplacer)
			if !ok {
				if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
					return failCreate(err)
				}
				fullApply = true
			} else if err := replacer.ReplaceInbound(ctx, path, activePath, xray.VMessInboundTag, operationID); err != nil {
				return failCreate(err)
			} else {
				vmessReplaced = true
			}
		} else if vmess, ok := s.handler.(vmessHandlerAPI); !ok {
			if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
				return failCreate(err)
			}
			fullApply = true
		} else if err := vmess.AddVMessUser(ctx, client.Email, client.UUID); err != nil {
			return failCreate(err)
		} else {
			vmessAdded = true
		}
	}
	if err := os.Rename(path, activePath); err != nil {
		return failCreate(fmt.Errorf("promote Xray config: %w", err))
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	if vlessReplaced {
		s.recordDiagnostic("warn", "REALITY short-ID reserve exhausted; the VLESS inbound was replaced and active VLESS connections may reconnect")
	}
	_ = s.store.AddAudit(ctx, actorID, "client.create", "client", clientID, "created a "+string(protocol)+" profile")
	return s.store.GetClient(ctx, clientID)
}

func newHysteriaAuth() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *server) changeClientState(w http.ResponseWriter, r *http.Request, client domain.Client, action domain.ClientAction, actorID string) {
	states, next, err := transitionClientAccesses(client, action)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	maintenanceLock, err := maintenance.Acquire(r.Context(), s.maintenancePath)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "Xray maintenance is in progress"})
		return
	}
	defer maintenanceLock.Close()
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
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list clients"})
		return
	}
	for i := range clients {
		if clients[i].ID == client.ID {
			clients[i] = next
		}
	}
	reserved, err := s.store.ListReservedShortIDs(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read REALITY short-ID reserve"})
		return
	}
	path, operationID, err := s.prepareCandidateWithReservedLocked(r.Context(), settings, privateKey, clients, reserved)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.UpdateApplyOperation(r.Context(), operationID, "applying", "")
	activePath := filepath.Join(s.configDir, "active.json")
	hysteriaChanged := stateChanged(client, next, domain.ProtocolHysteria2)
	vlessChanged := stateChanged(client, next, domain.ProtocolVLESS)
	vmessChanged := stateChanged(client, next, domain.ProtocolVMess)
	vlessRevoked := client.HasVLESS() && !client.VLESSRevoked && next.VLESSRevoked
	hysteriaEnabled := s.hysteriaEnabled(r.Context())
	vmessInboundChanged := hasInboundTag(activePath, xray.VMessInboundTag) != hasInboundTag(path, xray.VMessInboundTag)
	needsFullApply := !hasInboundTag(activePath, "vless-reality") || (hysteriaEnabled && !hasInboundTag(activePath, xray.HysteriaInboundTag))
	if hysteriaChanged && hysteriaEnabled {
		if _, ok := s.handler.(hysteriaHandlerAPI); !ok {
			needsFullApply = true
		}
	}
	if vlessChanged && !vlessRevoked && s.handler == nil {
		needsFullApply = true
	}
	if vmessChanged && !vmessInboundChanged {
		if _, ok := s.handler.(vmessHandlerAPI); !ok {
			needsFullApply = true
		}
	}
	replacer, canReplace := s.supervisor.(inboundReplacer)
	if (vlessRevoked || vmessInboundChanged) && !canReplace {
		needsFullApply = true
	}
	fullApplied, vlessReplaced := false, false
	vlessAdded, vlessRemoved, hysteriaAdded, hysteriaRemoved, vmessAdded, vmessRemoved, vmessReplaced := false, false, false, false, false, false, false
	rollbackRuntime := func() {
		if fullApplied {
			if rollbackErr := s.supervisor.Apply(r.Context(), activePath, operationID+"-rollback"); rollbackErr != nil {
				s.recordDiagnostic("error", "client state rollback failed: "+rollbackErr.Error())
			}
			return
		}
		if vlessReplaced {
			if rollbackErr := replacer.ReplaceInbound(r.Context(), activePath, path, "vless-reality", operationID+"-rollback"); rollbackErr != nil {
				s.recordDiagnostic("error", "VLESS inbound rollback failed: "+rollbackErr.Error())
			}
		}
		if vmessReplaced {
			if rollbackErr := replacer.ReplaceInbound(r.Context(), activePath, path, xray.VMessInboundTag, operationID+"-rollback"); rollbackErr != nil {
				s.recordDiagnostic("error", "VMess inbound rollback failed: "+rollbackErr.Error())
			}
		}
		if vlessAdded {
			_ = s.handler.RemoveUser(r.Context(), client.Email)
		}
		if vlessRemoved {
			_ = s.handler.AddUser(r.Context(), client.Email, client.UUID, xray.Flow)
		}
		if hysteriaAdded || hysteriaRemoved {
			if api, ok := s.handler.(hysteriaHandlerAPI); ok {
				if hysteriaAdded {
					_ = api.RemoveHysteriaUser(r.Context(), client.Email)
				} else {
					_ = api.AddHysteriaUser(r.Context(), client.Email, client.HysteriaCredential())
				}
			}
		}
		if vmessAdded || vmessRemoved {
			if api, ok := s.handler.(vmessHandlerAPI); ok {
				if vmessAdded {
					_ = api.RemoveVMessUser(r.Context(), client.Email)
				} else {
					_ = api.AddVMessUser(r.Context(), client.Email, client.UUID)
				}
			}
		}
	}
	failApply := func(cause error) {
		rollbackRuntime()
		_ = s.store.SetClientProtocolStates(r.Context(), client.ID, previousAccessStates(client))
		_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", cause.Error())
		_ = os.Remove(path)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": cause.Error()})
	}
	if needsFullApply {
		if err := s.supervisor.Apply(r.Context(), path, operationID); err != nil {
			_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
			_ = os.Remove(path)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		fullApplied = true
	} else {
		if hysteriaChanged && hysteriaEnabled {
			api := s.handler.(hysteriaHandlerAPI)
			if next.Hysteria2CanConnect() {
				if err := api.AddHysteriaUser(r.Context(), client.Email, client.HysteriaCredential()); err != nil {
					failApply(err)
					return
				}
				hysteriaAdded = true
			} else {
				if err := api.RemoveHysteriaUser(r.Context(), client.Email); err != nil {
					failApply(err)
					return
				}
				hysteriaRemoved = true
			}
		}
		if vlessRevoked {
			if err := replacer.ReplaceInbound(r.Context(), path, activePath, "vless-reality", operationID); err != nil {
				failApply(err)
				return
			}
			vlessReplaced = true
		} else if vlessChanged {
			if next.VLESSCanConnect() {
				if err := s.handler.AddUser(r.Context(), client.Email, client.UUID, xray.Flow); err != nil {
					failApply(err)
					return
				}
				vlessAdded = true
			} else {
				if err := s.handler.RemoveUser(r.Context(), client.Email); err != nil {
					failApply(err)
					return
				}
				vlessRemoved = true
			}
		}
		if vmessInboundChanged {
			if err := replacer.ReplaceInbound(r.Context(), path, activePath, xray.VMessInboundTag, operationID); err != nil {
				failApply(err)
				return
			}
			vmessReplaced = true
		} else if vmessChanged {
			api := s.handler.(vmessHandlerAPI)
			if next.VMessCanConnect() {
				if err := api.AddVMessUser(r.Context(), client.Email, client.UUID); err != nil {
					failApply(err)
					return
				}
				vmessAdded = true
			} else {
				if err := api.RemoveVMessUser(r.Context(), client.Email); err != nil {
					failApply(err)
					return
				}
				vmessRemoved = true
			}
		}
	}
	if err := s.store.SetClientProtocolStates(r.Context(), client.ID, states); err != nil {
		failApply(err)
		return
	}
	if err := os.Rename(path, activePath); err != nil {
		failApply(fmt.Errorf("promote client state config: %w", err))
		return
	}
	_ = s.store.UpdateApplyOperation(r.Context(), operationID, "committed", "")
	_ = s.store.AddAudit(r.Context(), actorID, "client.state", "client", client.ID, "protocol access state changed: "+strings.Join(protocolStateNames(states), ", "))
	updated, _ := s.store.GetClient(r.Context(), client.ID)
	writeJSON(w, http.StatusOK, s.withStats([]domain.Client{updated})[0])
}

func transitionClientAccesses(client domain.Client, action domain.ClientAction) (map[domain.ClientProtocol]domain.ClientState, domain.Client, error) {
	states := make(map[domain.ClientProtocol]domain.ClientState, 2)
	next := client
	for _, protocol := range []domain.ClientProtocol{domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolVMess} {
		state, err := client.AccessState(protocol)
		if err != nil {
			continue
		}
		if action == domain.ActionEnable && state.Revoked {
			return nil, domain.Client{}, domain.ErrClientRevoked
		}
		switch action {
		case domain.ActionEnable:
			state.Enabled = true
		case domain.ActionDisable:
			state.Enabled = false
		case domain.ActionRevoke:
			state.Enabled, state.Revoked = false, true
		default:
			return nil, domain.Client{}, errors.New("unsupported client action")
		}
		states[protocol] = state
		if protocol == domain.ProtocolVLESS {
			next.VLESSEnabled, next.VLESSRevoked = state.Enabled, state.Revoked
		} else if protocol == domain.ProtocolHysteria2 {
			next.HysteriaEnabled, next.HysteriaRevoked = state.Enabled, state.Revoked
		} else {
			next.VMessEnabled, next.VMessRevoked = state.Enabled, state.Revoked
		}
	}
	if len(states) == 0 {
		return nil, domain.Client{}, errors.New("profile has no supported protocol access")
	}
	next.Enabled = (next.HasVLESS() && next.VLESSEnabled && !next.VLESSRevoked) || (next.HasHysteria2() && next.HysteriaEnabled && !next.HysteriaRevoked) || (next.HasVMess() && next.VMessEnabled && !next.VMessRevoked)
	next.Revoked = (!next.HasVLESS() || next.VLESSRevoked) && (!next.HasHysteria2() || next.HysteriaRevoked) && (!next.HasVMess() || next.VMessRevoked)
	return states, next, nil
}

func stateChanged(before, after domain.Client, protocol domain.ClientProtocol) bool {
	oldState, oldErr := before.AccessState(protocol)
	newState, newErr := after.AccessState(protocol)
	return oldErr == nil && newErr == nil && oldState != newState
}

func previousAccessStates(client domain.Client) map[domain.ClientProtocol]domain.ClientState {
	states := make(map[domain.ClientProtocol]domain.ClientState, 2)
	for _, protocol := range []domain.ClientProtocol{domain.ProtocolVLESS, domain.ProtocolHysteria2, domain.ProtocolVMess} {
		if state, err := client.AccessState(protocol); err == nil {
			states[protocol] = state
		}
	}
	return states
}

func protocolStateNames(states map[domain.ClientProtocol]domain.ClientState) []string {
	names := make([]string, 0, len(states))
	for protocol := range states {
		names = append(names, string(protocol))
	}
	sort.Strings(names)
	return names
}

func (s *server) withStats(clients []domain.Client) []clientResponse {
	snapshot := map[string]stats.ClientStats{}
	if s.stats != nil {
		snapshot = s.stats.Snapshot()
	}
	result := make([]clientResponse, 0, len(clients))
	for _, client := range clients {
		current := snapshot[client.ID]
		response := clientResponse{
			Protocol: client.Protocol,
			ID:       client.ID, Name: client.Name, ClientFingerprint: client.ClientFingerprint,
			Enabled: client.Enabled, Revoked: client.Revoked, CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
			Online: current.Online, LastSeen: current.LastSeen, SourceIPs: current.SourceIPs,
			UploadBytes: current.UploadBytes, DownloadBytes: current.DownloadBytes,
			UploadRate: current.UploadBytesPerSecond, DownloadRate: current.DownloadBytesPerSecond,
		}
		if client.HasVLESS() {
			response.Protocols = append(response.Protocols, string(domain.ProtocolVLESS))
			response.VLESS = &clientAccessResponse{Enabled: client.VLESSEnabled, Revoked: client.VLESSRevoked}
		}
		if client.HasHysteria2() {
			response.Protocols = append(response.Protocols, string(domain.ProtocolHysteria2))
			response.Hysteria2 = &clientAccessResponse{Enabled: client.HysteriaEnabled, Revoked: client.HysteriaRevoked}
		}
		if client.HasVMess() {
			response.Protocols = append(response.Protocols, string(domain.ProtocolVMess))
			response.VMess = &clientAccessResponse{Enabled: client.VMessEnabled, Revoked: client.VMessRevoked}
		}
		result = append(result, response)
	}
	return result
}

func (s *server) startReconciler(ctx context.Context) {
	s.startReconcilerWithInterval(ctx, 30*time.Second)
}

func (s *server) startReconcilerWithInterval(ctx context.Context, interval time.Duration) {
	go func() {
		reconcileCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		if err := s.reconcileRunning(reconcileCtx); err != nil {
			s.recordDiagnostic("warn", "initial Xray reconciliation skipped: "+err.Error())
			fmt.Fprintf(os.Stderr, "xray handler reconciliation skipped: %v\n", err)
		}
		cancel()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reconcileCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				if err := s.reconcileRunning(reconcileCtx); err != nil {
					s.recordDiagnostic("warn", "Xray reconciliation skipped: "+err.Error())
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
	maintenanceLock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		return err
	}
	defer maintenanceLock.Close()
	clients, err := s.store.ListClients(ctx)
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		// Before the first device exists there may already be a configured
		// Xray instance. Seed the reserve once node settings are present so the
		// first issued profile can be added without restarting Xray.
		if _, err := s.store.GetSettings(ctx); errors.Is(err, store.ErrSettingsNotInitialized) {
			return nil // first-run setup has not saved node settings yet
		} else if err != nil {
			return err
		}
	}
	if err := s.reconcileRealityShortIDsLocked(ctx, clients); err != nil {
		return fmt.Errorf("reconcile REALITY short IDs: %w", err)
	}
	running, err := s.handler.Users(ctx)
	if err != nil {
		return err
	}
	activeVLESS := make(map[string]domain.Client)
	activeHysteria := make(map[string]domain.Client)
	activeVMess := make(map[string]domain.Client)
	for _, client := range clients {
		if client.VLESSCanConnect() {
			activeVLESS[client.Email] = client
		}
		if client.Hysteria2CanConnect() {
			activeHysteria[client.Email] = client
		}
		if client.VMessCanConnect() {
			activeVMess[client.Email] = client
		}
	}
	runningSet := make(map[string]struct{}, len(running))
	for _, email := range running {
		runningSet[email] = struct{}{}
		if _, ok := activeVLESS[email]; !ok {
			if err := s.handler.RemoveUser(ctx, email); err != nil {
				return err
			}
		}
	}
	for email, client := range activeVLESS {
		if _, ok := runningSet[email]; ok {
			continue
		}
		if err := s.handler.AddUser(ctx, email, client.UUID, xray.Flow); err != nil {
			return err
		}
	}
	if s.hysteriaEnabled(ctx) {
		hysteria, ok := s.handler.(hysteriaHandlerAPI)
		if !ok {
			return errors.New("Hysteria 2 HandlerService is unavailable")
		}
		hysteriaUsers, err := hysteria.UsersInInbound(ctx, xray.HysteriaInboundTag)
		if err != nil {
			return err
		}
		runningHysteria := make(map[string]struct{}, len(hysteriaUsers))
		for _, email := range hysteriaUsers {
			runningHysteria[email] = struct{}{}
			if _, ok := activeHysteria[email]; !ok {
				if err := hysteria.RemoveHysteriaUser(ctx, email); err != nil {
					return err
				}
			}
		}
		for email, client := range activeHysteria {
			if _, ok := runningHysteria[email]; ok {
				continue
			}
			if err := hysteria.AddHysteriaUser(ctx, email, client.HysteriaAuth); err != nil {
				return err
			}
		}
	}
	if vmessInboundExpected(clients) {
		vmess, ok := s.handler.(vmessHandlerAPI)
		if !ok {
			return errors.New("VMess HandlerService is unavailable")
		}
		users, err := vmess.UsersInInbound(ctx, xray.VMessInboundTag)
		if err != nil {
			return err
		}
		runningVMess := make(map[string]struct{}, len(users))
		for _, email := range users {
			runningVMess[email] = struct{}{}
			if _, ok := activeVMess[email]; !ok {
				if err := vmess.RemoveVMessUser(ctx, email); err != nil {
					return err
				}
			}
		}
		for email, client := range activeVMess {
			if _, ok := runningVMess[email]; ok {
				continue
			}
			if err := vmess.AddVMessUser(ctx, email, client.UUID); err != nil {
				return err
			}
		}
	}
	if err := s.reconcilePersistedClientConfigLocked(ctx, clients); err != nil {
		return fmt.Errorf("persist reconciled client state: %w", err)
	}
	return nil
}

func (s *server) reconcilePersistedClientConfigLocked(ctx context.Context, clients []domain.Client) error {
	activePath := filepath.Join(s.configDir, "active.json")
	if activeConfigUsersMatch(activePath, clients, s.hysteriaEnabled(ctx)) {
		return nil
	}
	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return err
	}
	settings.PublicPort = s.publicPort
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		return errors.New("could not decrypt REALITY private key while persisting reconciled state")
	}
	reserved, err := s.store.ListReservedShortIDs(ctx)
	if err != nil {
		return err
	}
	path, operationID, err := s.prepareCandidateWithReservedLocked(ctx, settings, privateKey, clients, reserved)
	if err != nil {
		return err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")
	if err := os.Rename(path, activePath); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		_ = os.Remove(path)
		return fmt.Errorf("promote reconciled client config: %w", err)
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	_ = s.store.AddAudit(ctx, "system", "runtime.reconcile", "clients", "all", "persisted reconciled live client state")
	return nil
}

func activeConfigUsersMatch(path string, clients []domain.Client, includeHysteria bool) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Clients []struct {
					ID    string `json:"id"`
					Email string `json:"email"`
				} `json:"clients"`
				Users []struct {
					Auth  string `json:"auth"`
					Email string `json:"email"`
				} `json:"users"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &config) != nil {
		return false
	}
	wantVLESS := make(map[string]struct{})
	wantHysteria := make(map[string]struct{})
	wantVMess := make(map[string]struct{})
	for _, client := range clients {
		if client.VLESSCanConnect() && client.UUID != "" {
			wantVLESS[client.Email+"\x00"+client.UUID] = struct{}{}
		}
		if client.Hysteria2CanConnect() && client.HysteriaCredential() != "" {
			wantHysteria[client.Email+"\x00"+client.HysteriaCredential()] = struct{}{}
		}
		if client.VMessCanConnect() && client.UUID != "" {
			wantVMess[client.Email+"\x00"+client.UUID] = struct{}{}
		}
	}
	var vless, hysteria, vmess []string
	foundHysteria, foundVMess := false, false
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "vless-reality" {
			for _, client := range inbound.Settings.Clients {
				vless = append(vless, client.Email+"\x00"+client.ID)
			}
		}
		if inbound.Tag == xray.HysteriaInboundTag {
			foundHysteria = true
			for _, user := range inbound.Settings.Users {
				hysteria = append(hysteria, user.Email+"\x00"+user.Auth)
			}
		}
		if inbound.Tag == xray.VMessInboundTag {
			foundVMess = true
			for _, client := range inbound.Settings.Clients {
				vmess = append(vmess, client.Email+"\x00"+client.ID)
			}
		}
	}
	if !stringSliceMatchesSet(vless, wantVLESS) {
		return false
	}
	if includeHysteria {
		if !foundHysteria || !stringSliceMatchesSet(hysteria, wantHysteria) {
			return false
		}
	}
	if foundVMess != vmessInboundExpected(clients) || !stringSliceMatchesSet(vmess, wantVMess) {
		return false
	}
	return true
}

func vmessInboundExpected(clients []domain.Client) bool {
	for _, client := range clients {
		if client.HasVMess() && !client.VMessRevoked {
			return true
		}
	}
	return false
}

func stringSliceMatchesSet(values []string, expected map[string]struct{}) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := expected[value]; !exists {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (s *server) reconcileRealityShortIDsLocked(ctx context.Context, clients []domain.Client) error {
	if err := s.store.SeedReservedShortIDs(ctx, xray.ReservedShortIDCount, xray.NewShortID); err != nil {
		return fmt.Errorf("ensure REALITY short-ID reserve: %w", err)
	}
	settings, err := s.store.GetSettings(ctx)
	if err != nil {
		return err
	}
	settings.PublicPort = s.publicPort
	privateKey, err := secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		return errors.New("could not decrypt REALITY private key during reconciliation")
	}
	reserved, err := s.store.ListReservedShortIDs(ctx)
	if err != nil {
		return err
	}
	activePath := filepath.Join(s.configDir, "active.json")
	currentIDs, err := activeRealityShortIDs(activePath)
	if errors.Is(err, os.ErrNotExist) {
		currentIDs = nil
	} else if err != nil {
		return err
	}
	expectedSet := make(map[string]struct{}, len(clients)+len(reserved))
	for _, client := range clients {
		if client.HasVLESS() && !client.VLESSRevoked && client.ShortID != "" {
			expectedSet[client.ShortID] = struct{}{}
		}
	}
	for _, id := range reserved {
		expectedSet[id] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		if id != "0000000000000000" {
			currentSet[id] = struct{}{}
		}
	}
	needApply := !sameStringSet(currentSet, expectedSet)
	vlessIDsChanged := !sameStringSet(currentSet, expectedSet)
	hysteriaTopologyChanged := hasInboundTag(activePath, xray.HysteriaInboundTag) != s.hysteriaEnabled(ctx)
	vmessTopologyChanged := hasInboundTag(activePath, xray.VMessInboundTag) != vmessInboundExpected(clients)
	if hysteriaTopologyChanged || vmessTopologyChanged {
		needApply = true
	}
	if !needApply {
		return nil
	}
	path, operationID, err := s.prepareCandidateWithReservedLocked(ctx, settings, privateKey, clients, reserved)
	if err != nil {
		return err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")
	fullApply := false
	replacer, canReplace := s.supervisor.(inboundReplacer)
	changedTags := make([]string, 0, 2)
	if vlessIDsChanged {
		changedTags = append(changedTags, "vless-reality")
	}
	if vmessTopologyChanged {
		changedTags = append(changedTags, xray.VMessInboundTag)
	}
	if !hasInboundTag(activePath, "vless-reality") || hysteriaTopologyChanged || !canReplace {
		fullApply = true
		err = s.supervisor.Apply(ctx, path, operationID)
	} else {
		replacedTags := make([]string, 0, len(changedTags))
		for _, tag := range changedTags {
			if err = replacer.ReplaceInbound(ctx, path, activePath, tag, operationID); err != nil {
				break
			}
			replacedTags = append(replacedTags, tag)
		}
		changedTags = replacedTags
	}
	if err != nil {
		if !fullApply {
			for i := len(changedTags) - 1; i >= 0; i-- {
				_ = replacer.ReplaceInbound(ctx, activePath, path, changedTags[i], operationID+"-rollback")
			}
		}
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		_ = os.Remove(path)
		return err
	}
	if err := os.Rename(path, activePath); err != nil {
		if fullApply {
			_ = s.supervisor.Apply(ctx, activePath, operationID+"-rollback")
		} else if canReplace {
			for i := len(changedTags) - 1; i >= 0; i-- {
				_ = replacer.ReplaceInbound(ctx, activePath, path, changedTags[i], operationID+"-rollback")
			}
		}
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		_ = os.Remove(path)
		return fmt.Errorf("promote reconciled Xray config: %w", err)
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	_ = s.store.AddAudit(ctx, "system", "runtime.reconcile", "xray", "vless-reality", "recovered desired REALITY inbound state")
	return nil
}

func activeRealityShortIDs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Inbounds []struct {
			Tag            string `json:"tag"`
			StreamSettings struct {
				RealitySettings struct {
					ShortIDs []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, errors.New("active Xray config is invalid JSON")
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "vless-reality" {
			return inbound.StreamSettings.RealitySettings.ShortIDs, nil
		}
	}
	return nil, nil
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if _, exists := right[value]; !exists {
			return false
		}
	}
	return true
}

func (s *server) applyClientsLocked(ctx context.Context, settings domain.Settings, privateKey string, clients []domain.Client, actorID, action, entityID string) error {
	maintenanceLock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		return err
	}
	defer maintenanceLock.Close()
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

func (s *server) applyClientsLiveLocked(ctx context.Context, settings domain.Settings, privateKey string, clients []domain.Client, actorID, action, entityID string, persist, rollbackPersist func() error) error {
	maintenanceLock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		return err
	}
	defer maintenanceLock.Close()
	path, operationID, err := s.prepareCandidateLocked(ctx, settings, privateKey, clients)
	if err != nil {
		return err
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "validated", "")
	_ = s.store.UpdateApplyOperation(ctx, operationID, "applying", "")

	// A complete candidate is needed whenever the client set changes: the
	// HandlerService can add/remove VLESS users, but it cannot update the
	// REALITY shortIds list. Apply the candidate through supervisor so the
	// child Xray process starts with both lists in sync.
	if err := s.supervisor.Apply(ctx, path, operationID); err != nil {
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return err
	}
	if persist != nil {
		if err := persist(); err != nil {
			_ = s.supervisor.Apply(ctx, filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
			_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
			return fmt.Errorf("persist client change: %w", err)
		}
	}
	if err := os.Rename(path, filepath.Join(s.configDir, "active.json")); err != nil {
		if rollbackPersist != nil {
			_ = rollbackPersist()
		}
		_ = s.supervisor.Apply(ctx, filepath.Join(s.configDir, "active.json"), operationID+"-rollback")
		_ = s.store.UpdateApplyOperation(ctx, operationID, "failed", err.Error())
		return fmt.Errorf("promote Xray config: %w", err)
	}
	_ = s.store.UpdateApplyOperation(ctx, operationID, "committed", "")
	_ = s.store.AddAudit(ctx, actorID, action, "client", entityID, "configuration applied")
	return nil
}

func (s *server) prepareCandidateLocked(ctx context.Context, settings domain.Settings, privateKey string, clients []domain.Client) (string, string, error) {
	if err := s.store.SeedReservedShortIDs(ctx, xray.ReservedShortIDCount, xray.NewShortID); err != nil {
		return "", "", err
	}
	reserved, err := s.store.ListReservedShortIDs(ctx)
	if err != nil {
		return "", "", err
	}
	return s.prepareCandidateWithReservedLocked(ctx, settings, privateKey, clients, reserved)
}

func (s *server) prepareCandidateWithReservedLocked(ctx context.Context, settings domain.Settings, privateKey string, clients []domain.Client, reserved []string) (string, string, error) {
	hysteriaSettings, err := loadHysteriaSettings(ctx, s.store)
	if err != nil {
		return "", "", err
	}
	return s.prepareCandidateWithHysteriaLocked(ctx, settings, privateKey, clients, reserved, hysteriaSettings)
}

func (s *server) prepareCandidateWithHysteriaLocked(ctx context.Context, settings domain.Settings, privateKey string, clients []domain.Client, reserved []string, hysteriaSettings domain.HysteriaSettings) (string, string, error) {
	xrayClients := xray.ClientsFromDomain(clients)
	renderSettings := rendererSettingsWithHysteria(settings, privateKey, hysteriaSettings)
	renderSettings.ReservedShortIDs = append([]string(nil), reserved...)
	rendered, err := xray.RenderServerConfig(renderSettings, xrayClients)
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
		_ = os.Remove(path)
		return "", "", err
	}
	return path, operationID, nil
}

func rendererSettings(settings domain.Settings, privateKey string) xray.Settings {
	return rendererSettingsWithHysteria(settings, privateKey, hysteriaSettingsFromEnvironment())
}

func rendererSettingsWithHysteria(settings domain.Settings, privateKey string, hysteriaSettings domain.HysteriaSettings) xray.Settings {
	result := xray.SettingsFromDomain(settings, privateKey)
	xray.ApplyHysteriaSettings(&result, hysteriaSettings)
	result.VMessPublicPort, _ = configuredVMessPort()
	return result
}

func hysteria2Enabled() bool {
	return strings.EqualFold(strings.TrimSpace(envOr("XRAY_HYSTERIA2_ENABLED", "false")), "true")
}

func hysteriaSettingsFromEnvironment() domain.HysteriaSettings {
	return domain.HysteriaSettings{
		Enabled:        hysteria2Enabled(),
		TLSMode:        envOr("XRAY_HYSTERIA2_TLS_MODE", domain.HysteriaTLSLegacy),
		TLSCertIP:      strings.TrimSpace(os.Getenv("XRAY_HYSTERIA2_CERT_IP")),
		TLSServerName:  strings.TrimSpace(os.Getenv("XRAY_HYSTERIA2_TLS_SERVER_NAME")),
		UDPIdleTimeout: 60,
		MasqueradeType: domain.HysteriaMasqueradeOff,
	}
}

func loadHysteriaSettings(ctx context.Context, db *store.Store) (domain.HysteriaSettings, error) {
	settings, err := db.GetHysteriaSettings(ctx)
	if err == nil {
		return settings, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.HysteriaSettings{}, err
	}
	defaults := hysteriaSettingsFromEnvironment()
	if err := db.InitializeHysteriaSettings(ctx, defaults); err != nil {
		return domain.HysteriaSettings{}, err
	}
	return db.GetHysteriaSettings(ctx)
}

func (s *server) hysteriaEnabled(ctx context.Context) bool {
	settings, err := loadHysteriaSettings(ctx, s.store)
	if err != nil {
		return hysteria2Enabled()
	}
	return settings.Enabled
}

func (s *server) validateHysteriaHost(ctx context.Context, host string) error {
	settings, err := loadHysteriaSettings(ctx, s.store)
	if err != nil {
		return err
	}
	if settings.Enabled && settings.Host == "" && settings.TLSMode == domain.HysteriaTLSSelfSigned && host != settings.TLSCertIP {
		return errors.New("public_host must match XRAY_HYSTERIA2_CERT_IP used by the Hysteria 2 self-signed certificate")
	}
	return nil
}

func validateHysteriaPublicHost(host string) error {
	settings := hysteriaSettingsFromEnvironment()
	if settings.Enabled && settings.TLSMode == domain.HysteriaTLSSelfSigned && host != settings.TLSCertIP {
		return errors.New("public_host must match XRAY_HYSTERIA2_CERT_IP for the mkcert Hysteria 2 certificate")
	}
	return nil
}

func hasInboundTag(path, tag string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &config) != nil {
		return false
	}
	for _, inbound := range config.Inbounds {
		if inbound.Tag == tag {
			return true
		}
	}
	return false
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

func (s *server) profile(w http.ResponseWriter, r *http.Request, client domain.Client) {
	settings, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "settings are incomplete"})
		return
	}
	settings.PublicPort = s.publicPort
	privateKey := ""
	if client.HasVLESS() && !client.VLESSRevoked {
		privateKey, err = secret.Open(s.masterKey, settings.RealityPrivateKeyEnc, "reality_private_key")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
			return
		}
	}
	_ = privateKey
	hysteriaSettings, err := loadHysteriaSettings(r.Context(), s.store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read Hysteria 2 settings"})
		return
	}
	renderSettings := rendererSettingsWithHysteria(settings, "server-secret-not-exported", hysteriaSettings)
	renderSettings.VMessPublicPort = s.vmessPort
	if client.HasVMess() && !client.VMessRevoked && (hysteriaSettings.TLSMode == domain.HysteriaTLSSelfSigned || hysteriaSettings.TLSMode == domain.HysteriaTLSLegacy) {
		serverName := hysteriaSettings.EffectiveTLSServerName(settings.PublicHost)
		certificate, inspectErr := hysteria.Inspect(s.hysteriaTLSDir(), hysteriaSettings.CertificateID, serverName, hysteriaSettings.CertificateID == "")
		if inspectErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "certificate_not_ready", "error": "could not read the VMess TLS certificate fingerprint", "detail": inspectErr.Error()})
			return
		}
		renderSettings.HysteriaTLSFingerprint = certificate.Fingerprint
	}
	profile, err := xray.BuildProfile(renderSettings, xray.ClientFromDomain(client))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	format := r.URL.Query().Get("format")
	switch format {
	case "json":
		if len(profile.JSON) == 0 {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "profile_format_unavailable", "error": "JSON profile is unavailable for this device"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+client.Name+`.json"`)
		_, _ = w.Write(profile.JSON)
	case "qr":
		if profile.URI == "" {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "profile_format_unavailable", "error": "VLESS is not available for this profile"})
			return
		}
		png, err := qrcode.Encode(profile.URI, qrcode.Medium, 512)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encode QR"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	case "hysteria-qr":
		if profile.HysteriaURI == "" {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Hysteria 2 is not enabled"})
			return
		}
		png, err := qrcode.Encode(profile.HysteriaURI, qrcode.Medium, 512)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encode Hysteria QR"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	case "vmess-qr":
		if profile.VMessURI == "" {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "profile_format_unavailable", "error": "VMess is not available for this profile"})
			return
		}
		png, err := qrcode.Encode(profile.VMessURI, qrcode.Medium, 512)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not encode VMess QR"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(png)
	default:
		response := map[string]any{"client_id": client.ID, "protocol": client.Protocol, "name": profile.Name}
		if client.Protocol == domain.ProtocolLegacyDual || client.Protocol == "" {
			if profile.URI != "" {
				response["uri"] = profile.URI
			}
			if len(profile.JSON) > 0 {
				response["json"] = json.RawMessage(profile.JSON)
			}
			if profile.HysteriaURI != "" {
				response["hysteria_uri"] = profile.HysteriaURI
			}
		} else if client.Protocol == domain.ProtocolVLESS {
			if profile.URI != "" {
				response["uri"] = profile.URI
			}
			if len(profile.JSON) > 0 {
				response["json"] = json.RawMessage(profile.JSON)
			}
		} else if client.Protocol == domain.ProtocolHysteria2 {
			response["hysteria_uri"] = profile.HysteriaURI
		} else if client.Protocol == domain.ProtocolVMess {
			response["vmess_uri"] = profile.VMessURI
			if len(profile.JSON) > 0 {
				response["json"] = json.RawMessage(profile.JSON)
			}
		}
		writeJSON(w, http.StatusOK, response)
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

func publicSettings(settings domain.Settings, vmessPublicPort int) map[string]any {
	return map[string]any{"public_host": settings.PublicHost, "public_port": settings.PublicPort, "vmess_public_port": vmessPublicPort, "reality_target": settings.RealityTarget, "reality_sni": settings.RealitySNI, "client_fingerprint": settings.ClientFingerprint, "log_level": settings.LogLevel, "protocol": xray.Protocol, "network": xray.Network, "security": xray.Security, "flow": xray.Flow}
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
