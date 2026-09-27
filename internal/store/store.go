package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Admin struct {
	ID            string
	Username      string
	PasswordHash  string
	TOTPSecretEnc string
	TOTPEnabled   bool
}

type SetupStatus struct {
	Initialized bool `json:"initialized"`
}

type Settings struct {
	PublicHost           string
	PublicPort           int
	XrayAPIListen        string
	InternalInboundPort  int
	RealityTarget        string
	RealitySNI           string
	RealityPrivateKeyEnc string
	RealityPublicKey     string
	ClientFingerprint    string
}

type Client struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	UUID              string    `json:"-"`
	Email             string    `json:"-"`
	ShortID           string    `json:"-"`
	ClientFingerprint string    `json:"fingerprint,omitempty"`
	Enabled           bool      `json:"enabled"`
	Revoked           bool      `json:"revoked"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TrafficSnapshot is the durable checkpoint for the counters returned by
// Xray's StatsService. Xray counters are process-local and can reset after a
// restart, so total_* are accumulated by the control plane while raw_* keep
// the last observed Xray values for reset detection.
type TrafficSnapshot struct {
	ClientID      string
	RawUpload     int64
	RawDownload   int64
	TotalUpload   int64
	TotalDownload int64
	LastSeenAt    time.Time
	LastPolledAt  time.Time
}

type ApplyOperation struct {
	ID        string
	Revision  int64
	State     string
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// BackupTo creates a transactionally consistent SQLite snapshot. VACUUM INTO
// includes committed WAL contents and never exposes the live database file to
// callers.
func (s *Store) BackupTo(path string) error {
	if path == "" {
		return errors.New("invalid backup path")
	}
	_ = os.Remove(path)
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func ValidateDatabase(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return err
	}
	for _, table := range databaseTables {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return fmt.Errorf("database table %s is missing", table)
		}
	}
	return nil
}

func ReadSettingsFromDatabase(path string) (Settings, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return Settings{}, err
	}
	defer db.Close()
	var settings Settings
	err = db.QueryRow(`SELECT public_host, public_port, xray_api_listen, internal_inbound_port, reality_target, reality_sni, reality_private_key_enc, reality_public_key, client_fingerprint FROM settings WHERE id=1`).Scan(&settings.PublicHost, &settings.PublicPort, &settings.XrayAPIListen, &settings.InternalInboundPort, &settings.RealityTarget, &settings.RealitySNI, &settings.RealityPrivateKeyEnc, &settings.RealityPublicKey, &settings.ClientFingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, errors.New("settings are not initialized")
	}
	return settings, err
}

func (s *Store) RestoreFrom(path string) error {
	if err := ValidateDatabase(path); err != nil {
		return err
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `ATTACH DATABASE ? AS restore_source`, path); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), `DETACH DATABASE restore_source`)
	if _, err := conn.ExecContext(context.Background(), `PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
	tx, err := conn.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	for _, table := range databaseTables {
		if _, err := tx.Exec(`DELETE FROM main.` + table); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("clear table %s: %w", table, err)
		}
	}
	for _, table := range databaseTables {
		if _, err := tx.Exec(`INSERT INTO main.` + table + ` SELECT * FROM restore_source.` + table); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("restore table %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

var databaseTables = []string{
	"schema_migrations",
	"settings",
	"admin_users",
	"sessions",
	"totp_recovery_codes",
	"clients",
	"config_revisions",
	"apply_operations",
	"audit_events",
	"traffic_snapshots",
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  schema_version INTEGER NOT NULL DEFAULT 1,
  public_host TEXT,
  public_port INTEGER,
  xray_api_listen TEXT NOT NULL DEFAULT '127.0.0.1:10085',
  internal_inbound_port INTEGER NOT NULL DEFAULT 8443,
  reality_target TEXT NOT NULL DEFAULT '',
  reality_sni TEXT NOT NULL DEFAULT '',
  reality_private_key_enc TEXT NOT NULL DEFAULT '',
  reality_public_key TEXT NOT NULL DEFAULT '',
  client_fingerprint TEXT NOT NULL DEFAULT 'chrome',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  totp_secret_enc TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
  id TEXT PRIMARY KEY,
  admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS totp_recovery_admin_idx ON totp_recovery_codes(admin_user_id, used_at);
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  uuid TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  short_id TEXT NOT NULL UNIQUE,
  client_fingerprint TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_revisions (
  revision INTEGER PRIMARY KEY,
  config_hash TEXT NOT NULL,
  state TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apply_operations (
  id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  state TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  redacted_diff TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_snapshots (
  client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  raw_upload INTEGER NOT NULL DEFAULT 0,
  raw_download INTEGER NOT NULL DEFAULT 0,
  total_upload INTEGER NOT NULL DEFAULT 0,
  total_download INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT NOT NULL DEFAULT '',
  last_polled_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	for _, column := range []string{
		`ALTER TABLE admin_users ADD COLUMN totp_secret_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE admin_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE settings ADD COLUMN xray_api_listen TEXT NOT NULL DEFAULT '127.0.0.1:10085'`,
		`ALTER TABLE settings ADD COLUMN internal_inbound_port INTEGER NOT NULL DEFAULT 8443`,
		`ALTER TABLE settings ADD COLUMN reality_target TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN reality_sni TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN reality_private_key_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN reality_public_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE settings ADD COLUMN client_fingerprint TEXT NOT NULL DEFAULT 'chrome'`,
	} {
		if _, err := s.db.ExecContext(ctx, column); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return fmt.Errorf("migrate settings: %w", err)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) SetupStatus(ctx context.Context) (SetupStatus, error) {
	var status SetupStatus
	var marker int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM admin_users LIMIT 1`).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return status, err
	}
	status.Initialized = true
	return status, nil
}

func (s *Store) Initialize(ctx context.Context, username, passwordHash, publicHost string, publicPort int) (Admin, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || passwordHash == "" {
		return Admin{}, errors.New("username and password hash are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	id, err := randomID()
	if err != nil {
		return Admin{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Admin{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&count); err != nil {
		return Admin{}, err
	}
	if count != 0 {
		return Admin{}, errors.New("setup is already initialized")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_users(id, username, password_hash, created_at, updated_at) VALUES(?,?,?,?,?)`, id, username, passwordHash, now, now); err != nil {
		return Admin{}, fmt.Errorf("create admin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(id, public_host, public_port, xray_api_listen, internal_inbound_port, created_at, updated_at) VALUES(1,?,?,?,?,?,?)`, publicHost, publicPort, "127.0.0.1:10085", 8443, now, now); err != nil {
		return Admin{}, fmt.Errorf("create settings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Admin{}, err
	}
	return Admin{ID: id, Username: username, PasswordHash: passwordHash}, nil
}

func (s *Store) FindAdmin(ctx context.Context, username string) (Admin, error) {
	var admin Admin
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, totp_secret_enc, totp_enabled FROM admin_users WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &admin.TOTPSecretEnc, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, errors.New("admin not found")
	}
	admin.TOTPEnabled = enabled != 0
	return admin, err
}

func (s *Store) CreateSession(ctx context.Context, adminID string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id, admin_user_id, token_hash, created_at, expires_at, last_seen_at) VALUES(?,?,?,?,?,?)`, hex.EncodeToString(raw[:16]), adminID, hash[:], now.Format(time.RFC3339Nano), now.Add(ttl).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) SessionAdmin(ctx context.Context, token string) (Admin, error) {
	hash := sha256.Sum256([]byte(token))
	var admin Admin
	var expires string
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT a.id, a.username, a.password_hash, a.totp_secret_enc, a.totp_enabled, s.expires_at FROM sessions s JOIN admin_users a ON a.id=s.admin_user_id WHERE s.token_hash=?`, hash[:]).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &admin.TOTPSecretEnc, &enabled, &expires)
	if err != nil {
		return Admin{}, errors.New("session not found")
	}
	admin.TOTPEnabled = enabled != 0
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || time.Now().UTC().After(expiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash[:])
		return Admin{}, errors.New("session expired")
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=? WHERE token_hash=?`, time.Now().UTC().Format(time.RFC3339Nano), hash[:])
	return admin, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hash[:])
	return err
}

func (s *Store) DeleteAllSessions(ctx context.Context, adminID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE admin_user_id=?`, adminID)
	return err
}

// SetTOTP replaces the encrypted secret and recovery-code hashes atomically.
// Raw recovery codes must never be passed here; only their hashes are stored.
func (s *Store) SetTOTP(ctx context.Context, adminID, secretEnc string, recoveryHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE admin_users SET totp_secret_enc=?, totp_enabled=1, updated_at=? WHERE id=?`, secretEnc, now, adminID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE admin_user_id=?`, adminID); err != nil {
		return err
	}
	for _, hash := range recoveryHashes {
		id, err := randomID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO totp_recovery_codes(id, admin_user_id, code_hash, created_at) VALUES(?,?,?,?)`, id, adminID, hash, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DisableTOTP(ctx context.Context, adminID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE admin_users SET totp_secret_enc='', totp_enabled=0, updated_at=? WHERE id=?`, now, adminID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE admin_user_id=?`, adminID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeRecoveryCode(ctx context.Context, adminID, codeHash string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE totp_recovery_codes SET used_at=? WHERE admin_user_id=? AND code_hash=? AND used_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), adminID, codeHash)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}

func (s *Store) RecoveryCodeCount(ctx context.Context, adminID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp_recovery_codes WHERE admin_user_id=? AND used_at IS NULL`, adminID).Scan(&count)
	return count, err
}

func (s *Store) FirstAdmin(ctx context.Context) (Admin, error) {
	var admin Admin
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, totp_secret_enc, totp_enabled FROM admin_users ORDER BY created_at LIMIT 1`).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &admin.TOTPSecretEnc, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, errors.New("admin not found")
	}
	admin.TOTPEnabled = enabled != 0
	return admin, err
}

func (s *Store) ReplaceRecoveryCodes(ctx context.Context, adminID string, recoveryHashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `DELETE FROM totp_recovery_codes WHERE admin_user_id=?`, adminID); err != nil {
		return err
	}
	for _, hash := range recoveryHashes {
		id, err := randomID()
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO totp_recovery_codes(id, admin_user_id, code_hash, created_at) VALUES(?,?,?,?)`, id, adminID, hash, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetSettings(ctx context.Context) (Settings, error) {
	var settings Settings
	err := s.db.QueryRowContext(ctx, `SELECT public_host, public_port, xray_api_listen, internal_inbound_port, reality_target, reality_sni, reality_private_key_enc, reality_public_key, client_fingerprint FROM settings WHERE id=1`).Scan(&settings.PublicHost, &settings.PublicPort, &settings.XrayAPIListen, &settings.InternalInboundPort, &settings.RealityTarget, &settings.RealitySNI, &settings.RealityPrivateKeyEnc, &settings.RealityPublicKey, &settings.ClientFingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, errors.New("settings are not initialized")
	}
	return settings, err
}

func (s *Store) UpdateSettings(ctx context.Context, settings Settings) error {
	_, err := s.db.ExecContext(ctx, `UPDATE settings SET public_host=?, public_port=?, xray_api_listen=?, internal_inbound_port=?, reality_target=?, reality_sni=?, reality_private_key_enc=?, reality_public_key=?, client_fingerprint=?, updated_at=? WHERE id=1`, settings.PublicHost, settings.PublicPort, settings.XrayAPIListen, settings.InternalInboundPort, settings.RealityTarget, settings.RealitySNI, settings.RealityPrivateKeyEnc, settings.RealityPublicKey, settings.ClientFingerprint, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) CreateClient(ctx context.Context, client Client, uuid, email, shortID string) error {
	if client.ID == "" {
		return errors.New("client id is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients(id, name, uuid, email, short_id, client_fingerprint, enabled, revoked, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, client.ID, client.Name, uuid, email, shortID, client.ClientFingerprint, boolInt(client.Enabled), boolInt(client.Revoked), now, now)
	return err
}

func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, uuid, email, short_id, client_fingerprint, enabled, revoked, created_at, updated_at FROM clients ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []Client
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, uuid, email, short_id, client_fingerprint, enabled, revoked, created_at, updated_at FROM clients WHERE id=?`, id)
	return scanClient(row)
}

func (s *Store) SetClientState(ctx context.Context, id string, enabled, revoked bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET enabled=?, revoked=?, updated_at=? WHERE id=?`, boolInt(enabled), boolInt(revoked), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return errors.New("client not found")
	}
	return err
}

func (s *Store) DeleteClient(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id=?`, id)
	return err
}

func (s *Store) ListTrafficSnapshots(ctx context.Context) (map[string]TrafficSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, raw_upload, raw_download, total_upload, total_download, last_seen_at, last_polled_at FROM traffic_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]TrafficSnapshot)
	for rows.Next() {
		var snapshot TrafficSnapshot
		var lastSeen, lastPolled string
		if err := rows.Scan(&snapshot.ClientID, &snapshot.RawUpload, &snapshot.RawDownload, &snapshot.TotalUpload, &snapshot.TotalDownload, &lastSeen, &lastPolled); err != nil {
			return nil, err
		}
		if lastSeen != "" {
			snapshot.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
		}
		snapshot.LastPolledAt, _ = time.Parse(time.RFC3339Nano, lastPolled)
		result[snapshot.ClientID] = snapshot
	}
	return result, rows.Err()
}

func (s *Store) UpsertTrafficSnapshot(ctx context.Context, snapshot TrafficSnapshot) error {
	if snapshot.ClientID == "" {
		return errors.New("client id is required")
	}
	lastSeen := ""
	if !snapshot.LastSeenAt.IsZero() {
		lastSeen = snapshot.LastSeenAt.UTC().Format(time.RFC3339Nano)
	}
	lastPolled := snapshot.LastPolledAt
	if lastPolled.IsZero() {
		lastPolled = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO traffic_snapshots(client_id, raw_upload, raw_download, total_upload, total_download, last_seen_at, last_polled_at) VALUES(?,?,?,?,?,?,?)
ON CONFLICT(client_id) DO UPDATE SET raw_upload=excluded.raw_upload, raw_download=excluded.raw_download, total_upload=excluded.total_upload, total_download=excluded.total_download, last_seen_at=excluded.last_seen_at, last_polled_at=excluded.last_polled_at`, snapshot.ClientID, snapshot.RawUpload, snapshot.RawDownload, snapshot.TotalUpload, snapshot.TotalDownload, lastSeen, lastPolled.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) CreateApplyOperation(ctx context.Context, operation ApplyOperation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO apply_operations(id, revision, state, error, created_at, updated_at) VALUES(?,?,?,?,?,?)`, operation.ID, operation.Revision, operation.State, operation.Error, operation.CreatedAt.Format(time.RFC3339Nano), operation.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) UpdateApplyOperation(ctx context.Context, id, state, operationError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE apply_operations SET state=?, error=?, updated_at=? WHERE id=?`, state, operationError, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) AddAudit(ctx context.Context, actorID, action, entity, entityID, diff string) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events(id, actor_id, action, entity, entity_id, redacted_diff, created_at) VALUES(?,?,?,?,?,?,?)`, id, actorID, action, entity, entityID, diff, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type scanner interface{ Scan(...any) error }

func scanClient(row scanner) (Client, error) {
	var client Client
	var uuid, email, shortID string
	var enabled, revoked int
	var created, updated string
	err := row.Scan(&client.ID, &client.Name, &uuid, &email, &shortID, &client.ClientFingerprint, &enabled, &revoked, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, errors.New("client not found")
		}
		return Client{}, err
	}
	client.UUID, client.Email, client.ShortID = uuid, email, shortID
	client.Enabled, client.Revoked = enabled != 0, revoked != 0
	client.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	client.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return client, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
