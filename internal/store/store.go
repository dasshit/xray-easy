package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Admin struct {
	ID           string
	Username     string
	PasswordHash string
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
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	for _, column := range []string{
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
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash FROM admin_users WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)).Scan(&admin.ID, &admin.Username, &admin.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, errors.New("admin not found")
	}
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
	err := s.db.QueryRowContext(ctx, `SELECT a.id, a.username, a.password_hash, s.expires_at FROM sessions s JOIN admin_users a ON a.id=s.admin_user_id WHERE s.token_hash=?`, hash[:]).Scan(&admin.ID, &admin.Username, &admin.PasswordHash, &expires)
	if err != nil {
		return Admin{}, errors.New("session not found")
	}
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
