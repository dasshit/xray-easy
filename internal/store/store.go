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
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings(id, public_host, public_port, created_at, updated_at) VALUES(1,?,?,?,?)`, publicHost, publicPort, now, now); err != nil {
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

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
