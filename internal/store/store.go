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
	"path/filepath"
	"strings"
	"time"

	"xray-easy/internal/domain"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	dbPath string
}

// ErrSettingsNotInitialized indicates that first-run server settings have not
// been saved yet.
var ErrSettingsNotInitialized = errors.New("settings are not initialized")

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

// Deprecated: domain entities live in internal/domain. These aliases keep the
// persistence package source-compatible for callers that only need storage.
type Settings = domain.Settings
type Client = domain.Client
type ClientState = domain.ClientState

// TrafficSnapshot is the durable checkpoint for counters returned by the
// embedded Xray runtime. Runtime counters are process-local and can reset after
// a restart, so total_* are accumulated by the control plane while raw_* keep
// the last observed values for reset detection.
type TrafficSnapshot struct {
	ClientID      string
	RawUpload     int64
	RawDownload   int64
	TotalUpload   int64
	TotalDownload int64
	LastSeenAt    time.Time
	LastPolledAt  time.Time
}

// AWGTrafficSnapshot checkpoints process-local AmneziaWG counters by peer name.
type AWGTrafficSnapshot struct {
	PeerName      string
	RawUpload     int64
	RawDownload   int64
	TotalUpload   int64
	TotalDownload int64
	SourceIP      string
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
	store := &Store{db: db, dbPath: path}
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
		if exists != 1 && table != "reality_short_ids" && table != "hysteria_settings" {
			return fmt.Errorf("database table %s is missing", table)
		}
	}
	return nil
}

func ReadSettingsFromDatabase(path string) (domain.Settings, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return domain.Settings{}, err
	}
	defer db.Close()
	var settings domain.Settings
	if hasSettingsLogLevel(db) {
		err = db.QueryRow(`SELECT public_host, public_port, xray_api_listen, internal_inbound_port, reality_target, reality_sni, reality_private_key_enc, reality_public_key, client_fingerprint, log_level FROM settings WHERE id=1`).Scan(&settings.PublicHost, &settings.PublicPort, &settings.XrayAPIListen, &settings.InternalInboundPort, &settings.RealityTarget, &settings.RealitySNI, &settings.RealityPrivateKeyEnc, &settings.RealityPublicKey, &settings.ClientFingerprint, &settings.LogLevel)
	} else {
		err = db.QueryRow(`SELECT public_host, public_port, xray_api_listen, internal_inbound_port, reality_target, reality_sni, reality_private_key_enc, reality_public_key, client_fingerprint FROM settings WHERE id=1`).Scan(&settings.PublicHost, &settings.PublicPort, &settings.XrayAPIListen, &settings.InternalInboundPort, &settings.RealityTarget, &settings.RealitySNI, &settings.RealityPrivateKeyEnc, &settings.RealityPublicKey, &settings.ClientFingerprint)
		settings.LogLevel = "warning"
	}
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Settings{}, ErrSettingsNotInitialized
	}
	return settings, err
}

func hasSettingsLogLevel(db *sql.DB) bool {
	rows, err := db.Query(`PRAGMA table_info(settings)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey) == nil && name == "log_level" {
			return true
		}
	}
	return false
}

func restoreSettings(tx *sql.Tx) error {
	hasLogLevel := false
	rows, err := tx.Query(`PRAGMA restore_source.table_info(settings)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == "log_level" {
			hasLogLevel = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	logLevel := `'warning'`
	if hasLogLevel {
		logLevel = `log_level`
	}
	_, err = tx.Exec(`INSERT INTO main.settings (
		id, schema_version, public_host, public_port, xray_api_listen,
		internal_inbound_port, reality_target, reality_sni,
		reality_private_key_enc, reality_public_key, client_fingerprint,
		log_level, created_at, updated_at
	) SELECT id, schema_version, public_host, public_port, xray_api_listen,
		internal_inbound_port, reality_target, reality_sni,
		reality_private_key_enc, reality_public_key, client_fingerprint,
		` + logLevel + `, created_at, updated_at FROM restore_source.settings`)
	return err
}

func restoreClients(tx *sql.Tx) error {
	hasProtocol := false
	hasVMessEnabled, hasVMessRevoked := false, false
	rows, err := tx.Query(`PRAGMA restore_source.table_info(clients)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == "protocol" {
			hasProtocol = true
		}
		if name == "vmess_enabled" {
			hasVMessEnabled = true
		}
		if name == "vmess_revoked" {
			hasVMessRevoked = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if hasProtocol {
		vmessEnabled, vmessRevoked := `0`, `0`
		if hasVMessEnabled {
			vmessEnabled = `vmess_enabled`
		}
		if hasVMessRevoked {
			vmessRevoked = `vmess_revoked`
		}
		_, err = tx.Exec(`INSERT INTO main.clients(
			id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
			protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
			hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at
		) SELECT id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
			protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
			hysteria_revoked, ` + vmessEnabled + `, ` + vmessRevoked + `, created_at, updated_at
			FROM restore_source.clients`)
		return err
	}
	_, err = tx.Exec(`INSERT INTO main.clients(
		id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
		hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at
	) SELECT id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		'legacy_dual', uuid, enabled, revoked, enabled, revoked, 0, 0, created_at, updated_at
		FROM restore_source.clients`)
	return err
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
		var restoreErr error
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM restore_source.sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("inspect restore table %s: %w", table, err)
		}
		if exists == 0 {
			switch table {
			case "reality_short_ids":
				continue
			case "hysteria_settings":
				if _, restoreErr = tx.Exec(`INSERT INTO main.hysteria_settings(id, enabled, host, tls_mode, tls_cert_ip, tls_server_name, certificate_id, udp_idle_timeout, masquerade_type, masquerade_string, updated_at) VALUES(1,0,'','legacy','','','',60,'off','',?)`, time.Now().UTC().Format(time.RFC3339Nano)); restoreErr != nil {
					_ = tx.Rollback()
					return fmt.Errorf("restore default Hysteria 2 settings: %w", restoreErr)
				}
				continue
			}
		}
		if table == "settings" {
			restoreErr = restoreSettings(tx)
		} else if table == "clients" {
			restoreErr = restoreClients(tx)
		} else {
			_, restoreErr = tx.Exec(`INSERT INTO main.` + table + ` SELECT * FROM restore_source.` + table)
		}
		if restoreErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("restore table %s: %w", table, restoreErr)
		}
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO main.reality_short_ids(short_id, assigned_client_id, created_at) SELECT short_id, id, created_at FROM main.clients WHERE short_id IS NOT NULL AND short_id != ''`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("restore short ID history: %w", err)
	}
	if err := insertClientProtocolMigrationMarker(context.Background(), tx); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("restore client protocol migration marker: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(5, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("restore VMess migration marker: %w", err)
	}
	if _, err := tx.Exec(`UPDATE main.apply_revision_sequence SET revision = MAX(revision, (SELECT COALESCE(MAX(revision), 0) FROM main.apply_operations)) WHERE id = 1`); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("preserve apply revision high-water mark: %w", err)
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
	"reality_short_ids",
	"hysteria_settings",
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
  log_level TEXT NOT NULL DEFAULT 'warning',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hysteria_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 0,
  host TEXT NOT NULL DEFAULT '',
  tls_mode TEXT NOT NULL DEFAULT 'custom',
  tls_cert_ip TEXT NOT NULL DEFAULT '',
  tls_server_name TEXT NOT NULL DEFAULT '',
  certificate_id TEXT NOT NULL DEFAULT '',
  udp_idle_timeout INTEGER NOT NULL DEFAULT 60,
  masquerade_type TEXT NOT NULL DEFAULT 'off',
  masquerade_string TEXT NOT NULL DEFAULT '',
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
  uuid TEXT UNIQUE,
  email TEXT NOT NULL UNIQUE,
  short_id TEXT UNIQUE,
  client_fingerprint TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  revoked INTEGER NOT NULL DEFAULT 0,
  protocol TEXT NOT NULL DEFAULT 'legacy_dual',
  hysteria_auth TEXT NOT NULL DEFAULT '',
  vless_enabled INTEGER NOT NULL DEFAULT 1,
  vless_revoked INTEGER NOT NULL DEFAULT 0,
  hysteria_enabled INTEGER NOT NULL DEFAULT 1,
  hysteria_revoked INTEGER NOT NULL DEFAULT 0,
  vmess_enabled INTEGER NOT NULL DEFAULT 0,
  vmess_revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reality_short_ids (
  short_id TEXT PRIMARY KEY,
  assigned_client_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reality_short_ids_pool_idx ON reality_short_ids(assigned_client_id, created_at);
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
CREATE TABLE IF NOT EXISTS apply_revision_sequence (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  revision INTEGER NOT NULL
);
INSERT OR IGNORE INTO apply_revision_sequence(id, revision)
  SELECT 1, COALESCE(MAX(revision), 0) FROM apply_operations;
UPDATE apply_revision_sequence
  SET revision = MAX(revision, (SELECT COALESCE(MAX(revision), 0) FROM apply_operations)) WHERE id = 1;
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
CREATE TABLE IF NOT EXISTS awg_traffic_snapshots (
  peer_name TEXT PRIMARY KEY,
  raw_upload INTEGER NOT NULL DEFAULT 0,
  raw_download INTEGER NOT NULL DEFAULT 0,
  total_upload INTEGER NOT NULL DEFAULT 0,
  total_download INTEGER NOT NULL DEFAULT 0,
  source_ip TEXT NOT NULL DEFAULT '',
  last_seen_at TEXT NOT NULL DEFAULT '',
  last_polled_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate sqlite: %w", err)
	}
	if err := s.migrateClientProtocols(ctx); err != nil {
		return fmt.Errorf("migrate client protocol model: %w", err)
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
		`ALTER TABLE settings ADD COLUMN log_level TEXT NOT NULL DEFAULT 'warning'`,
		`ALTER TABLE clients ADD COLUMN vmess_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE clients ADD COLUMN vmess_revoked INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.ExecContext(ctx, column); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return fmt.Errorf("migrate settings: %w", err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, now); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(5, ?)`, now)
	return err
}

// migrateClientProtocols snapshots and rebuilds the legacy clients table so
// protocol-specific credentials can be absent instead of using fake UUIDs.
func (s *Store) migrateClientProtocols(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(clients)`)
	if err != nil {
		return err
	}
	hasProtocol := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == "protocol" {
			hasProtocol = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if hasProtocol {
		return s.markClientProtocolMigration(ctx)
	}
	if s.dbPath == "" {
		return errors.New("database path is required for the pre-migration snapshot")
	}
	backupPath := s.dbPath + ".pre-protocol-profiles-" + time.Now().UTC().Format("20060102T150405.000000000") + ".db"
	if err := s.createProtocolMigrationSnapshot(ctx, backupPath); err != nil {
		return fmt.Errorf("create pre-migration database snapshot %s: %w", backupPath, err)
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	const replacementSchema = `CREATE TABLE clients_protocol_migration (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  uuid TEXT UNIQUE,
  email TEXT NOT NULL UNIQUE,
  short_id TEXT UNIQUE,
  client_fingerprint TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  revoked INTEGER NOT NULL DEFAULT 0,
  protocol TEXT NOT NULL DEFAULT 'legacy_dual',
  hysteria_auth TEXT NOT NULL DEFAULT '',
  vless_enabled INTEGER NOT NULL DEFAULT 1,
  vless_revoked INTEGER NOT NULL DEFAULT 0,
  hysteria_enabled INTEGER NOT NULL DEFAULT 1,
  hysteria_revoked INTEGER NOT NULL DEFAULT 0,
  vmess_enabled INTEGER NOT NULL DEFAULT 0,
  vmess_revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)`
	if _, err := tx.ExecContext(ctx, replacementSchema); err != nil {
		return fmt.Errorf("create protocol-aware clients table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO clients_protocol_migration (
		id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
		hysteria_revoked, created_at, updated_at
	) SELECT id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		'legacy_dual', uuid, enabled, revoked, enabled, revoked, created_at, updated_at
		FROM clients`); err != nil {
		return fmt.Errorf("copy existing profiles as legacy dual-protocol profiles: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE clients`); err != nil {
		return fmt.Errorf("replace legacy clients table: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE clients_protocol_migration RENAME TO clients`); err != nil {
		return fmt.Errorf("activate protocol-aware clients table: %w", err)
	}
	if err := insertClientProtocolMigrationMarker(ctx, tx); err != nil {
		return err
	}
	violations, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	if violations.Next() {
		var table string
		var rowID sql.NullInt64
		var parent string
		var foreignKey int
		_ = violations.Scan(&table, &rowID, &parent, &foreignKey)
		_ = violations.Close()
		return fmt.Errorf("foreign key check failed after clients migration (table %s references %s)", table, parent)
	}
	if err := violations.Err(); err != nil {
		_ = violations.Close()
		return err
	}
	if err := violations.Close(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit protocol-aware clients table: %w", err)
	}
	return nil
}

func (s *Store) createProtocolMigrationSnapshot(ctx context.Context, backupPath string) error {
	tempDir, err := os.MkdirTemp(filepath.Dir(backupPath), ".protocol-migration-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return err
	}
	tempSnapshot := filepath.Join(tempDir, "state.db")
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, tempSnapshot); err != nil {
		return err
	}
	if err := os.Chmod(tempSnapshot, 0o600); err != nil {
		return err
	}
	return os.Rename(tempSnapshot, backupPath)
}

func (s *Store) markClientProtocolMigration(ctx context.Context) error {
	return insertClientProtocolMigrationMarker(ctx, s.db)
}

func insertClientProtocolMigrationMarker(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := exec.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(4, ?)`, now)
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

// ChangeAdminPassword updates the password hash and revokes every session in one transaction.
func (s *Store) ChangeAdminPassword(ctx context.Context, adminID, passwordHash string) error {
	if adminID == "" || passwordHash == "" {
		return errors.New("admin ID and password hash are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE admin_users SET password_hash=?, updated_at=? WHERE id=?`, passwordHash, time.Now().UTC().Format(time.RFC3339Nano), adminID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return errors.New("admin not found")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_user_id=?`, adminID); err != nil {
		return err
	}
	return tx.Commit()
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

func (s *Store) GetSettings(ctx context.Context) (domain.Settings, error) {
	var settings domain.Settings
	err := s.db.QueryRowContext(ctx, `SELECT public_host, public_port, xray_api_listen, internal_inbound_port, reality_target, reality_sni, reality_private_key_enc, reality_public_key, client_fingerprint, log_level FROM settings WHERE id=1`).Scan(&settings.PublicHost, &settings.PublicPort, &settings.XrayAPIListen, &settings.InternalInboundPort, &settings.RealityTarget, &settings.RealitySNI, &settings.RealityPrivateKeyEnc, &settings.RealityPublicKey, &settings.ClientFingerprint, &settings.LogLevel)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Settings{}, ErrSettingsNotInitialized
	}
	return settings, err
}

func (s *Store) UpdateSettings(ctx context.Context, settings domain.Settings) error {
	_, err := s.db.ExecContext(ctx, `UPDATE settings SET public_host=?, public_port=?, xray_api_listen=?, internal_inbound_port=?, reality_target=?, reality_sni=?, reality_private_key_enc=?, reality_public_key=?, client_fingerprint=?, log_level=?, updated_at=? WHERE id=1`, settings.PublicHost, settings.PublicPort, settings.XrayAPIListen, settings.InternalInboundPort, settings.RealityTarget, settings.RealitySNI, settings.RealityPrivateKeyEnc, settings.RealityPublicKey, settings.ClientFingerprint, settings.LogLevel, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// InitializeHysteriaSettings saves the one-time environment migration defaults.
// Once a row exists, later container environment changes cannot overwrite the
// values managed through the application.
func (s *Store) InitializeHysteriaSettings(ctx context.Context, settings domain.HysteriaSettings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hysteria_settings(id, enabled, host, tls_mode, tls_cert_ip, tls_server_name, certificate_id, udp_idle_timeout, masquerade_type, masquerade_string, updated_at) VALUES(1,?,?,?,?,?,?,?,?,?,?)`, boolInt(settings.Enabled), settings.Host, settings.TLSMode, settings.TLSCertIP, settings.TLSServerName, settings.CertificateID, settings.UDPIdleTimeout, settings.MasqueradeType, settings.MasqueradeString, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// GetHysteriaSettings returns the shared Hysteria 2 inbound settings.
func (s *Store) GetHysteriaSettings(ctx context.Context) (domain.HysteriaSettings, error) {
	var settings domain.HysteriaSettings
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT enabled, host, tls_mode, tls_cert_ip, tls_server_name, certificate_id, udp_idle_timeout, masquerade_type, masquerade_string FROM hysteria_settings WHERE id=1`).Scan(&enabled, &settings.Host, &settings.TLSMode, &settings.TLSCertIP, &settings.TLSServerName, &settings.CertificateID, &settings.UDPIdleTimeout, &settings.MasqueradeType, &settings.MasqueradeString)
	if err != nil {
		return settings, err
	}
	settings.Enabled = enabled != 0
	return settings, nil
}

// UpdateHysteriaSettings persists a validated Hysteria 2 configuration.
func (s *Store) UpdateHysteriaSettings(ctx context.Context, settings domain.HysteriaSettings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE hysteria_settings SET enabled=?, host=?, tls_mode=?, tls_cert_ip=?, tls_server_name=?, certificate_id=?, udp_idle_timeout=?, masquerade_type=?, masquerade_string=?, updated_at=? WHERE id=1`, boolInt(settings.Enabled), settings.Host, settings.TLSMode, settings.TLSCertIP, settings.TLSServerName, settings.CertificateID, settings.UDPIdleTimeout, settings.MasqueradeType, settings.MasqueradeString, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return errors.New("Hysteria 2 settings are not initialized")
	}
	return nil
}

// UpdateSettingsAndClientStates commits a node settings change and the
// corresponding client state transitions as one SQLite transaction. It is
// used by settings rotation so a failed apply cannot leave the database with
// only half of the intended revocation.
func (s *Store) UpdateSettingsAndClientStates(ctx context.Context, settings domain.Settings, states map[string]domain.ClientState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET public_host=?, public_port=?, xray_api_listen=?, internal_inbound_port=?, reality_target=?, reality_sni=?, reality_private_key_enc=?, reality_public_key=?, client_fingerprint=?, log_level=?, updated_at=? WHERE id=1`, settings.PublicHost, settings.PublicPort, settings.XrayAPIListen, settings.InternalInboundPort, settings.RealityTarget, settings.RealitySNI, settings.RealityPrivateKeyEnc, settings.RealityPublicKey, settings.ClientFingerprint, settings.LogLevel, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	for id, state := range states {
		result, err := tx.ExecContext(ctx, `UPDATE clients SET enabled=?, revoked=?, vless_enabled=?, vless_revoked=?, hysteria_enabled=?, hysteria_revoked=?, vmess_enabled=?, vmess_revoked=?, updated_at=? WHERE id=?`, boolInt(state.Enabled), boolInt(state.Revoked), boolInt(state.Enabled), boolInt(state.Revoked), boolInt(state.Enabled), boolInt(state.Revoked), boolInt(state.Enabled), boolInt(state.Revoked), time.Now().UTC().Format(time.RFC3339Nano), id)
		if err != nil {
			return err
		}
		if count, err := result.RowsAffected(); err != nil {
			return err
		} else if count != 1 {
			return fmt.Errorf("client %s not found", id)
		}
	}
	return tx.Commit()
}

// UpdateSettingsAndClientProtocolStates commits settings and selected inbound
// state transitions together so key rotation cannot affect Hysteria-only access.
func (s *Store) UpdateSettingsAndClientProtocolStates(ctx context.Context, settings domain.Settings, states map[string]map[domain.ClientProtocol]domain.ClientState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE settings SET public_host=?, public_port=?, xray_api_listen=?, internal_inbound_port=?, reality_target=?, reality_sni=?, reality_private_key_enc=?, reality_public_key=?, client_fingerprint=?, log_level=?, updated_at=? WHERE id=1`, settings.PublicHost, settings.PublicPort, settings.XrayAPIListen, settings.InternalInboundPort, settings.RealityTarget, settings.RealitySNI, settings.RealityPrivateKeyEnc, settings.RealityPublicKey, settings.ClientFingerprint, settings.LogLevel, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	for id, transitions := range states {
		var protocol string
		var vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked int
		if err := tx.QueryRowContext(ctx, `SELECT protocol, vless_enabled, vless_revoked, hysteria_enabled, hysteria_revoked, vmess_enabled, vmess_revoked FROM clients WHERE id=?`, id).Scan(&protocol, &vlessEnabled, &vlessRevoked, &hysteriaEnabled, &hysteriaRevoked, &vmessEnabled, &vmessRevoked); err != nil {
			return err
		}
		clientProtocol := domain.ClientProtocol(protocol)
		hasVLESS := clientProtocol == domain.ProtocolVLESS || clientProtocol == domain.ProtocolLegacyDual
		hasHysteria := clientProtocol == domain.ProtocolHysteria2 || clientProtocol == domain.ProtocolLegacyDual
		hasVMess := clientProtocol == domain.ProtocolVMess
		for access, state := range transitions {
			if state.Enabled && state.Revoked {
				return errors.New("revoked protocol access cannot be enabled")
			}
			switch access {
			case domain.ProtocolVLESS:
				if !hasVLESS {
					return errors.New("profile has no VLESS access")
				}
				vlessEnabled, vlessRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
			case domain.ProtocolHysteria2:
				if !hasHysteria {
					return errors.New("profile has no Hysteria 2 access")
				}
				hysteriaEnabled, hysteriaRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
			case domain.ProtocolVMess:
				if !hasVMess {
					return errors.New("profile has no VMess access")
				}
				vmessEnabled, vmessRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
			default:
				return errors.New("unsupported protocol access")
			}
		}
		enabled := (hasVLESS && vlessEnabled != 0 && vlessRevoked == 0) || (hasHysteria && hysteriaEnabled != 0 && hysteriaRevoked == 0) || (hasVMess && vmessEnabled != 0 && vmessRevoked == 0)
		revoked := (!hasVLESS || vlessRevoked != 0) && (!hasHysteria || hysteriaRevoked != 0) && (!hasVMess || vmessRevoked != 0)
		if _, err := tx.ExecContext(ctx, `UPDATE clients SET enabled=?, revoked=?, vless_enabled=?, vless_revoked=?, hysteria_enabled=?, hysteria_revoked=?, vmess_enabled=?, vmess_revoked=?, updated_at=? WHERE id=?`, boolInt(enabled), boolInt(revoked), vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked, time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CreateClient(ctx context.Context, client domain.Client, uuid, email, shortID string) error {
	if client.ID == "" {
		return errors.New("client id is required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if client.Protocol == domain.ProtocolHysteria2 {
		return errors.New("Hysteria 2 profiles must be created without VLESS credentials")
	}
	protocol, hysteriaAuth, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked := clientProtocolStorage(client, uuid)
	if _, err := tx.ExecContext(ctx, `INSERT INTO clients(id, name, uuid, email, short_id, client_fingerprint, enabled, revoked, protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled, hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, client.ID, client.Name, nullableCredential(uuid), email, nullableCredential(shortID), client.ClientFingerprint, boolInt(client.Enabled), boolInt(client.Revoked), protocol, hysteriaAuth, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked, now, now); err != nil {
		return err
	}
	if shortID != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO reality_short_ids(short_id, assigned_client_id, created_at) VALUES(?,?,?)`, shortID, client.ID, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateHysteriaClient stores a Hysteria-only profile without REALITY credentials or pool allocation.
func (s *Store) CreateHysteriaClient(ctx context.Context, client domain.Client) error {
	if client.ID == "" || client.Protocol != domain.ProtocolHysteria2 || client.HysteriaAuth == "" || client.Email == "" {
		return errors.New("valid Hysteria 2 profile credentials are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients(
		id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
		hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at
	) VALUES(?,?,NULL,?,NULL,'',?,?,?,?,0,0,?,?,0,0,?,?)`,
		client.ID, client.Name, client.Email, boolInt(client.Enabled), boolInt(client.Revoked),
		string(client.Protocol), client.HysteriaAuth, boolInt(client.HysteriaEnabled),
		boolInt(client.HysteriaRevoked), now, now)
	return err
}

// CreateVMessClient stores a VMess-only profile without REALITY short-ID allocation.
func (s *Store) CreateVMessClient(ctx context.Context, client domain.Client) error {
	if client.ID == "" || client.Protocol != domain.ProtocolVMess || client.UUID == "" || client.Email == "" {
		return errors.New("valid VMess profile credentials are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO clients(
		id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
		protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled,
		hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at
	) VALUES(?,?,?,?,NULL,'',?,?,?,'',0,0,0,0,?,?,?,?)`,
		client.ID, client.Name, client.UUID, client.Email, boolInt(client.Enabled), boolInt(client.Revoked),
		string(client.Protocol), boolInt(client.Enabled), boolInt(client.Revoked), now, now)
	return err
}

func nullableCredential(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func clientProtocolStorage(client domain.Client, uuid string) (string, string, int, int, int, int, int, int) {
	protocol := client.Protocol
	if protocol == "" {
		protocol = domain.ProtocolLegacyDual
	}
	hysteriaAuth := client.HysteriaAuth
	if protocol == domain.ProtocolLegacyDual && hysteriaAuth == "" {
		hysteriaAuth = uuid
	}
	vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked := false, false, false, false, false, false
	switch protocol {
	case domain.ProtocolLegacyDual:
		vlessEnabled, vlessRevoked = client.Enabled, client.Revoked
		hysteriaEnabled, hysteriaRevoked = client.Enabled, client.Revoked
	case domain.ProtocolVLESS:
		vlessEnabled, vlessRevoked = client.VLESSEnabled, client.VLESSRevoked
		if !vlessEnabled && !vlessRevoked && client.Enabled && !client.Revoked {
			vlessEnabled = true
		}
	case domain.ProtocolHysteria2:
		hysteriaEnabled, hysteriaRevoked = client.HysteriaEnabled, client.HysteriaRevoked
		if !hysteriaEnabled && !hysteriaRevoked && client.Enabled && !client.Revoked {
			hysteriaEnabled = true
		}
	case domain.ProtocolVMess:
		vmessEnabled, vmessRevoked = client.Enabled, client.Revoked
		if !vmessEnabled && !vmessRevoked && client.Enabled && !client.Revoked {
			vmessEnabled = true
		}
	}
	return string(protocol), hysteriaAuth, boolInt(vlessEnabled), boolInt(vlessRevoked), boolInt(hysteriaEnabled), boolInt(hysteriaRevoked), boolInt(vmessEnabled), boolInt(vmessRevoked)
}

// ListReservedShortIDs returns the durable, unassigned REALITY IDs in issuance order.
func (s *Store) ListReservedShortIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT short_id FROM reality_short_ids WHERE assigned_client_id IS NULL ORDER BY created_at, short_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var shortID string
		if err := rows.Scan(&shortID); err != nil {
			return nil, err
		}
		result = append(result, shortID)
	}
	return result, rows.Err()
}

// EnsureReservedShortIDs adds stock IDs until count free IDs are available. Existing assignments are never changed.
func (s *Store) EnsureReservedShortIDs(ctx context.Context, count int, generate func() (string, error)) error {
	if count < 1 || generate == nil {
		return errors.New("short ID pool size and generator are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureShortIDHistory(ctx, tx); err != nil {
		return err
	}
	if err := replenishShortIDPool(ctx, tx, count, generate); err != nil {
		return err
	}
	return tx.Commit()
}

// SeedReservedShortIDs creates the initial reserve for an installation or a
// legacy database. After initialization, the reserve is allowed to drain;
// an exhausted pool is replenished by CreateClientWithReservedShortID.
func (s *Store) SeedReservedShortIDs(ctx context.Context, count int, generate func() (string, error)) error {
	if count < 1 || generate == nil {
		return errors.New("short ID pool size and generator are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := ensureShortIDHistory(ctx, tx); err != nil {
		return err
	}
	var initialized int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=3`).Scan(&initialized); err != nil {
		return err
	}
	if initialized == 0 {
		if err := replenishShortIDPool(ctx, tx, count, generate); err != nil {
			return err
		}
		if err := markShortIDPoolInitialized(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateClientWithReservedShortID assigns a reserved ID and inserts its client atomically.
// When the pool was exhausted, a new assigned ID plus a fresh reserve is generated.
func (s *Store) CreateClientWithReservedShortID(ctx context.Context, client domain.Client, uuid, email string, reserveSize int, generate func() (string, error)) (string, bool, error) {
	if client.ID == "" || reserveSize < 1 || generate == nil {
		return "", false, errors.New("client, reserve size and short ID generator are required")
	}
	if client.Protocol != "" && client.Protocol != domain.ProtocolVLESS && client.Protocol != domain.ProtocolLegacyDual {
		return "", false, errors.New("only VLESS profiles use REALITY short IDs")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()
	if err := ensureShortIDHistory(ctx, tx); err != nil {
		return "", false, err
	}
	var total, available int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN assigned_client_id IS NULL THEN 1 ELSE 0 END), 0) FROM reality_short_ids`).Scan(&total, &available); err != nil {
		return "", false, err
	}
	if total == 0 {
		if err := replenishShortIDPool(ctx, tx, reserveSize, generate); err != nil {
			return "", false, err
		}
		available = reserveSize
	}
	shortID := ""
	exhausted := available == 0
	if exhausted {
		shortID, err = generateUnusedShortID(ctx, tx, generate)
		if err != nil {
			return "", false, err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO reality_short_ids(short_id, assigned_client_id, created_at) VALUES(?,?,?)`, shortID, client.ID, now); err != nil {
			return "", false, err
		}
		if err := replenishShortIDPool(ctx, tx, reserveSize, generate); err != nil {
			return "", false, err
		}
	} else {
		if err := tx.QueryRowContext(ctx, `SELECT short_id FROM reality_short_ids WHERE assigned_client_id IS NULL ORDER BY created_at, short_id LIMIT 1`).Scan(&shortID); err != nil {
			return "", false, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE reality_short_ids SET assigned_client_id=? WHERE short_id=? AND assigned_client_id IS NULL`, client.ID, shortID)
		if err != nil {
			return "", false, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			if err != nil {
				return "", false, err
			}
			return "", false, errors.New("reserved REALITY short ID was claimed concurrently")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	protocol, hysteriaAuth, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked := clientProtocolStorage(client, uuid)
	if _, err := tx.ExecContext(ctx, `INSERT INTO clients(id, name, uuid, email, short_id, client_fingerprint, enabled, revoked, protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled, hysteria_revoked, vmess_enabled, vmess_revoked, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, client.ID, client.Name, nullableCredential(uuid), email, nullableCredential(shortID), client.ClientFingerprint, boolInt(client.Enabled), boolInt(client.Revoked), protocol, hysteriaAuth, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked, now, now); err != nil {
		return "", false, err
	}
	if err := markShortIDPoolInitialized(ctx, tx); err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return shortID, exhausted, nil
}

func ensureShortIDHistory(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO reality_short_ids(short_id, assigned_client_id, created_at) SELECT short_id, id, created_at FROM clients WHERE short_id IS NOT NULL AND short_id != ''`)
	return err
}

func markShortIDPoolInitialized(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(3, ?)`, now)
	return err
}

func replenishShortIDPool(ctx context.Context, tx *sql.Tx, target int, generate func() (string, error)) error {
	var available int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM reality_short_ids WHERE assigned_client_id IS NULL`).Scan(&available); err != nil {
		return err
	}
	for available < target {
		shortID, err := generateUnusedShortID(ctx, tx, generate)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO reality_short_ids(short_id, assigned_client_id, created_at) VALUES(?,NULL,?)`, shortID, now); err != nil {
			return err
		}
		available++
	}
	return nil
}

func generateUnusedShortID(ctx context.Context, tx *sql.Tx, generate func() (string, error)) (string, error) {
	for range 32 {
		shortID, err := generate()
		if err != nil {
			return "", err
		}
		if shortID == "" || shortID == "0000000000000000" {
			continue
		}
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM reality_short_ids WHERE short_id=?`, shortID).Scan(&exists); err != nil {
			return "", err
		}
		if exists == 0 {
			return shortID, nil
		}
	}
	return "", errors.New("could not generate a unique REALITY short ID")
}

func (s *Store) ListClients(ctx context.Context) ([]domain.Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientSelectColumns+` FROM clients ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []domain.Client
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *Store) GetClient(ctx context.Context, id string) (domain.Client, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+clientSelectColumns+` FROM clients WHERE id=?`, id)
	return scanClient(row)
}

func (s *Store) SetClientState(ctx context.Context, id string, enabled, revoked bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET enabled=?, revoked=?, vless_enabled=?, vless_revoked=?, hysteria_enabled=?, hysteria_revoked=?, vmess_enabled=?, vmess_revoked=?, updated_at=? WHERE id=?`, boolInt(enabled), boolInt(revoked), boolInt(enabled), boolInt(revoked), boolInt(enabled), boolInt(revoked), boolInt(enabled), boolInt(revoked), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return errors.New("client not found")
	}
	return err
}

// SetClientProtocolState changes the lifecycle of one inbound access, keeping the
// other protocol active for legacy dual-protocol profiles.
func (s *Store) SetClientProtocolState(ctx context.Context, id string, protocol domain.ClientProtocol, state domain.ClientState) error {
	return s.SetClientProtocolStates(ctx, id, map[domain.ClientProtocol]domain.ClientState{protocol: state})
}

// SetClientProtocolStates atomically updates selected accesses on one profile.
func (s *Store) SetClientProtocolStates(ctx context.Context, id string, states map[domain.ClientProtocol]domain.ClientState) error {
	if len(states) == 0 {
		return errors.New("at least one protocol access state is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var client domain.Client
	var uuid, shortID sql.NullString
	var email, storedProtocol, hysteriaAuth, created, updated string
	var enabled, revoked, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked int
	if err := tx.QueryRowContext(ctx, `SELECT `+clientSelectColumns+` FROM clients WHERE id=?`, id).Scan(
		&client.ID, &client.Name, &uuid, &email, &shortID, &client.ClientFingerprint, &enabled, &revoked,
		&storedProtocol, &hysteriaAuth, &vlessEnabled, &vlessRevoked, &hysteriaEnabled, &hysteriaRevoked, &vmessEnabled, &vmessRevoked, &created, &updated,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("client not found")
		}
		return err
	}
	client.Protocol = domain.ClientProtocol(storedProtocol)
	if client.Protocol == "" {
		client.Protocol = domain.ProtocolLegacyDual
	}
	for protocol, state := range states {
		if state.Enabled && state.Revoked {
			return errors.New("revoked protocol access cannot be enabled")
		}
		switch protocol {
		case domain.ProtocolVLESS:
			if !client.HasVLESS() {
				return errors.New("profile has no VLESS access")
			}
			vlessEnabled, vlessRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
		case domain.ProtocolHysteria2:
			if !client.HasHysteria2() {
				return errors.New("profile has no Hysteria 2 access")
			}
			hysteriaEnabled, hysteriaRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
		case domain.ProtocolVMess:
			if !client.HasVMess() {
				return errors.New("profile has no VMess access")
			}
			vmessEnabled, vmessRevoked = boolInt(state.Enabled), boolInt(state.Revoked)
		default:
			return errors.New("unsupported protocol access")
		}
	}
	anyEnabled := (client.HasVLESS() && vlessEnabled != 0 && vlessRevoked == 0) || (client.HasHysteria2() && hysteriaEnabled != 0 && hysteriaRevoked == 0) || (client.HasVMess() && vmessEnabled != 0 && vmessRevoked == 0)
	allRevoked := (!client.HasVLESS() || vlessRevoked != 0) && (!client.HasHysteria2() || hysteriaRevoked != 0) && (!client.HasVMess() || vmessRevoked != 0)
	result, err := tx.ExecContext(ctx, `UPDATE clients SET enabled=?, revoked=?, vless_enabled=?, vless_revoked=?, hysteria_enabled=?, hysteria_revoked=?, vmess_enabled=?, vmess_revoked=?, updated_at=? WHERE id=?`, boolInt(anyEnabled), boolInt(allRevoked), vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count != 1 {
		return errors.New("client not found")
	}
	return tx.Commit()
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

// ListAWGTrafficSnapshots loads durable counters for AmneziaWG peers.
func (s *Store) ListAWGTrafficSnapshots(ctx context.Context) (map[string]AWGTrafficSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT peer_name, raw_upload, raw_download, total_upload, total_download, source_ip, last_seen_at, last_polled_at FROM awg_traffic_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]AWGTrafficSnapshot)
	for rows.Next() {
		var snapshot AWGTrafficSnapshot
		var lastSeen, lastPolled string
		if err := rows.Scan(&snapshot.PeerName, &snapshot.RawUpload, &snapshot.RawDownload, &snapshot.TotalUpload, &snapshot.TotalDownload, &snapshot.SourceIP, &lastSeen, &lastPolled); err != nil {
			return nil, err
		}
		if lastSeen != "" {
			snapshot.LastSeenAt, _ = time.Parse(time.RFC3339Nano, lastSeen)
		}
		snapshot.LastPolledAt, _ = time.Parse(time.RFC3339Nano, lastPolled)
		result[snapshot.PeerName] = snapshot
	}
	return result, rows.Err()
}

// UpsertAWGTrafficSnapshot saves current counters and cumulative totals.
func (s *Store) UpsertAWGTrafficSnapshot(ctx context.Context, snapshot AWGTrafficSnapshot) error {
	if snapshot.PeerName == "" {
		return errors.New("AWG peer name is required")
	}
	lastSeen := ""
	if !snapshot.LastSeenAt.IsZero() {
		lastSeen = snapshot.LastSeenAt.UTC().Format(time.RFC3339Nano)
	}
	lastPolled := snapshot.LastPolledAt
	if lastPolled.IsZero() {
		lastPolled = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO awg_traffic_snapshots(peer_name, raw_upload, raw_download, total_upload, total_download, source_ip, last_seen_at, last_polled_at) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(peer_name) DO UPDATE SET raw_upload=excluded.raw_upload, raw_download=excluded.raw_download, total_upload=excluded.total_upload, total_download=excluded.total_download, source_ip=excluded.source_ip, last_seen_at=excluded.last_seen_at, last_polled_at=excluded.last_polled_at`, snapshot.PeerName, snapshot.RawUpload, snapshot.RawDownload, snapshot.TotalUpload, snapshot.TotalDownload, snapshot.SourceIP, lastSeen, lastPolled.UTC().Format(time.RFC3339Nano))
	return err
}

// DeleteAWGTrafficSnapshot removes the checkpoint when an AWG peer is revoked.
func (s *Store) DeleteAWGTrafficSnapshot(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM awg_traffic_snapshots WHERE peer_name=?`, name)
	return err
}

func (s *Store) CreateApplyOperation(ctx context.Context, operation ApplyOperation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO apply_operations(id, revision, state, error, created_at, updated_at) VALUES(?,?,?,?,?,?)`, operation.ID, operation.Revision, operation.State, operation.Error, operation.CreatedAt.Format(time.RFC3339Nano), operation.UpdatedAt.Format(time.RFC3339Nano))
	return err
}

// CreateApplyOperationWithNextRevision allocates a durable monotonically
// increasing revision and records the operation atomically. The sequence row
// is deliberately preserved by RestoreFrom so restoring an older backup does
// not lower the revision high-water mark held by the embedded Xray runtime.
func (s *Store) CreateApplyOperationWithNextRevision(ctx context.Context, operation ApplyOperation) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE apply_revision_sequence
SET revision = MAX(revision, (SELECT COALESCE(MAX(revision), 0) FROM apply_operations)) + 1 WHERE id=1`); err != nil {
		return 0, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM apply_revision_sequence WHERE id=1`).Scan(&revision); err != nil {
		return 0, fmt.Errorf("read apply revision sequence: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO apply_operations(id, revision, state, error, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
		operation.ID, revision, operation.State, operation.Error, operation.CreatedAt.Format(time.RFC3339Nano), operation.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revision, nil
}

func (s *Store) UpdateApplyOperation(ctx context.Context, id, state, operationError string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE apply_operations SET state=?, error=?, updated_at=? WHERE id=?`, state, operationError, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

// GetApplyOperation returns a persisted runtime configuration operation and its
// monotonic state revision for downstream correlation.
func (s *Store) GetApplyOperation(ctx context.Context, id string) (ApplyOperation, error) {
	var operation ApplyOperation
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT id, revision, state, error, created_at, updated_at FROM apply_operations WHERE id=?`, id).Scan(
		&operation.ID, &operation.Revision, &operation.State, &operation.Error, &createdAt, &updatedAt,
	)
	if err != nil {
		return ApplyOperation{}, err
	}
	operation.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ApplyOperation{}, fmt.Errorf("parse apply operation creation time: %w", err)
	}
	operation.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return ApplyOperation{}, fmt.Errorf("parse apply operation update time: %w", err)
	}
	return operation, nil
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

const clientSelectColumns = `id, name, uuid, email, short_id, client_fingerprint, enabled, revoked,
	protocol, hysteria_auth, vless_enabled, vless_revoked, hysteria_enabled, hysteria_revoked, vmess_enabled, vmess_revoked,
	created_at, updated_at`

func scanClient(row scanner) (domain.Client, error) {
	var client domain.Client
	var uuid, shortID sql.NullString
	var email, protocol, hysteriaAuth string
	var enabled, revoked, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked, vmessEnabled, vmessRevoked int
	var created, updated string
	err := row.Scan(&client.ID, &client.Name, &uuid, &email, &shortID, &client.ClientFingerprint,
		&enabled, &revoked, &protocol, &hysteriaAuth, &vlessEnabled, &vlessRevoked,
		&hysteriaEnabled, &hysteriaRevoked, &vmessEnabled, &vmessRevoked, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Client{}, errors.New("client not found")
		}
		return domain.Client{}, err
	}
	client.UUID, client.Email, client.ShortID = uuid.String, email, shortID.String
	client.Protocol = domain.ClientProtocol(protocol)
	if client.Protocol == "" {
		client.Protocol = domain.ProtocolLegacyDual
	}
	client.HysteriaAuth = hysteriaAuth
	if client.HysteriaAuth == "" && client.Protocol == domain.ProtocolLegacyDual {
		client.HysteriaAuth = client.UUID
	}
	client.Enabled, client.Revoked = enabled != 0, revoked != 0
	client.VLESSEnabled, client.VLESSRevoked = vlessEnabled != 0, vlessRevoked != 0
	client.HysteriaEnabled, client.HysteriaRevoked = hysteriaEnabled != 0, hysteriaRevoked != 0
	client.VMessEnabled, client.VMessRevoked = vmessEnabled != 0, vmessRevoked != 0
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
