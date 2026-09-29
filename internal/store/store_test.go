package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func openTestStore(t *testing.T, name string) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, ctx
}

func initTestAdmin(t *testing.T, db *Store, ctx context.Context) Admin {
	t.Helper()
	admin, err := db.Initialize(ctx, " Admin ", "password-hash", "vpn.example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	return admin
}

func createTestClient(t *testing.T, db *Store, ctx context.Context, id string) domain.Client {
	t.Helper()
	client := domain.Client{ID: id, Name: "phone-" + id, ClientFingerprint: "safari", Enabled: true}
	if err := db.CreateClient(ctx, client, "uuid-"+id, id+"@example.test", "short-"+id); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestMigrationSetupAndSettingsLifecycle(t *testing.T) {
	db, ctx := openTestStore(t, "state.db")
	if err := db.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.migrate(ctx); err != nil {
		t.Fatalf("running migrations twice: %v", err)
	}
	status, err := db.SetupStatus(ctx)
	if err != nil || status.Initialized {
		t.Fatalf("initial setup status = %+v, %v", status, err)
	}
	if _, err := db.GetSettings(ctx); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("GetSettings before setup error = %v", err)
	}
	for _, args := range [][2]string{{"", "hash"}, {"admin", ""}} {
		if _, err := db.Initialize(ctx, args[0], args[1], "vpn.example.com", 443); err == nil {
			t.Errorf("Initialize(%q, %q) accepted empty required field", args[0], args[1])
		}
	}
	admin := initTestAdmin(t, db, ctx)
	if admin.Username != "admin" || admin.ID == "" {
		t.Fatalf("admin was not canonicalized: %+v", admin)
	}
	status, err = db.SetupStatus(ctx)
	if err != nil || !status.Initialized {
		t.Fatalf("initialized setup status = %+v, %v", status, err)
	}
	if _, err := db.Initialize(ctx, "second", "hash", "other.example.com", 443); err == nil {
		t.Fatal("second initialization unexpectedly succeeded")
	}
	found, err := db.FindAdmin(ctx, " ADMIN ")
	if err != nil || found.ID != admin.ID || found.Username != "admin" {
		t.Fatalf("case-insensitive admin lookup = %+v, %v", found, err)
	}
	if _, err := db.FindAdmin(ctx, "missing"); err == nil {
		t.Fatal("missing admin lookup unexpectedly succeeded")
	}
	settings, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.PublicHost != "vpn.example.com" || settings.PublicPort != 443 || settings.XrayAPIListen != "127.0.0.1:10085" || settings.InternalInboundPort != 8443 {
		t.Fatalf("unexpected initial settings: %+v", settings)
	}
	if settings.LogLevel != "warning" {
		t.Fatalf("initial Xray log level = %q, want warning", settings.LogLevel)
	}
	settings.PublicHost = "new.example.com"
	settings.RealityTarget = "target.example.com:443"
	settings.RealitySNI = "target.example.com"
	settings.RealityPrivateKeyEnc = "encrypted-private-key"
	settings.RealityPublicKey = "public-key"
	settings.ClientFingerprint = "safari"
	settings.LogLevel = "debug"
	if err := db.UpdateSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetSettings(ctx)
	if err != nil || got != settings {
		t.Fatalf("settings round trip = %+v, %v; want %+v", got, err, settings)
	}
}

func TestClientProtocolMigrationPreservesLegacyCredentialsTrafficAndRestoresOldBackup(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	databasePath := filepath.Join(root, "legacy.db")
	initial, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", "file:"+databasePath+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatal(err)
	}
	legacy.SetMaxOpenConns(1)
	legacyDDL := []string{
		`PRAGMA foreign_keys=OFF`,
		`DROP TABLE traffic_snapshots`,
		`DROP TABLE clients`,
		`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, short_id TEXT NOT NULL UNIQUE, client_fingerprint TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE traffic_snapshots (client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE, raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0, total_upload INTEGER NOT NULL DEFAULT 0, total_download INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL DEFAULT '', last_polled_at TEXT NOT NULL)`,
		`INSERT INTO clients VALUES('legacy-phone','phone','preserved-uuid','legacy-email@xray-easy','fedcba9876543210','safari',1,0,'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`,
		`INSERT INTO traffic_snapshots VALUES('legacy-phone',100,200,1000,2000,'2026-01-02T00:00:00Z','2026-01-02T00:00:00Z')`,
		`DELETE FROM schema_migrations WHERE version=4`,
	}
	for _, statement := range legacyDDL {
		if _, err := legacy.Exec(statement); err != nil {
			_ = legacy.Close()
			t.Fatalf("prepare legacy database: %v (%s)", err, statement)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	client, err := db.GetClient(ctx, "legacy-phone")
	if err != nil {
		t.Fatal(err)
	}
	if client.Protocol != domain.ProtocolLegacyDual || client.UUID != "preserved-uuid" || client.HysteriaAuth != "preserved-uuid" || client.ShortID != "fedcba9876543210" || !client.VLESSCanConnect() || !client.Hysteria2CanConnect() {
		t.Fatalf("migrated legacy profile = %+v", client)
	}
	snapshots, err := db.ListTrafficSnapshots(ctx)
	if err != nil || snapshots[client.ID].TotalUpload != 1000 || snapshots[client.ID].TotalDownload != 2000 {
		t.Fatalf("migrated traffic totals = %+v, %v", snapshots[client.ID], err)
	}
	foreignKeys, err := db.db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if foreignKeys.Next() {
		var table, parent string
		var rowID sql.NullInt64
		var constraint int
		_ = foreignKeys.Scan(&table, &rowID, &parent, &constraint)
		_ = foreignKeys.Close()
		t.Fatalf("migration broke foreign key table %s -> %s", table, parent)
	}
	_ = foreignKeys.Close()
	snapshotPaths, err := filepath.Glob(databasePath + ".pre-protocol-profiles-*.db")
	if err != nil || len(snapshotPaths) != 1 {
		t.Fatalf("pre-migration snapshot paths = %v, %v", snapshotPaths, err)
	}
	if err := db.RestoreFrom(snapshotPaths[0]); err != nil {
		t.Fatalf("restore pre-migration backup: %v", err)
	}
	client, err = db.GetClient(ctx, "legacy-phone")
	if err != nil || client.Protocol != domain.ProtocolLegacyDual || client.UUID != "preserved-uuid" || client.HysteriaAuth != "preserved-uuid" || client.ShortID != "fedcba9876543210" {
		t.Fatalf("restored legacy profile = %+v, %v", client, err)
	}
	snapshots, err = db.ListTrafficSnapshots(ctx)
	if err != nil || snapshots[client.ID].TotalUpload != 1000 || snapshots[client.ID].TotalDownload != 2000 {
		t.Fatalf("restored legacy traffic totals = %+v, %v", snapshots[client.ID], err)
	}
}

func TestHysteriaOnlyClientStoresNoRealityCredentialsAndUsesIndependentState(t *testing.T) {
	db, ctx := openTestStore(t, "hysteria-only.db")
	client, err := domain.NewProtocolClient("hysteria-phone", "phone", domain.ProtocolHysteria2, "", "unique-hysteria-secret")
	if err != nil {
		t.Fatal(err)
	}
	client.Email = "hysteria-phone-hysteria2@xray-easy"
	if err := db.CreateHysteriaClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetClient(ctx, client.ID)
	if err != nil || got.Protocol != domain.ProtocolHysteria2 || got.UUID != "" || got.ShortID != "" || got.HysteriaAuth != client.HysteriaAuth || got.HasVLESS() || !got.Hysteria2CanConnect() {
		t.Fatalf("Hysteria-only client = %+v, %v", got, err)
	}
	var uuid, shortID sql.NullString
	if err := db.db.QueryRowContext(ctx, `SELECT uuid, short_id FROM clients WHERE id=?`, client.ID).Scan(&uuid, &shortID); err != nil {
		t.Fatal(err)
	}
	if uuid.Valid || shortID.Valid {
		t.Fatalf("Hysteria-only profile persisted fake REALITY credentials: uuid=%+v short_id=%+v", uuid, shortID)
	}
	var realityReservations int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reality_short_ids WHERE assigned_client_id=?`, client.ID).Scan(&realityReservations); err != nil || realityReservations != 0 {
		t.Fatalf("Hysteria-only profile consumed a REALITY short ID: count=%d, err=%v", realityReservations, err)
	}
	if err := db.SetClientProtocolState(ctx, "legacy-phone", domain.ProtocolVLESS, domain.ClientState{Revoked: true}); err == nil {
		t.Fatal("state change for missing client unexpectedly succeeded")
	}
	legacy := createTestClient(t, db, ctx, "dual")
	if err := db.SetClientProtocolState(ctx, legacy.ID, domain.ProtocolVLESS, domain.ClientState{Revoked: true}); err != nil {
		t.Fatal(err)
	}
	legacy, err = db.GetClient(ctx, legacy.ID)
	if err != nil || legacy.VLESSCanConnect() || !legacy.Hysteria2CanConnect() || !legacy.VLESSRevoked {
		t.Fatalf("independent legacy state = %+v, %v", legacy, err)
	}
	if err := db.SetClientProtocolState(ctx, got.ID, domain.ProtocolVLESS, domain.ClientState{}); err == nil {
		t.Fatal("Hysteria-only profile accepted VLESS state mutation")
	}
}

func TestHysteriaSettingsOneTimeEnvironmentMigration(t *testing.T) {
	db, ctx := openTestStore(t, "hysteria-settings.db")
	initial := domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.InitializeHysteriaSettings(ctx, initial); err != nil {
		t.Fatal(err)
	}
	updated := initial
	updated.Enabled = false
	updated.Host = "vpn.example.com"
	updated.UDPIdleTimeout = 120
	if err := db.UpdateHysteriaSettings(ctx, updated); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeHysteriaSettings(ctx, initial); err != nil {
		t.Fatalf("reapplying environment defaults: %v", err)
	}
	got, err := db.GetHysteriaSettings(ctx)
	if err != nil || got != updated {
		t.Fatalf("persisted settings = %+v, %v; want %+v", got, err, updated)
	}
}

func TestRestoreDatabaseWithoutHysteriaSettingsDefaultsTransportOff(t *testing.T) {
	db, ctx := openTestStore(t, "current.db")
	defaults := domain.HysteriaSettings{Enabled: true, TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.InitializeHysteriaSettings(ctx, defaults); err != nil {
		t.Fatal(err)
	}
	legacyBackup := filepath.Join(t.TempDir(), "legacy.db")
	if err := db.BackupTo(legacyBackup); err != nil {
		t.Fatal(err)
	}
	legacy, err := sql.Open("sqlite", "file:"+legacyBackup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`DROP TABLE hysteria_settings`); err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.RestoreFrom(legacyBackup); err != nil {
		t.Fatalf("restore legacy database: %v", err)
	}
	got, err := db.GetHysteriaSettings(ctx)
	if err != nil || got.Enabled || got.TLSMode != domain.HysteriaTLSLegacy || got.UDPIdleTimeout != 60 {
		t.Fatalf("restored Hysteria defaults = %+v, %v", got, err)
	}
}

func TestReservedRealityShortIDPoolRefillsAndNeverReusesAssignments(t *testing.T) {
	db, ctx := openTestStore(t, "short-id-pool.db")
	createTestClient(t, db, ctx, "legacy")
	counter := 0
	generate := func() (string, error) {
		counter++
		return fmt.Sprintf("%016x", counter), nil
	}
	if err := db.EnsureReservedShortIDs(ctx, 5, generate); err != nil {
		t.Fatalf("seed migrated reserve: %v", err)
	}
	reserved, err := db.ListReservedShortIDs(ctx)
	if err != nil || len(reserved) != 5 {
		t.Fatalf("initial short-ID reserve = %v, %v", reserved, err)
	}
	for index := 1; index <= 5; index++ {
		clientID := fmt.Sprintf("new-%d", index)
		shortID, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: clientID, Name: clientID, Enabled: true}, "uuid-"+clientID, clientID+"@example.test", 5, generate)
		if err != nil || exhausted {
			t.Fatalf("claim reserved ID %d = %q, exhausted=%v, err=%v", index, shortID, exhausted, err)
		}
	}
	reserved, err = db.ListReservedShortIDs(ctx)
	if err != nil || len(reserved) != 0 {
		t.Fatalf("reserve after five claims = %v, %v", reserved, err)
	}
	shortID, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "overflow", Name: "overflow", Enabled: true}, "uuid-overflow", "overflow@example.test", 5, generate)
	if err != nil || !exhausted || shortID != "0000000000000006" {
		t.Fatalf("overflow allocation = %q, exhausted=%v, err=%v", shortID, exhausted, err)
	}
	reserved, err = db.ListReservedShortIDs(ctx)
	if err != nil || len(reserved) != 5 {
		t.Fatalf("refilled short-ID reserve = %v, %v", reserved, err)
	}
	if err := db.DeleteClient(ctx, "legacy"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureReservedShortIDs(ctx, 5, generate); err != nil {
		t.Fatalf("ensure reserve after deletion: %v", err)
	}
	clientID := "after-delete"
	got, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: clientID, Name: clientID, Enabled: true}, "uuid-"+clientID, clientID+"@example.test", 5, generate)
	if err != nil || got == "short-legacy" {
		t.Fatalf("deleted profile short ID was reused: %q, %v", got, err)
	}
}

func TestLegacyBackupWithoutLogLevelRestoresWithWarningDefault(t *testing.T) {
	ctx := context.Background()
	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := Open(ctx, legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	initTestAdmin(t, legacy, ctx)
	if _, err := legacy.db.Exec(`ALTER TABLE settings DROP COLUMN log_level`); err != nil {
		t.Fatalf("create pre-log-level database: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "legacy-backup.db")
	if err := legacy.BackupTo(backupPath); err != nil {
		t.Fatal(err)
	}
	read, err := ReadSettingsFromDatabase(backupPath)
	if err != nil || read.LogLevel != "warning" {
		t.Fatalf("read legacy settings log level = %q, %v; want warning", read.LogLevel, err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(ctx, legacyPath)
	if err != nil {
		t.Fatalf("open pre-log-level database for migration: %v", err)
	}
	upgradedSettings, err := upgraded.GetSettings(ctx)
	if err != nil || upgradedSettings.LogLevel != "warning" {
		_ = upgraded.Close()
		t.Fatalf("migrated legacy settings log level = %q, %v; want warning", upgradedSettings.LogLevel, err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if err := destination.RestoreFrom(backupPath); err != nil {
		t.Fatalf("restore legacy backup: %v", err)
	}
	settings, err := destination.GetSettings(ctx)
	if err != nil || settings.LogLevel != "warning" {
		t.Fatalf("restored legacy settings log level = %q, %v; want warning", settings.LogLevel, err)
	}
}

func TestOpenReturnsMigrationErrorForCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if db, err := Open(ctx, filepath.Join(t.TempDir(), "canceled.db")); err == nil {
		_ = db.Close()
		t.Fatal("Open succeeded with a canceled migration context")
	}
}

func TestSessionCreationExpiryAndDeletion(t *testing.T) {
	db, ctx := openTestStore(t, "sessions.db")
	admin := initTestAdmin(t, db, ctx)
	token, err := db.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("session token has length %d, want 64", len(token))
	}
	var stored []byte
	if err := db.db.QueryRow(`SELECT token_hash FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == token {
		t.Fatal("session token was stored in plaintext")
	}
	found, err := db.SessionAdmin(ctx, token)
	if err != nil || found.ID != admin.ID {
		t.Fatalf("session lookup = %+v, %v", found, err)
	}
	var lastSeen string
	if err := db.db.QueryRow(`SELECT last_seen_at FROM sessions`).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, lastSeen); err != nil || parsed.IsZero() {
		t.Fatalf("session last_seen_at = %q, %v", lastSeen, err)
	}
	if err := db.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionAdmin(ctx, token); err == nil {
		t.Fatal("deleted session remained valid")
	}
	expired, err := db.CreateSession(ctx, admin.ID, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SessionAdmin(ctx, expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired session error = %v", err)
	}
	var remaining int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired session cleanup count = %d, %v", remaining, err)
	}
	first, err := db.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteAllSessions(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{first, second} {
		if _, err := db.SessionAdmin(ctx, token); err == nil {
			t.Errorf("logout-all left session %q valid", token)
		}
	}
}

func TestTOTPAndRecoveryCodeLifecycle(t *testing.T) {
	db, ctx := openTestStore(t, "totp.db")
	admin := initTestAdmin(t, db, ctx)
	if err := db.SetTOTP(ctx, admin.ID, "encrypted-secret", []string{"hash-1", "hash-2"}); err != nil {
		t.Fatal(err)
	}
	first, err := db.FirstAdmin(ctx)
	if err != nil || !first.TOTPEnabled || first.TOTPSecretEnc != "encrypted-secret" {
		t.Fatalf("FirstAdmin after TOTP setup = %+v, %v", first, err)
	}
	found, err := db.FindAdmin(ctx, "admin")
	if err != nil || !found.TOTPEnabled {
		t.Fatalf("FindAdmin TOTP status = %+v, %v", found, err)
	}
	if count, err := db.RecoveryCodeCount(ctx, admin.ID); err != nil || count != 2 {
		t.Fatalf("recovery count = %d, %v", count, err)
	}
	consumed, err := db.ConsumeRecoveryCode(ctx, admin.ID, "hash-1")
	if err != nil || !consumed {
		t.Fatalf("first recovery-code consume = %v, %v", consumed, err)
	}
	consumed, err = db.ConsumeRecoveryCode(ctx, admin.ID, "hash-1")
	if err != nil || consumed {
		t.Fatalf("second recovery-code consume = %v, %v", consumed, err)
	}
	if err := db.ReplaceRecoveryCodes(ctx, admin.ID, []string{"hash-3"}); err != nil {
		t.Fatal(err)
	}
	if count, err := db.RecoveryCodeCount(ctx, admin.ID); err != nil || count != 1 {
		t.Fatalf("replacement recovery count = %d, %v", count, err)
	}
	if err := db.ReplaceRecoveryCodes(ctx, admin.ID, []string{"hash-4", "hash-4"}); err == nil {
		t.Fatal("duplicate recovery hashes unexpectedly succeeded")
	}
	if count, err := db.RecoveryCodeCount(ctx, admin.ID); err != nil || count != 1 {
		t.Fatalf("failed replacement was not rolled back: count=%d err=%v", count, err)
	}
	if err := db.DisableTOTP(ctx, admin.ID); err != nil {
		t.Fatal(err)
	}
	found, err = db.FirstAdmin(ctx)
	if err != nil || found.TOTPEnabled || found.TOTPSecretEnc != "" {
		t.Fatalf("FirstAdmin after TOTP disable = %+v, %v", found, err)
	}
	if count, err := db.RecoveryCodeCount(ctx, admin.ID); err != nil || count != 0 {
		t.Fatalf("recovery codes after disable = %d, %v", count, err)
	}
	if _, err := db.SessionAdmin(ctx, "unknown"); err == nil {
		t.Fatal("unknown session unexpectedly succeeded")
	}
}

func TestClientsTrafficOperationsAndAudit(t *testing.T) {
	db, ctx := openTestStore(t, "clients.db")
	initTestAdmin(t, db, ctx)
	clientB := createTestClient(t, db, ctx, "b")
	clientA := createTestClient(t, db, ctx, "a")
	if _, err := db.GetClient(ctx, "missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing client error = %v", err)
	}
	if err := db.CreateClient(ctx, domain.Client{}, "", "", ""); err == nil {
		t.Fatal("client with empty ID unexpectedly created")
	}
	clients, err := db.ListClients(ctx)
	if err != nil || len(clients) != 2 || clients[0].ID != clientB.ID || clients[1].ID != clientA.ID {
		t.Fatalf("clients are not stably ordered: %+v, %v", clients, err)
	}
	if !clients[0].Enabled || clients[0].Revoked || clients[0].CreatedAt.IsZero() || clients[0].UpdatedAt.IsZero() {
		t.Fatalf("client fields were not decoded: %+v", clients[0])
	}
	if err := db.SetClientState(ctx, clientA.ID, false, true); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetClient(ctx, clientA.ID)
	if err != nil || got.Enabled || !got.Revoked {
		t.Fatalf("client state = %+v, %v", got, err)
	}
	if err := db.SetClientState(ctx, "missing", true, false); err == nil {
		t.Fatal("setting missing client state unexpectedly succeeded")
	}
	now := time.Now().UTC().Truncate(time.Second)
	snapshot := TrafficSnapshot{ClientID: clientA.ID, RawUpload: 10, RawDownload: 20, TotalUpload: 100, TotalDownload: 200, LastSeenAt: now, LastPolledAt: now}
	if err := db.UpsertTrafficSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.RawUpload, snapshot.TotalUpload = 2, 102
	if err := db.UpsertTrafficSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertTrafficSnapshot(ctx, TrafficSnapshot{}); err == nil {
		t.Fatal("snapshot without client ID unexpectedly succeeded")
	}
	snapshots, err := db.ListTrafficSnapshots(ctx)
	if err != nil || len(snapshots) != 1 || snapshots[clientA.ID].RawUpload != 2 || snapshots[clientA.ID].TotalUpload != 102 || !snapshots[clientA.ID].LastSeenAt.Equal(now) || snapshots[clientA.ID].LastPolledAt.IsZero() {
		t.Fatalf("traffic snapshot = %+v, %v", snapshots, err)
	}
	if err := db.CreateApplyOperation(ctx, ApplyOperation{ID: "operation-1", Revision: 4, State: "pending", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateApplyOperation(ctx, "operation-1", "failed", "probe failed"); err != nil {
		t.Fatal(err)
	}
	var state, operationError string
	if err := db.db.QueryRow(`SELECT state, error FROM apply_operations WHERE id='operation-1'`).Scan(&state, &operationError); err != nil || state != "failed" || operationError != "probe failed" {
		t.Fatalf("updated operation = %q/%q, %v", state, operationError, err)
	}
	if err := db.AddAudit(ctx, "admin", "revoke", "client", clientA.ID, "state changed"); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE entity_id=? AND redacted_diff=?`, clientA.ID, "state changed").Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("audit count = %d, %v", auditCount, err)
	}
	if err := db.DeleteClient(ctx, clientB.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM traffic_snapshots WHERE client_id=?`, clientA.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("unexpected traffic rows after unrelated delete: %d, %v", auditCount, err)
	}
	if err := db.DeleteClient(ctx, clientA.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM traffic_snapshots WHERE client_id=?`, clientA.ID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("traffic snapshot not cascaded on device delete: %d, %v", auditCount, err)
	}
}

func TestDatabaseBackupValidationSettingsReadAndRestore(t *testing.T) {
	ctx := context.Background()
	source, err := Open(ctx, filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	initTestAdmin(t, source, ctx)
	settings, err := source.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	settings.RealityTarget = "source.example.com:443"
	settings.RealitySNI = "source.example.com"
	if err := source.UpdateSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := source.BackupTo(backupPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backupPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, %v", info, err)
	}
	if err := ValidateDatabase(backupPath); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	read, err := ReadSettingsFromDatabase(backupPath)
	if err != nil || read != settings {
		t.Fatalf("read snapshot settings = %+v, %v; want %+v", read, err, settings)
	}
	if err := source.BackupTo(""); err == nil {
		t.Fatal("empty backup path accepted")
	}
	destination, err := Open(ctx, filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	initTestAdmin(t, destination, ctx)
	destSettings, err := destination.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destSettings.PublicHost = "destination.example.com"
	if err := destination.UpdateSettings(ctx, destSettings); err != nil {
		t.Fatal(err)
	}
	if err := destination.RestoreFrom(backupPath); err != nil {
		t.Fatal(err)
	}
	restored, err := destination.GetSettings(ctx)
	if err != nil || restored != settings {
		t.Fatalf("restored settings = %+v, %v; want %+v", restored, err, settings)
	}
	if err := destination.RestoreFrom(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("restore accepted a missing or invalid database")
	}
	if _, err := ReadSettingsFromDatabase(filepath.Join(t.TempDir(), "missing-settings.db")); err == nil {
		t.Fatal("read settings accepted a nonexistent database")
	}
	emptyPath := filepath.Join(t.TempDir(), "empty-settings.db")
	empty, err := Open(ctx, emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if _, err := ReadSettingsFromDatabase(emptyPath); !errors.Is(err, ErrSettingsNotInitialized) {
		t.Fatalf("missing settings error = %v", err)
	}
	if _, err := empty.db.Exec(`DROP TABLE traffic_snapshots`); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDatabase(emptyPath); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("incomplete DB validation error = %v", err)
	}
}
