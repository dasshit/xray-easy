package store

import (
	"errors"
	"time"

	"xray-easy/internal/domain"
)

// These database rows intentionally stay separate from domain types. SQLite
// has a long-lived on-disk contract (including TEXT timestamps), while domain
// types describe the API and runtime behaviour.

type migrationRow struct {
	Version   int    `gorm:"primaryKey;autoIncrement:false"`
	AppliedAt string `gorm:"type:text;not null"`
}

func (migrationRow) TableName() string { return "schema_migrations" }

type settingsRow struct {
	ID                   int    `gorm:"primaryKey;autoIncrement:false;check:settings_singleton,id = 1"`
	SchemaVersion        int    `gorm:"not null;default:1"`
	PublicHost           string `gorm:"type:text"`
	PublicPort           int
	XrayAPIListen        string `gorm:"column:xray_api_listen;type:text;not null;default:127.0.0.1:10085"`
	InternalInboundPort  int    `gorm:"not null;default:8443"`
	RealityTarget        string `gorm:"type:text;not null;default:''"`
	RealitySNI           string `gorm:"type:text;not null;default:''"`
	RealityPrivateKeyEnc string `gorm:"type:text;not null;default:''"`
	RealityPublicKey     string `gorm:"type:text;not null;default:''"`
	ClientFingerprint    string `gorm:"type:text;not null;default:chrome"`
	LogLevel             string `gorm:"type:text;not null;default:warning"`
	CreatedAt            string `gorm:"type:text;not null"`
	UpdatedAt            string `gorm:"type:text;not null"`
}

func (settingsRow) TableName() string { return "settings" }

type hysteriaSettingsRow struct {
	ID               int    `gorm:"primaryKey;autoIncrement:false;check:hysteria_settings_singleton,id = 1"`
	Enabled          int    `gorm:"not null;default:0"`
	Host             string `gorm:"type:text;not null;default:''"`
	TLSMode          string `gorm:"column:tls_mode;type:text;not null;default:custom"`
	TLSCertIP        string `gorm:"column:tls_cert_ip;type:text;not null;default:''"`
	TLSServerName    string `gorm:"column:tls_server_name;type:text;not null;default:''"`
	CertificateID    string `gorm:"type:text;not null;default:''"`
	UDPIdleTimeout   int    `gorm:"column:udp_idle_timeout;not null;default:60"`
	MasqueradeType   string `gorm:"type:text;not null;default:off"`
	MasqueradeString string `gorm:"type:text;not null;default:''"`
	UpdatedAt        string `gorm:"type:text;not null"`
}

func (hysteriaSettingsRow) TableName() string { return "hysteria_settings" }

type adminUserRow struct {
	ID            string `gorm:"type:text;primaryKey"`
	Username      string `gorm:"type:text;not null;unique;collate:nocase"`
	PasswordHash  string `gorm:"type:text;not null"`
	TOTPSecretEnc string `gorm:"column:totp_secret_enc;type:text;not null;default:''"`
	TOTPEnabled   int    `gorm:"column:totp_enabled;not null;default:0"`
	CreatedAt     string `gorm:"type:text;not null"`
	UpdatedAt     string `gorm:"type:text;not null"`
}

func (adminUserRow) TableName() string { return "admin_users" }

func adminFromRow(row adminUserRow) Admin {
	return Admin{
		ID: row.ID, Username: row.Username, PasswordHash: row.PasswordHash,
		TOTPSecretEnc: row.TOTPSecretEnc, TOTPEnabled: row.TOTPEnabled != 0,
	}
}

type sessionRow struct {
	ID          string        `gorm:"type:text;primaryKey"`
	AdminUserID string        `gorm:"type:text;not null"`
	TokenHash   []byte        `gorm:"not null;unique"`
	CreatedAt   string        `gorm:"type:text;not null"`
	ExpiresAt   string        `gorm:"type:text;not null;index:sessions_expiry_idx"`
	LastSeenAt  string        `gorm:"type:text;not null"`
	Admin       *adminUserRow `gorm:"foreignKey:AdminUserID;references:ID;constraint:OnDelete:CASCADE"`
}

func (sessionRow) TableName() string { return "sessions" }

type recoveryCodeRow struct {
	ID          string        `gorm:"type:text;primaryKey"`
	AdminUserID string        `gorm:"type:text;not null;index:totp_recovery_admin_idx,priority:1"`
	CodeHash    string        `gorm:"type:text;not null;unique"`
	UsedAt      *string       `gorm:"type:text;index:totp_recovery_admin_idx,priority:2"`
	CreatedAt   string        `gorm:"type:text;not null"`
	Admin       *adminUserRow `gorm:"foreignKey:AdminUserID;references:ID;constraint:OnDelete:CASCADE"`
}

func (recoveryCodeRow) TableName() string { return "totp_recovery_codes" }

type clientRow struct {
	ID                     string  `gorm:"type:text;primaryKey"`
	Name                   string  `gorm:"type:text;not null"`
	UUID                   *string `gorm:"type:text;unique"`
	Email                  string  `gorm:"type:text;not null;unique"`
	ShortID                *string `gorm:"type:text;unique"`
	ClientFingerprint      string  `gorm:"type:text;not null;default:''"`
	Enabled                int     `gorm:"not null;default:1"`
	Revoked                int     `gorm:"not null;default:0"`
	Protocol               string  `gorm:"type:text;not null;default:legacy_dual"`
	HysteriaAuth           string  `gorm:"type:text;not null;default:''"`
	VlessEnabled           int     `gorm:"not null;default:1"`
	VlessRevoked           int     `gorm:"not null;default:0"`
	HysteriaEnabled        int     `gorm:"not null;default:1"`
	HysteriaRevoked        int     `gorm:"not null;default:0"`
	VMessEnabled           int     `gorm:"column:vmess_enabled;not null;default:0"`
	VMessRevoked           int     `gorm:"column:vmess_revoked;not null;default:0"`
	ShadowsocksPasswordEnc string  `gorm:"type:text;not null;default:''"`
	ShadowsocksEnabled     int     `gorm:"not null;default:0"`
	ShadowsocksRevoked     int     `gorm:"not null;default:0"`
	TrojanPasswordEnc      string  `gorm:"type:text;not null;default:''"`
	TrojanEnabled          int     `gorm:"not null;default:0"`
	TrojanRevoked          int     `gorm:"not null;default:0"`
	CreatedAt              string  `gorm:"type:text;not null"`
	UpdatedAt              string  `gorm:"type:text;not null"`
	ExpiresAt              *string `gorm:"type:text"`
}

func (clientRow) TableName() string { return "clients" }

type realityShortIDRow struct {
	ShortID          string  `gorm:"type:text;primaryKey"`
	AssignedClientID *string `gorm:"type:text;index:reality_short_ids_pool_idx,priority:1"`
	CreatedAt        string  `gorm:"type:text;not null;index:reality_short_ids_pool_idx,priority:2"`
}

func (realityShortIDRow) TableName() string { return "reality_short_ids" }

type configRevisionRow struct {
	Revision   int64  `gorm:"primaryKey;autoIncrement:false"`
	ConfigHash string `gorm:"type:text;not null"`
	State      string `gorm:"type:text;not null"`
	Error      string `gorm:"type:text;not null;default:''"`
	CreatedAt  string `gorm:"type:text;not null"`
}

func (configRevisionRow) TableName() string { return "config_revisions" }

type applyOperationRow struct {
	ID        string `gorm:"type:text;primaryKey"`
	Revision  int64  `gorm:"not null"`
	State     string `gorm:"type:text;not null"`
	Error     string `gorm:"type:text;not null;default:''"`
	CreatedAt string `gorm:"type:text;not null"`
	UpdatedAt string `gorm:"type:text;not null"`
}

func (applyOperationRow) TableName() string { return "apply_operations" }

type applyRevisionSequenceRow struct {
	ID       int   `gorm:"primaryKey;autoIncrement:false;check:apply_revision_sequence_singleton,id = 1"`
	Revision int64 `gorm:"not null"`
}

func (applyRevisionSequenceRow) TableName() string { return "apply_revision_sequence" }

type auditEventRow struct {
	ID           string `gorm:"type:text;primaryKey"`
	ActorID      string `gorm:"type:text;not null"`
	Action       string `gorm:"type:text;not null"`
	Entity       string `gorm:"type:text;not null"`
	EntityID     string `gorm:"type:text;not null"`
	RedactedDiff string `gorm:"type:text;not null;default:''"`
	CreatedAt    string `gorm:"type:text;not null"`
}

func (auditEventRow) TableName() string { return "audit_events" }

type trafficSnapshotRow struct {
	ClientID      string     `gorm:"type:text;primaryKey"`
	RawUpload     int64      `gorm:"not null;default:0"`
	RawDownload   int64      `gorm:"not null;default:0"`
	TotalUpload   int64      `gorm:"not null;default:0"`
	TotalDownload int64      `gorm:"not null;default:0"`
	LastSeenAt    string     `gorm:"type:text;not null;default:''"`
	LastPolledAt  string     `gorm:"type:text;not null"`
	Client        *clientRow `gorm:"foreignKey:ClientID;references:ID;constraint:OnDelete:CASCADE"`
}

func (trafficSnapshotRow) TableName() string { return "traffic_snapshots" }

type awgTrafficSnapshotRow struct {
	PeerName      string `gorm:"type:text;primaryKey"`
	RawUpload     int64  `gorm:"not null;default:0"`
	RawDownload   int64  `gorm:"not null;default:0"`
	TotalUpload   int64  `gorm:"not null;default:0"`
	TotalDownload int64  `gorm:"not null;default:0"`
	SourceIP      string `gorm:"type:text;not null;default:''"`
	LastSeenAt    string `gorm:"type:text;not null;default:''"`
	LastPolledAt  string `gorm:"type:text;not null"`
}

func (awgTrafficSnapshotRow) TableName() string { return "awg_traffic_snapshots" }

func migrationModelsBeforeClients() []any {
	return []any{
		&migrationRow{}, &settingsRow{}, &hysteriaSettingsRow{}, &adminUserRow{},
		&sessionRow{}, &recoveryCodeRow{}, &realityShortIDRow{}, &configRevisionRow{},
		&applyOperationRow{}, &applyRevisionSequenceRow{}, &auditEventRow{},
		&awgTrafficSnapshotRow{},
	}
}

func migrationModelsAfterClients() []any {
	return []any{&clientRow{}, &trafficSnapshotRow{}}
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

func nullableTimeString(value *time.Time) *string {
	if value == nil || value.IsZero() {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339Nano)
	return &formatted
}

func clientRowForInsert(client domain.Client, uuid, email, shortID, now string) clientRow {
	protocol, hysteriaAuth, vlessEnabled, vlessRevoked, hysteriaEnabled, hysteriaRevoked,
		vmessEnabled, vmessRevoked, shadowsocksPassword, shadowsocksEnabled, shadowsocksRevoked,
		trojanPassword, trojanEnabled, trojanRevoked := clientProtocolStorage(client, uuid)
	return clientRow{
		ID: client.ID, Name: client.Name, UUID: stringPointer(uuid), Email: email, ShortID: stringPointer(shortID),
		ClientFingerprint: client.ClientFingerprint, Enabled: boolInt(client.Enabled), Revoked: boolInt(client.Revoked),
		Protocol: protocol, HysteriaAuth: hysteriaAuth, VlessEnabled: vlessEnabled, VlessRevoked: vlessRevoked,
		HysteriaEnabled: hysteriaEnabled, HysteriaRevoked: hysteriaRevoked, VMessEnabled: vmessEnabled,
		VMessRevoked: vmessRevoked, ShadowsocksPasswordEnc: shadowsocksPassword,
		ShadowsocksEnabled: shadowsocksEnabled, ShadowsocksRevoked: shadowsocksRevoked,
		TrojanPasswordEnc: trojanPassword, TrojanEnabled: trojanEnabled, TrojanRevoked: trojanRevoked,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: nullableTimeString(client.ExpiresAt),
	}
}

func clientFromRow(row clientRow) (domain.Client, error) {
	client := domain.Client{
		ID: row.ID, Name: row.Name, Email: row.Email, ClientFingerprint: row.ClientFingerprint,
		Protocol: domain.ClientProtocol(row.Protocol), HysteriaAuth: row.HysteriaAuth,
		Enabled: row.Enabled != 0, Revoked: row.Revoked != 0,
		VLESSEnabled: row.VlessEnabled != 0, VLESSRevoked: row.VlessRevoked != 0,
		HysteriaEnabled: row.HysteriaEnabled != 0, HysteriaRevoked: row.HysteriaRevoked != 0,
		VMessEnabled: row.VMessEnabled != 0, VMessRevoked: row.VMessRevoked != 0,
		ShadowsocksPasswordEnc: row.ShadowsocksPasswordEnc,
		ShadowsocksEnabled:     row.ShadowsocksEnabled != 0, ShadowsocksRevoked: row.ShadowsocksRevoked != 0,
		TrojanPasswordEnc: row.TrojanPasswordEnc,
		TrojanEnabled:     row.TrojanEnabled != 0, TrojanRevoked: row.TrojanRevoked != 0,
	}
	if row.UUID != nil {
		client.UUID = *row.UUID
	}
	if row.ShortID != nil {
		client.ShortID = *row.ShortID
	}
	if client.Protocol == "" {
		client.Protocol = domain.ProtocolLegacyDual
	}
	if client.HysteriaAuth == "" && client.Protocol == domain.ProtocolLegacyDual {
		client.HysteriaAuth = client.UUID
	}
	if row.ExpiresAt != nil {
		expiresAt, err := time.Parse(time.RFC3339Nano, *row.ExpiresAt)
		if err != nil {
			return domain.Client{}, errors.New("client expiry timestamp is invalid")
		}
		expiresAt = expiresAt.UTC()
		client.ExpiresAt = &expiresAt
	}
	client.CreatedAt, _ = time.Parse(time.RFC3339Nano, row.CreatedAt)
	client.UpdatedAt, _ = time.Parse(time.RFC3339Nano, row.UpdatedAt)
	return client, nil
}
