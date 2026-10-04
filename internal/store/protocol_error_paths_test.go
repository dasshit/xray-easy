package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestProtocolStateUpdatesRejectInvalidAccessAndRollBackWriteErrors(t *testing.T) {
	db, ctx := openTestStore(t, "protocol-state-errors.db")
	legacy := createTestClient(t, db, ctx, "legacy")
	hysteria, err := domain.NewProtocolClient("hysteria", "hysteria", domain.ProtocolHysteria2, "", "auth")
	if err != nil {
		t.Fatal(err)
	}
	hysteria.Email = "hysteria@xray-easy"
	if err := db.CreateHysteriaClient(ctx, hysteria); err != nil {
		t.Fatal(err)
	}
	vmess, err := domain.NewProtocolClient("vmess", "vmess", domain.ProtocolVMess, "uuid-vmess", "")
	if err != nil {
		t.Fatal(err)
	}
	vmess.UUID, vmess.Email = "uuid-vmess", "vmess@xray-easy"
	if err := db.CreateVMessClient(ctx, vmess); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		id     string
		states map[domain.ClientProtocol]domain.ClientState
		want   string
	}{
		{name: "empty", id: legacy.ID, states: map[domain.ClientProtocol]domain.ClientState{}, want: "at least one"},
		{name: "missing client", id: "missing", states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}, want: "client not found"},
		{name: "revoked enabled", id: legacy.ID, states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: true, Revoked: true}}, want: "revoked protocol"},
		{name: "missing VLESS", id: hysteria.ID, states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}, want: "no VLESS"},
		{name: "missing Hysteria", id: vmess.ID, states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolHysteria2: {Enabled: false}}, want: "no Hysteria"},
		{name: "missing VMess", id: hysteria.ID, states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVMess: {Enabled: false}}, want: "no VMess"},
		{name: "unsupported", id: legacy.ID, states: map[domain.ClientProtocol]domain.ClientState{domain.ProtocolAmneziaWG: {Enabled: false}}, want: "unsupported protocol"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := db.SetClientProtocolStates(ctx, test.id, test.states); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("SetClientProtocolStates() error = %v, want %q", err, test.want)
			}
		})
	}

	if _, err := db.db.Exec(`CREATE TRIGGER reject_protocol_state BEFORE UPDATE ON clients BEGIN SELECT RAISE(ABORT, 'protocol state blocked'); END`); err != nil {
		t.Fatal(err)
	}
	err = db.SetClientProtocolState(ctx, legacy.ID, domain.ProtocolVLESS, domain.ClientState{Enabled: false})
	if err == nil || !strings.Contains(err.Error(), "protocol state blocked") {
		t.Fatalf("protocol state update trigger error = %v", err)
	}
	current, err := db.GetClient(ctx, legacy.ID)
	if err != nil || !current.VLESSEnabled || current.VLESSRevoked {
		t.Fatalf("failed protocol state update was not rolled back: %+v, %v", current, err)
	}
}

func TestHysteriaSettingsRejectInvalidAndUninitializedUpdates(t *testing.T) {
	db, ctx := openTestStore(t, "hysteria-settings-errors.db")
	settings := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.UpdateHysteriaSettings(ctx, settings); err == nil || !strings.Contains(err.Error(), "Hysteria 2 settings are not initialized") {
		t.Fatalf("update before initialization = %v", err)
	}
	invalid := settings
	invalid.UDPIdleTimeout = 0
	if err := db.UpdateHysteriaSettings(ctx, invalid); err == nil {
		t.Fatal("UpdateHysteriaSettings accepted invalid settings")
	}
	if err := db.InitializeHysteriaSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER reject_hysteria_update BEFORE UPDATE ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'Hysteria update blocked'); END`); err != nil {
		t.Fatal(err)
	}
	settings.Enabled = true
	if err := db.UpdateHysteriaSettings(ctx, settings); err == nil || !strings.Contains(err.Error(), "Hysteria update blocked") {
		t.Fatalf("Hysteria update trigger error = %v", err)
	}
}

func TestSettingsAndProtocolStateUpdateValidatesEveryXrayProtocolAccess(t *testing.T) {
	db, ctx := openTestStore(t, "settings-protocol-transition-matrix.db")
	admin := initTestAdmin(t, db, ctx)
	settings, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[domain.ClientProtocol]string{}
	vless := createTestClient(t, db, ctx, "vless")
	profiles[domain.ProtocolVLESS] = vless.ID
	for _, protocol := range []domain.ClientProtocol{domain.ProtocolHysteria2, domain.ProtocolVMess, domain.ProtocolShadowsocks, domain.ProtocolTrojan} {
		client, err := domain.NewProtocolClient(string(protocol), string(protocol), protocol, "", "auth")
		if err != nil {
			t.Fatal(err)
		}
		client.Email = string(protocol) + "@example.test"
		switch protocol {
		case domain.ProtocolHysteria2:
			err = db.CreateHysteriaClient(ctx, client)
		case domain.ProtocolVMess:
			client.UUID = "vmess-uuid"
			err = db.CreateVMessClient(ctx, client)
		case domain.ProtocolShadowsocks:
			client.ShadowsocksPasswordEnc = "encrypted-ss"
			err = db.CreateShadowsocksClient(ctx, client)
		case domain.ProtocolTrojan:
			client.TrojanPasswordEnc = "encrypted-trojan"
			err = db.CreateTrojanClient(ctx, client)
		}
		if err != nil {
			t.Fatalf("create %s test profile: %v", protocol, err)
		}
		profiles[protocol] = client.ID
	}

	invalidTransitions := []struct {
		name     string
		protocol domain.ClientProtocol
		access   domain.ClientProtocol
		want     string
	}{
		{"VLESS cannot gain Hysteria access", domain.ProtocolVLESS, domain.ProtocolVMess, "no VMess"},
		{"Hysteria cannot gain VLESS access", domain.ProtocolHysteria2, domain.ProtocolVLESS, "no VLESS"},
		{"VMess cannot gain Hysteria access", domain.ProtocolVMess, domain.ProtocolHysteria2, "no Hysteria"},
		{"VMess cannot gain Shadowsocks access", domain.ProtocolVMess, domain.ProtocolShadowsocks, "no Shadowsocks"},
		{"Shadowsocks cannot gain Trojan access", domain.ProtocolShadowsocks, domain.ProtocolTrojan, "no Trojan"},
		{"Trojan cannot gain Shadowsocks access", domain.ProtocolTrojan, domain.ProtocolShadowsocks, "no Shadowsocks"},
		{"unsupported protocol access", domain.ProtocolVLESS, domain.ProtocolAmneziaWG, "unsupported protocol"},
	}
	for _, test := range invalidTransitions {
		t.Run(test.name, func(t *testing.T) {
			err := db.UpdateSettingsAndClientProtocolStates(ctx, settings, map[string]map[domain.ClientProtocol]domain.ClientState{
				profiles[test.protocol]: {test.access: {Enabled: false}},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("protocol transition error = %v, want %q", err, test.want)
			}
		})
	}
	if err := db.UpdateSettingsAndClientProtocolStates(ctx, settings, map[string]map[domain.ClientProtocol]domain.ClientState{
		"missing-profile": {domain.ProtocolVLESS: {Enabled: false}},
	}); err == nil || !strings.Contains(err.Error(), "no rows") {
		t.Fatalf("missing profile transition error = %v", err)
	}
	if err := db.UpdateSettingsAndClientProtocolStates(ctx, settings, map[string]map[domain.ClientProtocol]domain.ClientState{
		profiles[domain.ProtocolVLESS]: {domain.ProtocolVLESS: {Enabled: true, Revoked: true}},
	}); err == nil || !strings.Contains(err.Error(), "revoked protocol") {
		t.Fatalf("revoked profile re-enable error = %v", err)
	}
	for protocol, id := range profiles {
		if err := db.UpdateSettingsAndClientProtocolStates(ctx, settings, map[string]map[domain.ClientProtocol]domain.ClientState{
			id: {protocol: {Enabled: false}},
		}); err != nil {
			t.Errorf("disable %s: %v", protocol, err)
		}
	}
	if err := db.AddAudit(ctx, admin.ID, "transition-matrix.complete", "test", "matrix", "all protocol paths visited"); err != nil {
		t.Fatal(err)
	}
}

func TestSetClientProtocolStatesTransitionsEveryPersistedProtocol(t *testing.T) {
	db, ctx := openTestStore(t, "protocol-state-write-matrix.db")
	clients := map[domain.ClientProtocol]domain.Client{
		domain.ProtocolVLESS: createTestClient(t, db, ctx, "vless-state"),
	}
	for _, protocol := range []domain.ClientProtocol{domain.ProtocolHysteria2, domain.ProtocolVMess, domain.ProtocolShadowsocks, domain.ProtocolTrojan} {
		client, err := domain.NewProtocolClient("state-"+string(protocol), string(protocol), protocol, "", "auth")
		if err != nil {
			t.Fatal(err)
		}
		client.Email = string(protocol) + "-state@example.test"
		switch protocol {
		case domain.ProtocolHysteria2:
			err = db.CreateHysteriaClient(ctx, client)
		case domain.ProtocolVMess:
			client.UUID = "vmess-state-uuid"
			err = db.CreateVMessClient(ctx, client)
		case domain.ProtocolShadowsocks:
			client.ShadowsocksPasswordEnc = "ss-secret"
			err = db.CreateShadowsocksClient(ctx, client)
		case domain.ProtocolTrojan:
			client.TrojanPasswordEnc = "trojan-secret"
			err = db.CreateTrojanClient(ctx, client)
		}
		if err != nil {
			t.Fatalf("create %s test profile: %v", protocol, err)
		}
		clients[protocol] = client
	}
	for protocol, client := range clients {
		if err := db.SetClientProtocolState(ctx, client.ID, protocol, domain.ClientState{Enabled: false}); err != nil {
			t.Errorf("disable %s profile: %v", protocol, err)
		}
	}
	if _, err := db.db.Exec(`UPDATE clients SET protocol='' WHERE id='vless-state'`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetClientProtocolState(ctx, "vless-state", domain.ProtocolVLESS, domain.ClientState{Enabled: true}); err != nil {
		t.Fatalf("legacy empty protocol state update: %v", err)
	}
	if _, err := db.db.Exec(`UPDATE clients SET expires_at='not-a-timestamp' WHERE id='vless-state'`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetClientProtocolState(ctx, "vless-state", domain.ProtocolVLESS, domain.ClientState{Enabled: false}); err == nil || !strings.Contains(err.Error(), "expiry timestamp is invalid") {
		t.Fatalf("malformed persisted profile expiry error = %v", err)
	}
	if _, err := db.db.Exec(`UPDATE clients SET expires_at=NULL WHERE id='vless-state'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER block_protocol_state_update BEFORE UPDATE ON clients BEGIN SELECT RAISE(ABORT, 'state update blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.SetClientProtocolState(ctx, "vless-state", domain.ProtocolVLESS, domain.ClientState{Enabled: false}); err == nil || !strings.Contains(err.Error(), "state update blocked") {
		t.Fatalf("protocol state update trigger error = %v", err)
	}
}

func TestSetClientProtocolStatesHandlesMalformedRowsAndLostUpdates(t *testing.T) {
	t.Run("protocol is absent and optional accesses are unavailable", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-state-empty-protocol.db")
		client := createTestClient(t, db, ctx, "empty-protocol")
		if _, err := db.db.Exec(`UPDATE clients SET protocol='' WHERE id=?`, client.ID); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			access domain.ClientProtocol
			want   string
		}{{domain.ProtocolShadowsocks, "no Shadowsocks"}, {domain.ProtocolTrojan, "no Trojan"}} {
			err := db.SetClientProtocolStates(ctx, client.ID, map[domain.ClientProtocol]domain.ClientState{test.access: {Enabled: false}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("legacy profile access %q error = %v", test.access, err)
			}
		}
	})

	t.Run("expiry timestamp is converted to UTC", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-state-expiry.db")
		deadline := time.Date(2027, time.March, 4, 5, 6, 7, 0, time.FixedZone("UTC+2", 2*60*60))
		client := domain.Client{ID: "expiring", Name: "expiring", Enabled: true, ExpiresAt: &deadline}
		if err := db.CreateClient(ctx, client, "uuid-expiring", "expiring@example.test", "0123456789abcdef"); err != nil {
			t.Fatal(err)
		}
		if err := db.SetClientProtocolStates(ctx, client.ID, map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("malformed schema and ignored update", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-state-row-errors.db")
		if _, err := db.db.Exec(`ALTER TABLE clients DROP COLUMN expires_at`); err != nil {
			t.Fatal(err)
		}
		if err := db.SetClientProtocolStates(ctx, "missing", map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}); err == nil {
			t.Fatal("state update succeeded against a malformed clients schema")
		}
	})

	t.Run("update ignored by trigger", func(t *testing.T) {
		db, ctx := openTestStore(t, "protocol-state-ignored-update.db")
		client := createTestClient(t, db, ctx, "ignored-update")
		if _, err := db.db.Exec(`CREATE TRIGGER ignore_client_state_update BEFORE UPDATE ON clients BEGIN SELECT RAISE(IGNORE); END`); err != nil {
			t.Fatal(err)
		}
		if err := db.SetClientProtocolStates(ctx, client.ID, map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}); err == nil || !strings.Contains(err.Error(), "client not found") {
			t.Fatalf("ignored state update error = %v", err)
		}
	})
}

func TestProtocolMigrationRequiresSnapshotPathAndReportsSnapshotFailure(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "missing database path", want: "database path is required"},
		{name: "unavailable snapshot directory", path: filepath.Join(t.TempDir(), "missing", "legacy.db"), want: "create pre-migration database snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TABLE clients (id TEXT PRIMARY KEY, name TEXT NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			store := &Store{db: db, dbPath: test.path}
			if err := store.migrateClientProtocols(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("migrateClientProtocols() error = %v, want %q", err, test.want)
			}
		})
	}
}
