package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

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
