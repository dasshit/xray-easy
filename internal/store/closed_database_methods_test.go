package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestPublicStoreMethodsPropagateClosedDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "closed-methods.db"))
	if err != nil {
		t.Fatal(err)
	}
	admin := initTestAdmin(t, db, ctx)
	if err := db.InitializeHysteriaSettings(ctx, domain.HysteriaSettings{TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	settings := domain.Settings{PublicHost: "vpn.example.test", PublicPort: 443}
	hysteriaSettings := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	client := domain.Client{ID: "new-client", Name: "New client", Enabled: true, Protocol: domain.ProtocolVLESS, VLESSEnabled: true}
	vlessState := map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}}
	operation := ApplyOperation{ID: "op", Revision: 1, State: "pending", CreatedAt: now, UpdatedAt: now}
	checks := []struct {
		name string
		call func() error
	}{
		{"Ping", func() error { return db.Ping(ctx) }},
		{"SetupStatus", func() error { _, err := db.SetupStatus(ctx); return err }},
		{"Initialize", func() error { _, err := db.Initialize(ctx, "another", "hash", "host.example.test", 443); return err }},
		{"FindAdmin", func() error { _, err := db.FindAdmin(ctx, admin.Username); return err }},
		{"CreateSession", func() error { _, err := db.CreateSession(ctx, admin.ID, time.Hour); return err }},
		{"SessionAdmin", func() error { _, err := db.SessionAdmin(ctx, "token"); return err }},
		{"DeleteSession", func() error { return db.DeleteSession(ctx, "token") }},
		{"DeleteAllSessions", func() error { return db.DeleteAllSessions(ctx, admin.ID) }},
		{"ChangeAdminPassword", func() error { return db.ChangeAdminPassword(ctx, admin.ID, "new-hash") }},
		{"SetTOTP", func() error { return db.SetTOTP(ctx, admin.ID, "secret", nil) }},
		{"DisableTOTP", func() error { return db.DisableTOTP(ctx, admin.ID) }},
		{"ConsumeRecoveryCode", func() error { _, err := db.ConsumeRecoveryCode(ctx, admin.ID, "code"); return err }},
		{"RecoveryCodeCount", func() error { _, err := db.RecoveryCodeCount(ctx, admin.ID); return err }},
		{"FirstAdmin", func() error { _, err := db.FirstAdmin(ctx); return err }},
		{"ReplaceRecoveryCodes", func() error { return db.ReplaceRecoveryCodes(ctx, admin.ID, nil) }},
		{"GetSettings", func() error { _, err := db.GetSettings(ctx); return err }},
		{"UpdateSettings", func() error { return db.UpdateSettings(ctx, settings) }},
		{"InitializeHysteriaSettings", func() error { return db.InitializeHysteriaSettings(ctx, hysteriaSettings) }},
		{"GetHysteriaSettings", func() error { _, err := db.GetHysteriaSettings(ctx); return err }},
		{"UpdateHysteriaSettings", func() error { return db.UpdateHysteriaSettings(ctx, hysteriaSettings) }},
		{"UpdateSettingsAndClientStates", func() error { return db.UpdateSettingsAndClientStates(ctx, settings, nil) }},
		{"UpdateSettingsAndClientProtocolStates", func() error { return db.UpdateSettingsAndClientProtocolStates(ctx, settings, nil) }},
		{"CreateClient", func() error { return db.CreateClient(ctx, client, "uuid", "vless@example.test", "0123456789abcdef") }},
		{"CreateHysteriaClient", func() error {
			return db.CreateHysteriaClient(ctx, domain.Client{ID: "hysteria", Name: "Hysteria", Protocol: domain.ProtocolHysteria2, HysteriaAuth: "auth", Email: "hysteria@example.test"})
		}},
		{"CreateVMessClient", func() error {
			return db.CreateVMessClient(ctx, domain.Client{ID: "vmess", Name: "VMess", Protocol: domain.ProtocolVMess, UUID: "uuid", Email: "vmess@example.test"})
		}},
		{"CreateShadowsocksClient", func() error {
			return db.CreateShadowsocksClient(ctx, domain.Client{ID: "ss", Name: "SS", Protocol: domain.ProtocolShadowsocks, ShadowsocksPasswordEnc: "enc", Email: "ss@example.test"})
		}},
		{"CreateTrojanClient", func() error {
			return db.CreateTrojanClient(ctx, domain.Client{ID: "trojan", Name: "Trojan", Protocol: domain.ProtocolTrojan, TrojanPasswordEnc: "enc", Email: "trojan@example.test"})
		}},
		{"ListReservedShortIDs", func() error { _, err := db.ListReservedShortIDs(ctx); return err }},
		{"EnsureReservedShortIDs", func() error {
			return db.EnsureReservedShortIDs(ctx, 1, func() (string, error) { return "0123456789abcdef", nil })
		}},
		{"SeedReservedShortIDs", func() error {
			return db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "0123456789abcdef", nil })
		}},
		{"CreateClientWithReservedShortID", func() error {
			_, _, err := db.CreateClientWithReservedShortID(ctx, client, "uuid", "vless@example.test", 1, func() (string, error) { return "0123456789abcdef", nil })
			return err
		}},
		{"ListClients", func() error { _, err := db.ListClients(ctx); return err }},
		{"GetClient", func() error { _, err := db.GetClient(ctx, "existing"); return err }},
		{"SetClientExpiry", func() error { return db.SetClientExpiry(ctx, "existing", nil) }},
		{"ListExpiredEnabledClients", func() error { _, err := db.ListExpiredEnabledClients(ctx, now); return err }},
		{"SetClientState", func() error { return db.SetClientState(ctx, "existing", false, false) }},
		{"SetClientProtocolStates", func() error { return db.SetClientProtocolStates(ctx, "existing", vlessState) }},
		{"DeleteClient", func() error { return db.DeleteClient(ctx, "existing") }},
		{"ListTrafficSnapshots", func() error { _, err := db.ListTrafficSnapshots(ctx); return err }},
		{"UpsertTrafficSnapshot", func() error { return db.UpsertTrafficSnapshot(ctx, TrafficSnapshot{ClientID: "existing"}) }},
		{"ListAWGTrafficSnapshots", func() error { _, err := db.ListAWGTrafficSnapshots(ctx); return err }},
		{"UpsertAWGTrafficSnapshot", func() error { return db.UpsertAWGTrafficSnapshot(ctx, AWGTrafficSnapshot{PeerName: "peer"}) }},
		{"DeleteAWGTrafficSnapshot", func() error { return db.DeleteAWGTrafficSnapshot(ctx, "peer") }},
		{"CreateApplyOperation", func() error { return db.CreateApplyOperation(ctx, operation) }},
		{"CreateApplyOperationWithNextRevision", func() error { _, err := db.CreateApplyOperationWithNextRevision(ctx, operation); return err }},
		{"UpdateApplyOperation", func() error { return db.UpdateApplyOperation(ctx, operation.ID, "failed", "error") }},
		{"GetApplyOperation", func() error { _, err := db.GetApplyOperation(ctx, operation.ID); return err }},
		{"AddAudit", func() error { return db.AddAudit(ctx, admin.ID, "action", "client", client.ID, "diff") }},
		{"BackupTo", func() error { return db.BackupTo(filepath.Join(t.TempDir(), "snapshot.db")) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.call(); err == nil {
				t.Fatal("operation succeeded after the database was closed")
			}
		})
	}
}
