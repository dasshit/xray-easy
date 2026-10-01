package store

import (
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestClosedStoreOperationsReturnDatabaseErrors(t *testing.T) {
	db, ctx := openTestStore(t, "closed-operations.db")
	admin := initTestAdmin(t, db, ctx)
	client := createTestClient(t, db, ctx, "phone")
	settings, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hysteriaSettings := domain.HysteriaSettings{TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff}
	if err := db.InitializeHysteriaSettings(ctx, hysteriaSettings); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(ctx); err == nil {
		t.Fatal("Ping succeeded after the database was closed")
	}
	if err := db.BackupTo(t.TempDir() + "/closed.db"); err == nil {
		t.Fatal("BackupTo succeeded after the database was closed")
	}
	if _, err := db.SetupStatus(ctx); err == nil {
		t.Fatal("SetupStatus succeeded after the database was closed")
	}
	if _, err := db.Initialize(ctx, "other", "hash", "vpn.example.test", 443); err == nil {
		t.Fatal("Initialize succeeded after the database was closed")
	}
	if _, err := db.FindAdmin(ctx, admin.Username); err == nil {
		t.Fatal("FindAdmin succeeded after the database was closed")
	}
	if _, err := db.CreateSession(ctx, admin.ID, time.Hour); err == nil {
		t.Fatal("CreateSession succeeded after the database was closed")
	}
	if _, err := db.SessionAdmin(ctx, "token"); err == nil {
		t.Fatal("SessionAdmin unexpectedly returned an administrator")
	}
	for name, operation := range map[string]func() error{
		"delete session":         func() error { return db.DeleteSession(ctx, "token") },
		"delete all sessions":    func() error { return db.DeleteAllSessions(ctx, admin.ID) },
		"change password":        func() error { return db.ChangeAdminPassword(ctx, admin.ID, "new-hash") },
		"set TOTP":               func() error { return db.SetTOTP(ctx, admin.ID, "encrypted", []string{"recovery-hash"}) },
		"disable TOTP":           func() error { return db.DisableTOTP(ctx, admin.ID) },
		"replace recovery codes": func() error { return db.ReplaceRecoveryCodes(ctx, admin.ID, []string{"hash"}) },
		"update settings":        func() error { return db.UpdateSettings(ctx, settings) },
		"initialize Hysteria":    func() error { return db.InitializeHysteriaSettings(ctx, hysteriaSettings) },
		"update Hysteria":        func() error { return db.UpdateHysteriaSettings(ctx, hysteriaSettings) },
		"update settings and states": func() error {
			return db.UpdateSettingsAndClientStates(ctx, settings, map[string]domain.ClientState{client.ID: {Enabled: false}})
		},
		"update settings and protocol states": func() error {
			return db.UpdateSettingsAndClientProtocolStates(ctx, settings, map[string]map[domain.ClientProtocol]domain.ClientState{client.ID: {domain.ProtocolVLESS: {Enabled: false}}})
		},
		"create legacy profile": func() error { return db.CreateClient(ctx, client, "uuid", "email", "short") },
		"create Hysteria profile": func() error {
			return db.CreateHysteriaClient(ctx, domain.Client{ID: "hysteria", Name: "hysteria", Email: "h@example.test", Protocol: domain.ProtocolHysteria2, HysteriaAuth: "auth"})
		},
		"create VMess profile": func() error {
			return db.CreateVMessClient(ctx, domain.Client{ID: "vmess", Name: "vmess", Email: "v@example.test", Protocol: domain.ProtocolVMess, UUID: "uuid"})
		},
		"create Shadowsocks profile": func() error {
			return db.CreateShadowsocksClient(ctx, domain.Client{ID: "shadowsocks", Name: "shadowsocks", Email: "s@example.test", Protocol: domain.ProtocolShadowsocks, ShadowsocksPasswordEnc: "encrypted"})
		},
		"ensure short ID pool": func() error {
			return db.EnsureReservedShortIDs(ctx, 1, func() (string, error) { return "0123456789abcdef", nil })
		},
		"seed short ID pool": func() error {
			return db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "0123456789abcdef", nil })
		},
		"create client with short ID": func() error {
			_, _, err := db.CreateClientWithReservedShortID(ctx, client, "uuid", "email", 1, func() (string, error) { return "0123456789abcdef", nil })
			return err
		},
		"set client state": func() error { return db.SetClientState(ctx, client.ID, false, false) },
		"set protocol state": func() error {
			return db.SetClientProtocolState(ctx, client.ID, domain.ProtocolVLESS, domain.ClientState{Enabled: false})
		},
		"set protocol states": func() error {
			return db.SetClientProtocolStates(ctx, client.ID, map[domain.ClientProtocol]domain.ClientState{domain.ProtocolVLESS: {Enabled: false}})
		},
		"delete client":          func() error { return db.DeleteClient(ctx, client.ID) },
		"upsert traffic":         func() error { return db.UpsertTrafficSnapshot(ctx, TrafficSnapshot{ClientID: client.ID}) },
		"upsert AWG traffic":     func() error { return db.UpsertAWGTrafficSnapshot(ctx, AWGTrafficSnapshot{PeerName: "peer"}) },
		"create apply operation": func() error { return db.CreateApplyOperation(ctx, ApplyOperation{ID: "op"}) },
		"create apply operation with revision": func() error {
			_, err := db.CreateApplyOperationWithNextRevision(ctx, ApplyOperation{ID: "revision-op"})
			return err
		},
		"update apply operation": func() error { return db.UpdateApplyOperation(ctx, "op", "failed", "error") },
		"add audit":              func() error { return db.AddAudit(ctx, admin.ID, "test", "client", client.ID, "diff") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil {
				t.Fatal("operation succeeded with a closed database")
			}
		})
	}
	if _, err := db.GetSettings(ctx); err == nil {
		t.Fatal("GetSettings succeeded after the database was closed")
	}
	if _, err := db.GetHysteriaSettings(ctx); err == nil {
		t.Fatal("GetHysteriaSettings succeeded after the database was closed")
	}
	if _, err := db.ListClients(ctx); err == nil {
		t.Fatal("ListClients succeeded after the database was closed")
	}
	if _, err := db.GetClient(ctx, client.ID); err == nil {
		t.Fatal("GetClient succeeded after the database was closed")
	}
	if _, err := db.ListReservedShortIDs(ctx); err == nil {
		t.Fatal("ListReservedShortIDs succeeded after the database was closed")
	}
	if _, err := db.ListTrafficSnapshots(ctx); err == nil {
		t.Fatal("ListTrafficSnapshots succeeded after the database was closed")
	}
	if _, err := db.ListAWGTrafficSnapshots(ctx); err == nil {
		t.Fatal("ListAWGTrafficSnapshots succeeded after the database was closed")
	}
	if _, err := db.GetApplyOperation(ctx, "op"); err == nil {
		t.Fatal("GetApplyOperation succeeded after the database was closed")
	}
	if _, err := db.RecoveryCodeCount(ctx, admin.ID); err == nil {
		t.Fatal("RecoveryCodeCount succeeded after the database was closed")
	}
	if _, err := db.ConsumeRecoveryCode(ctx, admin.ID, "hash"); err == nil {
		t.Fatal("ConsumeRecoveryCode succeeded after the database was closed")
	}
	if err := db.DeleteAWGTrafficSnapshot(ctx, "peer"); err == nil {
		t.Fatal("DeleteAWGTrafficSnapshot succeeded after the database was closed")
	}
}
