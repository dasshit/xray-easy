package store

import (
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestStoreWriteMethodsReturnDatabaseErrors(t *testing.T) {
	db, ctx := openTestStore(t, "write-errors.db")
	admin := initTestAdmin(t, db, ctx)

	for _, test := range []struct {
		name      string
		statement string
		operation func() error
	}{
		{
			name: "session insert", statement: `CREATE TRIGGER reject_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'session blocked'); END`,
			operation: func() error { _, err := db.CreateSession(ctx, admin.ID, time.Hour); return err },
		},
		{
			name: "apply operation insert", statement: `CREATE TRIGGER reject_apply BEFORE INSERT ON apply_operations BEGIN SELECT RAISE(ABORT, 'apply blocked'); END`,
			operation: func() error {
				return db.CreateApplyOperation(ctx, ApplyOperation{ID: "blocked", CreatedAt: time.Now(), UpdatedAt: time.Now()})
			},
		},
		{
			name: "audit insert", statement: `CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit blocked'); END`,
			operation: func() error { return db.AddAudit(ctx, admin.ID, "test", "admin", admin.ID, "") },
		},
		{
			name: "Hysteria defaults insert", statement: `CREATE TRIGGER reject_hysteria_defaults BEFORE INSERT ON hysteria_settings BEGIN SELECT RAISE(ABORT, 'Hysteria defaults blocked'); END`,
			operation: func() error {
				return db.InitializeHysteriaSettings(ctx, domain.HysteriaSettings{
					TLSMode: domain.HysteriaTLSLegacy, UDPIdleTimeout: 60, MasqueradeType: domain.HysteriaMasqueradeOff,
				})
			},
		},
		{
			name: "VMess profile insert", statement: `CREATE TRIGGER reject_vmess BEFORE INSERT ON clients BEGIN SELECT RAISE(ABORT, 'VMess blocked'); END`,
			operation: func() error {
				return db.CreateVMessClient(ctx, domain.Client{ID: "phone", Name: "phone", Protocol: domain.ProtocolVMess, UUID: "uuid", Email: "phone@xray-easy"})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.db.ExecContext(ctx, test.statement); err != nil {
				t.Fatal(err)
			}
			if err := test.operation(); err == nil || !strings.Contains(err.Error(), "blocked") {
				t.Fatalf("write error = %v", err)
			}
			if _, err := db.db.ExecContext(ctx, `DROP TRIGGER IF EXISTS `+map[string]string{
				"session insert": "reject_session", "apply operation insert": "reject_apply", "audit insert": "reject_audit",
				"Hysteria defaults insert": "reject_hysteria_defaults", "VMess profile insert": "reject_vmess",
			}[test.name]); err != nil {
				t.Fatal(err)
			}
		})
	}
}
