package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
)

func TestCreateProtocolClientReportsPreparationAndPersistenceFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol domain.ClientProtocol
		profile  string
		setup    string
		want     string
	}{
		{
			name: "invalid name", protocol: domain.ProtocolVMess, profile: "bad name", want: "name must contain",
		},
		{
			name: "unsupported protocol", protocol: domain.ProtocolAmneziaWG, profile: "phone", want: "new profiles must use",
		},
		{
			name: "database rejects insert", protocol: domain.ProtocolVMess, profile: "phone", want: "create client",
			setup: `CREATE TRIGGER reject_profile BEFORE INSERT ON clients BEGIN SELECT RAISE(ABORT, 'profile insert blocked'); END`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			if test.setup != "" {
				execSQLiteTestMutation(t, app, "setup create failure", test.setup)
			}
			settings, err := app.server.store.GetSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = app.server.createProtocolClient(t.Context(), settings, test.protocol, test.profile, "", "", app.admin.ID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("createProtocolClient() error = %v, want %q", err, test.want)
			}
		})
	}

	t.Run("maintenance lock is busy", func(t *testing.T) {
		app := newTestApp(t, true)
		settings, err := app.server.store.GetSettings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		lock, err := maintenance.Acquire(t.Context(), app.server.maintenancePath)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
		defer cancel()
		_, err = app.server.createProtocolClient(ctx, settings, "", "phone", "", "", app.admin.ID)
		if err == nil {
			t.Fatal("profile creation proceeded while maintenance lock was held")
		}
	})
}
