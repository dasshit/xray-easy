package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestRealityShortIDReconciliationAdditionalFailurePaths(t *testing.T) {
	for _, test := range []struct {
		name      string
		statement string
		want      string
		mutate    func(*testing.T, *testApp)
	}{
		{
			name:      "settings query failure",
			statement: `DROP TABLE settings`,
			want:      "no such table",
		},
		{
			name:      "private key decryption failure",
			statement: `UPDATE settings SET reality_private_key_enc='invalid' WHERE id=1`,
			want:      "could not decrypt REALITY private key",
		},
		{
			name:      "reserved pool seed failure",
			statement: `DELETE FROM schema_migrations WHERE version=3; DELETE FROM reality_short_ids; CREATE TRIGGER reject_short_id_seed BEFORE INSERT ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'seed blocked'); END`,
			want:      "ensure REALITY short-ID reserve",
		},
		{
			name: "active config read failure",
			want: "is a directory",
			mutate: func(t *testing.T, app *testApp) {
				active := filepath.Join(app.server.configDir, "active.json")
				if err := os.Remove(active); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(active, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			if test.statement != "" {
				execSQLiteTestMutation(t, app, "inject REALITY reconciliation error", test.statement)
			}
			if test.mutate != nil {
				_ = createRuntimeTestClient(t, app, "active-config-read-error")
				test.mutate(t, &app)
			}
			err := app.server.reconcileRealityShortIDsLocked(t.Context(), nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("REALITY reconciliation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestRealityShortIDReconciliationUsesFullApplyAndRollsBackPromotion(t *testing.T) {
	t.Run("runtime without inbound replacement", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "full-apply")
		staleRealityShortIDs(t, &app)
		app.sup.applyCalls = nil
		if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err != nil {
			t.Fatalf("full runtime apply: %v", err)
		}
		if len(app.sup.applyCalls) == 0 {
			t.Fatal("runtime without ReplaceInbound was not fully applied")
		}
	})

	t.Run("full apply failure", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "full-apply-failure")
		staleRealityShortIDs(t, &app)
		app.sup.applyCalls = nil
		app.sup.applyErrors = []error{errors.New("runtime rejected full apply")}
		if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "runtime rejected full apply") {
			t.Fatalf("full apply error = %v", err)
		}
	})

	t.Run("rename failure restores the previous full configuration", func(t *testing.T) {
		app := newTestApp(t, true)
		client := createRuntimeTestClient(t, app, "full-apply-rollback")
		staleRealityShortIDs(t, &app)
		app.sup.applyCalls = nil
		active := filepath.Join(app.server.configDir, "active.json")
		changed := false
		app.sup.applyHook = func(path, _ string) {
			if changed || path == active {
				return
			}
			changed = true
			if err := os.Remove(active); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(active, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := app.server.reconcileRealityShortIDsLocked(t.Context(), []domain.Client{client}); err == nil || !strings.Contains(err.Error(), "promote reconciled") {
			t.Fatalf("full apply promotion error = %v", err)
		}
		if len(app.sup.applyCalls) != 2 || !strings.HasSuffix(app.sup.applyCalls[1][1], "-rollback") {
			t.Fatalf("previous full configuration was not restored: %v", app.sup.applyCalls)
		}
	})
}

func staleRealityShortIDs(t *testing.T, app *testApp) {
	t.Helper()
	active := filepath.Join(app.server.configDir, "active.json")
	data, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		t.Fatalf("active config has no inbound: %s", data)
	}
	inbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("active inbound has unexpected type: %#v", inbounds[0])
	}
	stream, ok := inbound["streamSettings"].(map[string]any)
	if !ok {
		t.Fatalf("active stream settings have unexpected type: %#v", inbound["streamSettings"])
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok {
		t.Fatalf("active REALITY settings have unexpected type: %#v", stream["realitySettings"])
	}
	reality["shortIds"] = []string{"ffffffffffffffff"}
	updated, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunCLIDoctorRejectsUnsupportedArguments(t *testing.T) {
	if err := runCLI(context.Background(), []string{"doctor", "unknown"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("unknown doctor subcommand error = %v", err)
	}
}

func TestClientCreationRejectsUnknownAndUnreadyHysteriaConfigurations(t *testing.T) {
	t.Run("unknown protocol", func(t *testing.T) {
		app := newTestApp(t, true)
		response := requestJSON(t, app, "POST", "/api/clients", map[string]any{"name": "phone", "protocol": "unknown"}, true)
		if response.Code != 400 || !strings.Contains(response.Body.String(), "protocol must be") {
			t.Fatalf("unknown protocol response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("missing Hysteria settings", func(t *testing.T) {
		app := newTestApp(t, true)
		execSQLiteTestMutation(t, app, "drop Hysteria settings", `DROP TABLE hysteria_settings`)
		response := requestJSON(t, app, "POST", "/api/clients", map[string]any{"name": "phone", "protocol": "hysteria2"}, true)
		if response.Code != 500 || !strings.Contains(response.Body.String(), "could not read Hysteria 2 settings") {
			t.Fatalf("missing Hysteria settings response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("missing Hysteria certificate", func(t *testing.T) {
		app := newTestApp(t, true)
		if err := os.Remove(filepath.Join(app.server.dataDir, "hysteria-tls", "fullchain.pem")); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHysteriaSettings(t.Context(), app.server.store); err != nil {
			t.Fatal(err)
		}
		hysteriaSettings, err := app.server.store.GetHysteriaSettings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		hysteriaSettings.Enabled = true
		if err := app.server.store.UpdateHysteriaSettings(t.Context(), hysteriaSettings); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, "POST", "/api/clients", map[string]any{"name": "phone", "protocol": "hysteria2"}, true)
		if response.Code != 409 || !strings.Contains(response.Body.String(), "certificate_not_ready") {
			t.Fatalf("missing Hysteria certificate response = %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("self-signed endpoint does not match configured host", func(t *testing.T) {
		app := newTestApp(t, true)
		certificateDir := filepath.Join(app.server.dataDir, "hysteria-tls")
		writeTestMkcertMaterial(t, certificateDir, "8.8.8.8")
		leaf, err := os.ReadFile(filepath.Join(certificateDir, "leaf.pem"))
		if err != nil {
			t.Fatal(err)
		}
		privateKey, err := os.ReadFile(filepath.Join(certificateDir, "key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certificateDir, "fullchain.pem"), leaf, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(certificateDir, "privkey.pem"), privateKey, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHysteriaSettings(t.Context(), app.server.store); err != nil {
			t.Fatal(err)
		}
		hysteriaSettings, err := app.server.store.GetHysteriaSettings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		hysteriaSettings.Enabled = true
		hysteriaSettings.TLSMode = domain.HysteriaTLSSelfSigned
		hysteriaSettings.TLSCertIP = "8.8.8.8"
		if err := app.server.store.UpdateHysteriaSettings(t.Context(), hysteriaSettings); err != nil {
			t.Fatal(err)
		}
		response := requestJSON(t, app, "POST", "/api/clients", map[string]any{"name": "phone", "protocol": "hysteria2"}, true)
		if response.Code != 409 || !strings.Contains(response.Body.String(), "public_host must match") {
			t.Fatalf("mismatched Hysteria endpoint response = %d %s", response.Code, response.Body.String())
		}
	})
}
