package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
)

type oneReadRandomThenFailure struct{ used bool }

func (r *oneReadRandomThenFailure) Read(value []byte) (int, error) {
	if r.used {
		return 0, errors.New("staged entropy exhausted")
	}
	r.used = true
	for index := range value {
		value[index] = byte(index + 1)
	}
	return len(value), nil
}

func TestCreateProtocolClientReportsPreparationAndPersistenceFailures(t *testing.T) {
	t.Parallel()
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
			_, err = app.server.createProtocolClient(t.Context(), settings, test.protocol, test.profile, "", "", nil, app.admin.ID)
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
		_, err = app.server.createProtocolClient(ctx, settings, "", "phone", "", "", nil, app.admin.ID)
		if err == nil {
			t.Fatal("profile creation proceeded while maintenance lock was held")
		}
	})
}

func TestCreateProtocolClientPropagatesCredentialEntropyFailures(t *testing.T) {
	for _, protocol := range []domain.ClientProtocol{
		domain.ProtocolVLESS,
		domain.ProtocolVMess,
		domain.ProtocolHysteria2,
		domain.ProtocolShadowsocks,
		domain.ProtocolTrojan,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			app := newTestApp(t, true)
			settings, err := app.server.store.GetSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			previous := rand.Reader
			rand.Reader = &oneReadRandomThenFailure{}
			t.Cleanup(func() { rand.Reader = previous })
			if _, err := app.server.createProtocolClient(t.Context(), settings, protocol, "entropy-phone", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "staged entropy exhausted") {
				t.Fatalf("createProtocolClient(%s) entropy error = %v", protocol, err)
			}
		})
	}
}

func TestCreateProtocolClientPropagatesProfileIDEntropyFailure(t *testing.T) {
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	previous := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = previous })

	if _, err := app.server.createProtocolClient(t.Context(), settings, domain.ProtocolVMess, "entropy-phone", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("createProtocolClient() entropy error = %v, want random source failure", err)
	}
}

func TestCreateTrojanClientReportsPasswordEncryptionFailure(t *testing.T) {
	t.Setenv("XRAY_TROJAN_ENABLED", "true")
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	app.server.masterKey = []byte("too-short")

	if _, err := app.server.createProtocolClient(t.Context(), settings, domain.ProtocolTrojan, "encryption-phone", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "encrypt Trojan password") {
		t.Fatalf("createProtocolClient(Trojan) encryption error = %v", err)
	}
}

func TestCreateProtocolClientRollsBackPersistedProfilesOnPreparationFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol domain.ClientProtocol
		setup    func(*testing.T, testApp)
		want     string
	}{
		{
			name: "reserved short ID storage unavailable", protocol: domain.ProtocolVMess,
			setup: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "drop reserved short IDs", `DROP TABLE reality_short_ids`)
			},
			want: "list reserved REALITY short IDs",
		},
		{
			name: "REALITY key cannot be decrypted", protocol: domain.ProtocolVMess,
			setup: func(t *testing.T, app testApp) {
				execSQLiteTestMutation(t, app, "corrupt REALITY key", `UPDATE settings SET reality_private_key_enc='invalid' WHERE id=1`)
			},
			want: "could not decrypt REALITY private key",
		},
		{
			name: "candidate validation rejected", protocol: domain.ProtocolVMess,
			setup: func(_ *testing.T, app testApp) { app.sup.validateErr = errors.New("candidate rejected") },
			want:  "candidate rejected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			test.setup(t, app)
			settings, err := app.server.store.GetSettings(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, err = app.server.createProtocolClient(t.Context(), settings, test.protocol, "rollback-phone", "", "", nil, app.admin.ID)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("createProtocolClient() error = %v, want %q", err, test.want)
			}
			clients, listErr := app.server.store.ListClients(t.Context())
			if listErr != nil || len(clients) != 0 {
				t.Fatalf("failed profile creation left clients behind: count=%d err=%v", len(clients), listErr)
			}
		})
	}
}

func TestCreateVLESSClientRollsBackLiveUserWhenConfigPromotionFails(t *testing.T) {
	app := newTestApp(t, true)
	first := createRuntimeTestClient(t, app, "first-phone")
	activePath := filepath.Join(app.server.configDir, "active.json")
	app.handler.afterAdd = func() {
		if err := os.Remove(activePath); err != nil {
			t.Errorf("remove active config during live add: %v", err)
			return
		}
		if err := os.Mkdir(activePath, 0o700); err != nil {
			t.Errorf("replace active config with directory: %v", err)
		}
	}

	response := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Name: "second-phone"}, true)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "promote Xray config") {
		t.Fatalf("profile creation with failed config promotion = %d %s", response.Code, response.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 1 || clients[0].ID != first.ID {
		t.Fatalf("profiles after failed promotion = %+v, %v", clients, err)
	}
	app.handler.mu.Lock()
	users := append([]string(nil), app.handler.users...)
	app.handler.mu.Unlock()
	if len(users) != 0 {
		t.Fatalf("live users after failed promotion = %v, want the newly added user rolled back", users)
	}
}

func TestCreateProtocolClientReportsClosedStoreBeforeGeneratingCredentials(t *testing.T) {
	app := newTestApp(t, true)
	settings, err := app.server.store.GetSettings(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := app.server.store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.server.createProtocolClient(t.Context(), settings, domain.ProtocolVMess, "phone", "", "", nil, app.admin.ID); err == nil || !strings.Contains(err.Error(), "list clients") {
		t.Fatalf("createProtocolClient() with closed store = %v", err)
	}
}

func TestApplyRestoredStateRequiresControllerAddress(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	app := newTestApp(t, false)

	err := applyRestoredState(t.Context(), app.server.store, app.server.masterKey, app.server.configDir, 443)
	if err == nil || !strings.Contains(err.Error(), "XRAY_CONTROLLER_ADDR must be configured") {
		t.Fatalf("applyRestoredState() error = %v, want missing Controller address", err)
	}
}

func TestDialRuntimeControlReportsControllerTokenReadFailure(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-controller.token"))

	client, closeClient, err := dialRuntimeControl()
	if err == nil || client != nil || closeClient != nil || !strings.Contains(err.Error(), "initialize Controller gRPC client") {
		t.Fatalf("dialRuntimeControl() = client %v, close %v, error %v", client, closeClient != nil, err)
	}
}
