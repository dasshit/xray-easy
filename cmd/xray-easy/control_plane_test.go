package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/stats"
	"xray-easy/internal/store"
)

func configureControlPlaneEnvironment(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	configDir := filepath.Join(root, "xray")
	t.Setenv("XRAY_EASY_DATA_DIR", dataDir)
	t.Setenv("XRAY_EASY_CONFIG_DIR", configDir)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	t.Setenv("XRAY_PUBLIC_PORT", "443")
	t.Setenv("XRAY_VMESS_PORT", "9443")
	t.Setenv("XRAY_EASY_UI_PORT", "8080")
	t.Setenv("XRAY_API_LISTEN", "passthrough:///xray-api-test")
	t.Setenv("XRAY_HYSTERIA2_ENABLED", "false")
	tokenPath := filepath.Join(root, "controller.token")
	if err := os.WriteFile(tokenPath, []byte("controller-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
	t.Setenv("AWG_PUBLIC_HOST", "")
	t.Setenv("AWG_CONTROL_ADDR", "")
	return dataDir, configDir
}

func TestInitializeControlPlaneBuildsAndCleansRuntime(t *testing.T) {
	dataDir, configDir := configureControlPlaneEnvironment(t)
	runtime, cleanup, err := initializeControlPlane(context.Background())
	if err != nil {
		t.Fatalf("initializeControlPlane: %v", err)
	}
	if runtime.store == nil || runtime.stats == nil || runtime.handler == nil || runtime.awg != nil || runtime.configDir != configDir || runtime.dataDir != dataDir || runtime.publicPort != 443 || runtime.vmessPort != 9443 {
		t.Fatalf("initialized runtime fields = %+v", runtime)
	}
	if _, err := os.Stat(filepath.Join(configDir, "candidates")); err != nil {
		t.Fatalf("candidate directory was not prepared: %v", err)
	}
	if _, err := runtime.store.GetHysteriaSettings(t.Context()); err != nil {
		t.Fatalf("Hysteria settings were not initialized: %v", err)
	}
	cleanup()
	if err := runtime.store.Ping(context.Background()); err == nil {
		t.Fatal("runtime cleanup left the SQLite handle open")
	}
}

func TestInitializeControlPlaneRejectsFilesystemPortsAndAWGConfiguration(t *testing.T) {
	t.Run("data directory is a file", func(t *testing.T) {
		root := t.TempDir()
		block := filepath.Join(root, "data")
		if err := os.WriteFile(block, []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XRAY_EASY_DATA_DIR", block)
		t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("control plane initialized below a regular file")
		}
	})
	t.Run("missing master key", func(t *testing.T) {
		configureControlPlaneEnvironment(t)
		t.Setenv("XRAY_EASY_MASTER_KEY", "")
		if _, _, err := initializeControlPlane(context.Background()); err == nil || !strings.Contains(err.Error(), "XRAY_EASY_MASTER_KEY") {
			t.Fatalf("missing master key error = %v", err)
		}
	})
	t.Run("invalid VMess port closes database", func(t *testing.T) {
		dataDir, _ := configureControlPlaneEnvironment(t)
		t.Setenv("XRAY_VMESS_PORT", "443")
		if _, _, err := initializeControlPlane(context.Background()); err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("invalid VMess port error = %v", err)
		}
		db, err := store.Open(context.Background(), filepath.Join(dataDir, "state.db"))
		if err != nil {
			t.Fatalf("failed initialization did not release database: %v", err)
		}
		_ = db.Close()
	})
	t.Run("Controller token inspection failure", func(t *testing.T) {
		dataDir, _ := configureControlPlaneEnvironment(t)
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		blocked := filepath.Join(dataDir, "not-a-directory")
		if err := os.WriteFile(blocked, []byte("block"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", filepath.Join(blocked, "token"))
		if _, _, err := initializeControlPlane(context.Background()); err == nil || !strings.Contains(err.Error(), "initialize Controller gRPC client") {
			t.Fatalf("Controller token inspection error = %v", err)
		}
	})
	t.Run("AWG token is not exposed to backend", func(t *testing.T) {
		configureControlPlaneEnvironment(t)
		t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
		t.Setenv("AWG_CONTROL_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-token"))
		runtime, cleanup, err := initializeControlPlane(context.Background())
		if err != nil {
			t.Fatalf("initialize without a direct AWG token: %v", err)
		}
		defer cleanup()
		if runtime.awg == nil {
			t.Fatal("Controller-backed AWG gateway was not configured")
		}
	})
}

func TestDialRuntimeControlRequiresAndOpensController(t *testing.T) {
	t.Setenv("XRAY_CONTROLLER_ADDR", "")
	if _, _, err := dialRuntimeControl(); err == nil || !strings.Contains(err.Error(), "direct runtime connections from the backend are disabled") {
		t.Fatalf("missing Controller address error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "controller.token")
	if err := os.WriteFile(path, []byte("controller-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", path)
	client, closeClient, err := dialRuntimeControl()
	if err != nil {
		t.Fatalf("dial Controller runtime: %v", err)
	}
	if client == nil || closeClient == nil {
		t.Fatal("Controller client or cleanup function is nil")
	}
	if err := closeClient(); err != nil {
		t.Fatalf("close Controller client: %v", err)
	}
}

func TestRunControlPlaneCleansRuntimeAndHandlesListenerResults(t *testing.T) {
	for _, test := range []struct {
		name      string
		listenErr error
		wantErr   bool
	}{
		{name: "normal close"},
		{name: "server closed", listenErr: http.ErrServerClosed},
		{name: "listener failure", listenErr: errors.New("listen failed"), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newTestApp(t, true)
			app.server.stats = stats.NewManager(app.server.store, fixedStatsAPI{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cleanupCalled := false
			err := runControlPlane(ctx, func(context.Context) (*server, func(), error) {
				return app.server, func() { cleanupCalled = true }, nil
			}, func(serverHTTP *http.Server) error {
				if serverHTTP.Addr != "127.0.0.1:8080" || serverHTTP.Handler == nil || serverHTTP.ReadHeaderTimeout == 0 || serverHTTP.ReadTimeout == 0 {
					t.Fatalf("HTTP server configuration = %+v", serverHTTP)
				}
				cancel()
				return test.listenErr
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("runControlPlane() error = %v, wantErr=%v", err, test.wantErr)
			}
			if !cleanupCalled {
				t.Fatal("runControlPlane did not release initialized runtime")
			}
		})
	}

	initErr := errors.New("initialization failed")
	listenCalled := false
	err := runControlPlane(t.Context(), func(context.Context) (*server, func(), error) {
		return nil, nil, initErr
	}, func(*http.Server) error {
		listenCalled = true
		return nil
	})
	if !errors.Is(err, initErr) || listenCalled {
		t.Fatalf("initialization failure = %v, listenCalled=%v", err, listenCalled)
	}
}
