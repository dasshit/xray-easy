package main

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func setBootstrapEnv(t *testing.T, root string) {
	t.Helper()
	t.Setenv("XRAY_EASY_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("XRAY_EASY_CONFIG_DIR", filepath.Join(root, "xray"))
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	t.Setenv("XRAY_PUBLIC_PORT", "8443")
	t.Setenv("XRAY_VMESS_PORT", "9443")
	t.Setenv("XRAY_API_LISTEN", "127.0.0.1:10100")
	tokenPath := filepath.Join(root, "controller.token")
	if err := os.WriteFile(tokenPath, []byte("controller-test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_CONTROLLER_ADDR", "passthrough:///controller-test")
	t.Setenv("XRAY_CONTROLLER_TOKEN_FILE", tokenPath)
}

func TestInitializeControlPlaneBuildsConfiguredDependenciesAndCleanup(t *testing.T) {
	root := t.TempDir()
	setBootstrapEnv(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, cleanup, err := initializeControlPlane(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.store == nil || len(s.masterKey) != 32 || s.configDir != filepath.Join(root, "xray") || s.publicPort != 8443 || s.vmessPort != 9443 || s.dataDir != filepath.Join(root, "data") || s.maintenancePath != filepath.Join(root, "data", "maintenance.lock") || s.defaultAPIListen != "127.0.0.1:10100" || s.stats == nil || s.supervisor == nil || s.handler == nil {
		t.Fatalf("initialized control plane dependencies incomplete: %+v", s)
	}
	if info, err := os.Stat(filepath.Join(root, "xray", "candidates")); err != nil || !info.IsDir() {
		t.Fatalf("candidate directory = %v, %v", info, err)
	}
	if err := s.store.Ping(ctx); err != nil {
		t.Fatalf("initialized store ping: %v", err)
	}
	cleanup()
	if err := s.store.Ping(ctx); err == nil {
		t.Fatal("cleanup left SQLite store open")
	}
}

func TestInitializeControlPlaneReportsBootstrapFailuresAndClosesPartialResources(t *testing.T) {
	t.Run("data directory", func(t *testing.T) {
		root := t.TempDir()
		file := filepath.Join(root, "data-file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		setBootstrapEnv(t, root)
		t.Setenv("XRAY_EASY_DATA_DIR", file)
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("file used as data directory accepted")
		}
	})
	t.Run("master key", func(t *testing.T) {
		setBootstrapEnv(t, t.TempDir())
		t.Setenv("XRAY_EASY_MASTER_KEY", "")
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("missing master key accepted")
		}
	})
	t.Run("database", func(t *testing.T) {
		root := t.TempDir()
		setBootstrapEnv(t, root)
		if err := os.MkdirAll(filepath.Join(root, "data", "state.db"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("directory used as database file accepted")
		}
	})
	t.Run("config directory", func(t *testing.T) {
		root := t.TempDir()
		setBootstrapEnv(t, root)
		if err := os.WriteFile(filepath.Join(root, "xray"), []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("file used as config directory accepted")
		}
		// The opened database can be reopened after the partial startup failure closed it.
		if _, err := os.Stat(filepath.Join(root, "data", "state.db")); err != nil {
			t.Fatalf("database file missing after cleanup: %v", err)
		}
	})
	t.Run("port", func(t *testing.T) {
		root := t.TempDir()
		setBootstrapEnv(t, root)
		t.Setenv("XRAY_PUBLIC_PORT", "65536")
		if _, _, err := initializeControlPlane(context.Background()); err == nil {
			t.Fatal("invalid public port accepted")
		}
	})
}
