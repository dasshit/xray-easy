package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"google.golang.org/grpc"
	"xray-easy/awg-service/internal/control"
)

func TestRunUsesServeForDefaultAndExplicitServeCommands(t *testing.T) {
	t.Setenv("AWG_MASTER_KEY", "")
	for _, args := range [][]string{nil, {"serve"}} {
		if err := run(args, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "AWG_MASTER_KEY") {
			t.Errorf("run(%v) error = %v, want configuration error from serve", args, err)
		}
	}
}

func TestCommandRPCDialAndInvocationFailures(t *testing.T) {
	t.Run("dial failures", func(t *testing.T) {
		previous := dialControlRPC
		dialControlRPC = func() (controlRPC, error) { return nil, errors.New("injected dial failure") }
		t.Cleanup(func() { dialControlRPC = previous })
		if err := printRPC("GetStatus", nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "injected dial failure") {
			t.Errorf("printRPC dial error = %v", err)
		}
		if err := checkHealth(); err == nil || !strings.Contains(err.Error(), "injected dial failure") {
			t.Errorf("checkHealth dial error = %v", err)
		}
		if err := removePeer([]string{"--name=phone"}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "injected dial failure") {
			t.Errorf("removePeer dial error = %v", err)
		}
		if err := addPeer([]string{"--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "injected dial failure") {
			t.Errorf("addPeer dial error = %v", err)
		}
	})

	t.Run("print RPC invocation failure", func(t *testing.T) {
		client := &scriptedRPC{errors: map[string]error{"GetStatus": errors.New("injected RPC failure")}}
		useScriptedRPC(t, client)
		if err := printRPC("GetStatus", nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "injected RPC failure") {
			t.Fatalf("printRPC invocation error = %v", err)
		}
	})
}

func TestAddPeerAndRefreshProfileReportOutputAndEmptyConfigFailures(t *testing.T) {
	t.Run("add profile JSON output failure", func(t *testing.T) {
		t.Setenv("AWG_DATA_DIR", t.TempDir())
		useScriptedRPC(t, &scriptedRPC{})
		if err := addPeer([]string{"--name=phone"}, failedOutput{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "output failed") {
			t.Fatalf("addPeer output error = %v", err)
		}
	})

	profileDir := filepath.Join(t.TempDir(), "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWG_DATA_DIR", filepath.Dir(profileDir))
	profilePath := filepath.Join(profileDir, "phone.conf")
	if err := os.WriteFile(profilePath, []byte("[Interface]\nPrivateKey = client-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("empty rendered config", func(t *testing.T) {
		useScriptedRPC(t, &scriptedRPC{responses: map[string]map[string]any{"RenderClientConfig": {"config": ""}}})
		if err := refreshProfile([]string{"--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "empty client profile") {
			t.Fatalf("refreshProfile empty-config error = %v", err)
		}
	})
	t.Run("profile JSON output failure", func(t *testing.T) {
		useScriptedRPC(t, &scriptedRPC{})
		if err := refreshProfile([]string{"--name=phone"}, failedOutput{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "output failed") {
			t.Fatalf("refreshProfile output error = %v", err)
		}
	})
}

func setValidServeEnvironment(t *testing.T, dataDir string) {
	t.Helper()
	t.Setenv("AWG_MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("AWG_PUBLIC_PORT", "1234")
	t.Setenv("AWG_LISTEN_PORT", "51820")
	t.Setenv("AWG_DATA_DIR", dataDir)
	t.Setenv("AWG_CONTROL_TOKEN_FILE", filepath.Join(dataDir, "control.token"))
	t.Setenv("AWG_GRPC_LISTEN", "127.0.0.1:0")
}

func TestServeReportsTokenAndManagerInitializationFailures(t *testing.T) {
	t.Run("token file is unreadable as a file", func(t *testing.T) {
		dataDir := t.TempDir()
		setValidServeEnvironment(t, dataDir)
		tokenPath := filepath.Join(dataDir, "control.token")
		if err := os.Mkdir(tokenPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := serve(); err == nil || !strings.Contains(err.Error(), "read AWG control token") {
			t.Fatalf("serve token error = %v", err)
		}
	})

	t.Run("manager cannot open", func(t *testing.T) {
		dataDir := t.TempDir()
		setValidServeEnvironment(t, dataDir)
		previous := openControlManager
		openControlManager = func(control.Options, control.DeviceFactory) (*control.Manager, error) {
			return nil, errors.New("injected manager failure")
		}
		t.Cleanup(func() { openControlManager = previous })
		if err := serve(); err == nil || !strings.Contains(err.Error(), "injected manager failure") {
			t.Fatalf("serve manager error = %v", err)
		}
	})
}

func TestServeRunsAndShutsDownAfterConfigurationLoads(t *testing.T) {
	dataDir := t.TempDir()
	setValidServeEnvironment(t, dataDir)
	options := control.Options{
		DataDir: dataDir, MasterKey: make([]byte, 32), PublicHost: "vpn.example.test",
		PublicPort: 1234, ListenPort: 51820,
		IPv4Prefix: netip.MustParsePrefix("10.88.0.0/24"),
		IPv6Prefix: netip.MustParsePrefix("fd88:88:88::/64"),
	}
	manager, err := control.Open(options, inertAWGFactory{})
	if err != nil {
		t.Fatal(err)
	}
	previousOpen, previousListen, previousSignal := openControlManager, listenControl, signalNotify
	openControlManager = func(got control.Options, _ control.DeviceFactory) (*control.Manager, error) {
		if got.PublicHost != options.PublicHost {
			t.Errorf("manager options host = %q, want %q", got.PublicHost, options.PublicHost)
		}
		return manager, nil
	}
	listener := newScriptedListener(nil)
	listenControl = func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "127.0.0.1:0" {
			t.Errorf("listenControl(%q, %q) used unexpected endpoint", network, address)
		}
		return listener, nil
	}
	signalNotify = func(channel chan<- os.Signal) { channel <- syscall.SIGTERM }
	t.Cleanup(func() {
		openControlManager, listenControl, signalNotify = previousOpen, previousListen, previousSignal
		_ = listener.Close()
		manager.Close()
	})

	if err := serve(); err != nil {
		t.Fatalf("serve() = %v", err)
	}
	_, publicKey, err := control.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("closed", publicKey); err == nil || !strings.Contains(err.Error(), "manager is closed") {
		t.Fatalf("serve() left the manager open after shutdown: %v", err)
	}
}

func TestServeControlServerTreatsStoppedServerAsNormalShutdown(t *testing.T) {
	server := grpc.NewServer()
	server.Stop()
	listener := newScriptedListener(nil)
	defer listener.Close()
	if err := serveControlServer(server, listener, make(chan os.Signal)); err != nil {
		t.Fatalf("stopped server returned error: %v", err)
	}
}
