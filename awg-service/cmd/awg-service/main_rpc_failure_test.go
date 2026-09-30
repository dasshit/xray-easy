package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type scriptedRPC struct {
	responses map[string]map[string]any
	errors    map[string]error
	calls     []string
}

func (c *scriptedRPC) Invoke(_ context.Context, method string, _ map[string]any) (map[string]any, error) {
	c.calls = append(c.calls, method)
	if err := c.errors[method]; err != nil {
		return nil, err
	}
	if response := c.responses[method]; response != nil {
		return response, nil
	}
	if method == "RenderClientConfig" {
		return map[string]any{"config": "[Interface]\nPrivateKey = key\n[Peer]\n"}, nil
	}
	return map[string]any{"name": "phone", "removed": true}, nil
}
func (*scriptedRPC) Close() error { return nil }

func useScriptedRPC(t *testing.T, client controlRPC) {
	t.Helper()
	previous := dialControlRPC
	dialControlRPC = func() (controlRPC, error) { return client, nil }
	t.Cleanup(func() { dialControlRPC = previous })
}

func TestCLIReportsRPCFailuresAndRollsBackIncompletePeerCreation(t *testing.T) {
	emptyProfile := map[string]any{"config": ""}
	for _, test := range []struct {
		name        string
		client      *scriptedRPC
		wantMessage string
		wantRemove  bool
	}{
		{name: "add rejected", client: &scriptedRPC{errors: map[string]error{"AddPeer": errors.New("unavailable")}}, wantMessage: "add AWG peer"},
		{name: "profile render rejected", client: &scriptedRPC{errors: map[string]error{"RenderClientConfig": errors.New("render failed")}}, wantMessage: "render AWG client profile", wantRemove: true},
		{name: "empty profile", client: &scriptedRPC{responses: map[string]map[string]any{"RenderClientConfig": emptyProfile}}, wantMessage: "empty client profile", wantRemove: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("AWG_DATA_DIR", dataDir)
			useScriptedRPC(t, test.client)
			err := run([]string{"peer-add", "--name=phone"}, &strings.Builder{}, &strings.Builder{})
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("peer-add error = %v, want %q", err, test.wantMessage)
			}
			if test.wantRemove && (len(test.client.calls) != 3 || test.client.calls[2] != "RemovePeer") {
				t.Fatalf("incomplete peer creation was not rolled back: %v", test.client.calls)
			}
		})
	}
	t.Run("private profile file collision", func(t *testing.T) {
		dataDir := t.TempDir()
		profileDir := filepath.Join(dataDir, "profiles")
		if err := os.MkdirAll(profileDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(profileDir, "phone.conf"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWG_DATA_DIR", dataDir)
		client := &scriptedRPC{}
		useScriptedRPC(t, client)
		if err := run([]string{"peer-add", "--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "create profile securely") {
			t.Fatalf("profile file collision error = %v", err)
		}
		if client.calls[len(client.calls)-1] != "RemovePeer" {
			t.Fatalf("peer was not rolled back after profile collision: %v", client.calls)
		}
	})
}

func TestCLIReportsRefreshRemovalAndHealthFailures(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("AWG_DATA_DIR", dataDir)
	profileDir := filepath.Join(dataDir, "profiles")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(profileDir, "phone.conf")
	if err := os.WriteFile(profilePath, []byte("[Interface]\nAddress = 10.88.0.2/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"profile", "--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "no Interface PrivateKey") {
		t.Fatalf("profile without private key error = %v", err)
	}
	if err := os.WriteFile(profilePath, []byte("[Interface]\nPrivateKey = key\n[Peer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	renderFailure := &scriptedRPC{errors: map[string]error{"RenderClientConfig": errors.New("offline")}}
	useScriptedRPC(t, renderFailure)
	if err := run([]string{"profile", "--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "render refreshed AWG profile") {
		t.Fatalf("refresh RPC error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(profileDir, "bad.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "bad.conf", "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeFailure := &scriptedRPC{}
	useScriptedRPC(t, removeFailure)
	if err := run([]string{"peer-remove", "--name=bad"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "could not be deleted") {
		t.Fatalf("profile deletion error = %v", err)
	}
	serviceFailure := &scriptedRPC{errors: map[string]error{"GetStatus": errors.New("offline")}}
	useScriptedRPC(t, serviceFailure)
	if err := run([]string{"health"}, &strings.Builder{}, &strings.Builder{}); err == nil {
		t.Fatal("health command ignored a failed status call")
	}
	if err := printRPC("ListPeers", nil, &strings.Builder{}); err != nil {
		t.Fatalf("list-peers RPC = %v", err)
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func TestCLIReportsTransportOutputAndOptionalProfileRemovalPaths(t *testing.T) {
	t.Run("peer-remove RPC rejected", func(t *testing.T) {
		client := &scriptedRPC{errors: map[string]error{"RemovePeer": errors.New("offline")}}
		useScriptedRPC(t, client)
		if err := run([]string{"peer-remove", "--name=phone"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "offline") {
			t.Fatalf("peer-remove error = %v", err)
		}
	})
	t.Run("profile remove succeeds when local copy is already absent", func(t *testing.T) {
		t.Setenv("AWG_DATA_DIR", t.TempDir())
		client := &scriptedRPC{}
		useScriptedRPC(t, client)
		if err := run([]string{"peer-remove", "--name=phone"}, &strings.Builder{}, &strings.Builder{}); err != nil {
			t.Fatalf("peer-remove with no local file: %v", err)
		}
	})
	t.Run("RPC response output errors propagate", func(t *testing.T) {
		useScriptedRPC(t, &scriptedRPC{})
		if err := printRPC("GetStatus", nil, failedOutput{}); err == nil || !strings.Contains(err.Error(), "output failed") {
			t.Fatalf("printRPC output error = %v", err)
		}
		if err := removePeer([]string{"--name=phone"}, failedOutput{}); err == nil || !strings.Contains(err.Error(), "output failed") {
			t.Fatalf("peer-remove output error = %v", err)
		}
	})
	t.Run("missing profile after remove is harmless", func(t *testing.T) {
		if err := removeSavedProfile(t.TempDir(), "phone"); err != nil {
			t.Fatalf("remove absent profile: %v", err)
		}
	})
}

func TestServeValidConfigurationReachesKernelInitialization(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("AWG_MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	t.Setenv("AWG_DATA_DIR", dataDir)
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("AWG_CONTROL_TOKEN_FILE", filepath.Join(dataDir, "control.token"))
	t.Setenv("AWG_GRPC_LISTEN", "127.0.0.1:0")
	err := serve()
	if err == nil || !(strings.Contains(err.Error(), "create AmneziaWG device") || strings.Contains(err.Error(), "requires Linux")) {
		t.Fatalf("serve should reach the TUN-backed device creation stage in an unprivileged test: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, "control.token")); statErr != nil {
		t.Fatalf("serve did not initialize its authenticated control token: %v", statErr)
	}
}
