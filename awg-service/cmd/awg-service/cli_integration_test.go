package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
	"xray-easy/awg-service/internal/control"
)

type cliControl struct {
	config string
}

func (cliControl) GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"running": true, "peerCount": 1})
}
func (cliControl) ListPeers(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"peers": []any{map[string]any{"name": "phone"}}})
}
func (cliControl) GetPeerStats(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"peers": []any{}})
}
func (cliControl) CreatePeer(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"name": "phone"})
}
func (cliControl) AddPeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"name": request.GetFields()["name"].GetStringValue(), "publicKey": request.GetFields()["publicKey"].GetStringValue()})
}
func (cliControl) RemovePeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"removed": true, "name": request.GetFields()["name"].GetStringValue()})
}
func (cliControl) GetClientConfig(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"config": "[Interface]\nPrivateKey = persisted\n[Peer]\n"})
}
func (cliControl) ExportBackup(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"snapshot": "backup"})
}
func (cliControl) RestoreBackup(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"restored": true})
}
func (s cliControl) RenderClientConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	name := request.GetFields()["name"].GetStringValue()
	key := request.GetFields()["privateKey"].GetStringValue()
	config := s.config
	if config == "" {
		config = "[Interface]\nPrivateKey = " + key + "\nAddress = 10.88.0.2/32\n\n[Peer]\n# " + name + "\n"
	}
	return structpb.NewStruct(map[string]any{"config": config})
}

type inProcessCLIClient struct{ api control.API }

func (c inProcessCLIClient) Invoke(ctx context.Context, method string, fields map[string]any) (*structpb.Struct, error) {
	request, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, err
	}
	switch method {
	case "GetStatus":
		return c.api.GetStatus(ctx, request)
	case "ListPeers":
		return c.api.ListPeers(ctx, request)
	case "AddPeer":
		return c.api.AddPeer(ctx, request)
	case "RemovePeer":
		return c.api.RemovePeer(ctx, request)
	case "RenderClientConfig":
		return c.api.RenderClientConfig(ctx, request)
	default:
		return nil, context.Canceled
	}
}
func (inProcessCLIClient) Close() error { return nil }

func startCLIControl(t *testing.T, api control.API) string {
	t.Helper()
	previousDial := dialControlRPC
	dialControlRPC = func() (controlRPC, error) { return inProcessCLIClient{api: api}, nil }
	t.Cleanup(func() { dialControlRPC = previousDial })
	t.Setenv("AWG_DATA_DIR", t.TempDir())
	return os.Getenv("AWG_DATA_DIR")
}

func TestCLICommandsCallAuthenticatedAWGServiceAndManageProfiles(t *testing.T) {
	dataDir := startCLIControl(t, cliControl{})
	for _, command := range [][]string{{"health"}, {"status"}, {"peer-list"}} {
		var output strings.Builder
		if err := run(command, &output, &strings.Builder{}); err != nil {
			t.Fatalf("run %v: %v", command, err)
		}
		if command[0] != "health" && output.Len() == 0 {
			t.Errorf("run %v returned no output", command)
		}
	}
	var output strings.Builder
	if err := run([]string{"peer-add", "--name=phone"}, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(output.String()), &created); err != nil {
		t.Fatalf("peer-add JSON = %q: %v", output.String(), err)
	}
	profilePath := filepath.Join(dataDir, "profiles", "phone.conf")
	profile, err := os.ReadFile(profilePath)
	if err != nil || !strings.Contains(string(profile), "PrivateKey = ") {
		t.Fatalf("peer-add profile = %q, %v", profile, err)
	}
	if info, err := os.Stat(profilePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("peer-add profile permissions = %v, %v", info, err)
	}
	output.Reset()
	if err := run([]string{"profile", "--name=phone"}, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	refreshed, err := os.ReadFile(profilePath)
	if err != nil || !strings.Contains(string(refreshed), "# phone") || strings.Contains(string(refreshed), "persisted") {
		t.Fatalf("refreshed profile = %q, %v", refreshed, err)
	}
	output.Reset()
	if err := run([]string{"peer-remove", "--name=phone"}, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("peer-remove retained the private profile: %v", err)
	}
	output.Reset()
	if err := run([]string{"keygen"}, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	var keypair map[string]string
	if err := json.Unmarshal([]byte(output.String()), &keypair); err != nil || keypair["privateKey"] == "" || keypair["publicKey"] == "" {
		t.Fatalf("keygen output = %q (%v)", output.String(), err)
	}
}

func TestCLICommandsValidateArgumentsAndConfiguration(t *testing.T) {
	if err := run([]string{"unknown"}, &strings.Builder{}, &strings.Builder{}); err == nil {
		t.Fatal("unknown command was accepted")
	}
	for _, args := range [][]string{{"peer-add"}, {"peer-add", "--unknown"}, {"peer-remove"}, {"profile"}, {"profile", "--name=../outside"}} {
		if err := run(args, &strings.Builder{}, &strings.Builder{}); err == nil {
			t.Errorf("invalid command arguments were accepted: %v", args)
		}
	}
	t.Setenv("AWG_DATA_DIR", t.TempDir())
	if err := run([]string{"profile", "--name=missing"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "read saved client profile") {
		t.Fatalf("missing profile error = %v", err)
	}
	for _, key := range []string{"", "not-base64", "AA=="} {
		t.Setenv("AWG_MASTER_KEY", key)
		if _, err := optionsFromEnvironment(); err == nil {
			t.Errorf("invalid master key %q was accepted", key)
		}
	}
	t.Setenv("AWG_MASTER_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	for variable, value := range map[string]string{"AWG_PUBLIC_PORT": "0", "AWG_LISTEN_PORT": "65536"} {
		t.Setenv(variable, value)
		if _, err := optionsFromEnvironment(); err == nil {
			t.Errorf("invalid port %s=%s was accepted", variable, value)
		}
	}
	t.Setenv("AWG_PUBLIC_PORT", "1234")
	t.Setenv("AWG_LISTEN_PORT", "51820")
	t.Setenv("AWG_IPV4_POOL", "bad")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("invalid IPv4 pool was accepted")
	}
	t.Setenv("AWG_IPV4_POOL", "10.0.0.0/24")
	t.Setenv("AWG_IPV6_POOL", "bad")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("invalid IPv6 pool was accepted")
	}
	t.Setenv("AWG_IPV6_POOL", "fd00::/64")
	t.Setenv("AWG_DNS_SERVERS", "1.1.1.1,invalid")
	if _, err := optionsFromEnvironment(); err == nil {
		t.Fatal("invalid DNS address was accepted")
	}
	t.Setenv("AWG_DNS_SERVERS", "1.1.1.1, ,2606:4700:4700::1111")
	t.Setenv("AWG_PUBLIC_HOST", " vpn.example.test ")
	t.Setenv("AWG_INTERFACE", "awg-test")
	t.Setenv("AWG_JC", " 4 ")
	opts, err := optionsFromEnvironment()
	if err != nil || opts.PublicPort != 1234 || opts.ListenPort != 51820 || opts.PublicHost != "vpn.example.test" || opts.InterfaceName != "awg-test" || len(opts.DNS) != 2 || opts.Obfuscation["jc"] != "4" {
		t.Fatalf("valid environment options = %+v, %v", opts, err)
	}
}
