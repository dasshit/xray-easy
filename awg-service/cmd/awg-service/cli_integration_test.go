package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awgapi "xray-easy/awg-contract/api/v1"
	"xray-easy/awg-service/internal/control"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type cliControl struct {
	awgapi.UnimplementedControlServer
	config string
}

func (cliControl) GetStatus(context.Context, *emptypb.Empty) (*awgapi.StatusResponse, error) {
	return &awgapi.StatusResponse{Running: true, PeerCount: 1}, nil
}
func (cliControl) ListPeers(context.Context, *emptypb.Empty) (*awgapi.ListPeersResponse, error) {
	return &awgapi.ListPeersResponse{Peers: []*awgapi.Peer{{Name: "phone"}}}, nil
}
func (cliControl) GetPeerStats(context.Context, *emptypb.Empty) (*awgapi.GetPeerStatsResponse, error) {
	return &awgapi.GetPeerStatsResponse{}, nil
}
func (cliControl) CreatePeer(context.Context, *awgapi.CreatePeerRequest) (*awgapi.Peer, error) {
	return &awgapi.Peer{Name: "phone"}, nil
}
func (cliControl) AddPeer(_ context.Context, request *awgapi.AddPeerRequest) (*awgapi.Peer, error) {
	return &awgapi.Peer{Name: request.GetName(), PublicKey: request.GetPublicKey()}, nil
}
func (cliControl) RemovePeer(_ context.Context, request *awgapi.RemovePeerRequest) (*awgapi.RemovePeerResponse, error) {
	return &awgapi.RemovePeerResponse{Removed: true, Name: request.GetName()}, nil
}
func (cliControl) GetClientConfig(context.Context, *awgapi.GetClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	return &awgapi.ClientConfigResponse{Config: "[Interface]\nPrivateKey = persisted\n[Peer]\n"}, nil
}
func (cliControl) ExportBackup(context.Context, *emptypb.Empty) (*awgapi.BackupResponse, error) {
	return &awgapi.BackupResponse{Data: []byte("backup")}, nil
}
func (cliControl) RestoreBackup(context.Context, *awgapi.RestoreBackupRequest) (*awgapi.RestoreBackupResponse, error) {
	return &awgapi.RestoreBackupResponse{Restored: true}, nil
}
func (s cliControl) RenderClientConfig(_ context.Context, request *awgapi.RenderClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	name := request.GetName()
	key := request.GetPrivateKey()
	config := s.config
	if config == "" {
		config = "[Interface]\nPrivateKey = " + key + "\nAddress = 10.88.0.2/32\n\n[Peer]\n# " + name + "\n"
	}
	return &awgapi.ClientConfigResponse{Config: config}, nil
}

type inProcessCLIClient struct{ api control.API }

func (c inProcessCLIClient) Invoke(ctx context.Context, method string, fields map[string]any) (map[string]any, error) {
	request := func(message proto.Message) error {
		data, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		return protojson.Unmarshal(data, message)
	}
	var response proto.Message
	var err error
	switch method {
	case "GetStatus":
		response, err = c.api.GetStatus(ctx, &emptypb.Empty{})
	case "ListPeers":
		response, err = c.api.ListPeers(ctx, &emptypb.Empty{})
	case "AddPeer":
		message := new(awgapi.AddPeerRequest)
		if err = request(message); err == nil {
			response, err = c.api.AddPeer(ctx, message)
		}
	case "RemovePeer":
		message := new(awgapi.RemovePeerRequest)
		if err = request(message); err == nil {
			response, err = c.api.RemovePeer(ctx, message)
		}
	case "RenderClientConfig":
		message := new(awgapi.RenderClientConfigRequest)
		if err = request(message); err == nil {
			response, err = c.api.RenderClientConfig(ctx, message)
		}
	default:
		return nil, context.Canceled
	}
	if err != nil {
		return nil, err
	}
	data, err := protojson.Marshal(response)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
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
