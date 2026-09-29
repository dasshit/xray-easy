package control

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"net/netip"
)

type fakeDevice struct {
	sets   []string
	ups    int
	closed bool
}

func (d *fakeDevice) Set(config string) error {
	d.sets = append(d.sets, config)
	return nil
}
func (d *fakeDevice) Up() error                 { d.ups++; return nil }
func (d *fakeDevice) Snapshot() (string, error) { return "", nil }
func (d *fakeDevice) Close()                    { d.closed = true }

type fakeFactory struct{ device *fakeDevice }

func (f fakeFactory) Open(string, int) (Device, error) { return f.device, nil }

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		DataDir: t.TempDir(), MasterKey: bytes.Repeat([]byte{0x5a}, 32), PublicHost: "vpn.example.test", PublicPort: 51820, ListenPort: 51820,
		IPv4Prefix:    netip.MustParsePrefix("10.88.0.0/29"),
		IPv6Prefix:    netip.MustParsePrefix("fd88:88:88::/64"),
		DNS:           []string{"1.1.1.1", "2606:4700:4700::1111"},
		InterfaceName: "awg0",
		Obfuscation:   map[string]string{"jc": "4", "jmin": "40", "jmax": "70", "h1": "123456"},
	}
}

func TestGenerateKeypairProducesMatchingPublicKey(t *testing.T) {
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, derived, err := derivePublicKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if derived != publicKey {
		t.Fatalf("derived public key %q does not match generated key %q", derived, publicKey)
	}
}

func TestAddPeerAppliesLiveAndPersistsAllocatedAddresses(t *testing.T) {
	opts := testOptions(t)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if device.ups != 1 {
		t.Fatalf("engine starts = %d, want 1", device.ups)
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := manager.AddPeer("iphone-1", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if peer.IPv4 != "10.88.0.2" || peer.IPv6 != "fd88:88:88::2" {
		t.Fatalf("unexpected allocation: %+v", peer)
	}
	if device.ups != 1 {
		t.Fatalf("adding peer restarted engine %d times", device.ups-1)
	}
	if len(device.sets) != 2 || !strings.Contains(device.sets[1], "public_key=") || !strings.Contains(device.sets[1], "allowed_ip=10.88.0.2/32") {
		t.Fatalf("live peer UAPI was not applied: %#v", device.sets)
	}
	profile, err := manager.RenderClientConfig("iphone-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"PrivateKey = " + privateKey,
		"Address = 10.88.0.2/32, fd88:88:88::2/128",
		"DNS = 1.1.1.1, 2606:4700:4700::1111",
		"Jc = 4", "Jmin = 40", "H1 = 123456",
		"AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = vpn.example.test:51820",
	} {
		if !strings.Contains(profile, expected) {
			t.Errorf("profile missing %q:\n%s", expected, profile)
		}
	}
	stateInfo, err := os.Stat(filepath.Join(opts.DataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0600 {
		t.Errorf("state mode = %04o, want 0600", stateInfo.Mode().Perm())
	}
	if strings.Contains(string(mustRead(t, filepath.Join(opts.DataDir, "state.json"))), privateKey) {
		t.Fatal("client private key was persisted in server state")
	}
	if strings.Contains(string(mustRead(t, filepath.Join(opts.DataDir, "state.json"))), manager.serverPrivateKey) {
		t.Fatal("server private key was not encrypted in persistent state")
	}
}

func TestRemovePeerIsAppliedLiveAndRestoredAfterReopen(t *testing.T) {
	opts := testOptions(t)
	firstDevice := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: firstDevice})
	if err != nil {
		t.Fatal(err)
	}
	_, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("macbook", publicKey); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemovePeer("macbook"); err != nil {
		t.Fatal(err)
	}
	if len(manager.Peers()) != 0 || !strings.Contains(firstDevice.sets[len(firstDevice.sets)-1], "remove=true") {
		t.Fatalf("peer was not removed live: %+v / %#v", manager.Peers(), firstDevice.sets)
	}
	manager.Close()
	secondDevice := &fakeDevice{}
	secondManager, err := Open(opts, fakeFactory{device: secondDevice})
	if err != nil {
		t.Fatal(err)
	}
	defer secondManager.Close()
	if len(secondManager.Peers()) != 0 {
		t.Fatalf("removed peer returned after process restart: %+v", secondManager.Peers())
	}
	if len(secondDevice.sets) != 1 {
		t.Fatalf("removed peer unexpectedly restored: %#v", secondDevice.sets)
	}
}

func TestManagerRejectsDuplicateAndInvalidPeer(t *testing.T) {
	device := &fakeDevice{}
	manager, err := Open(testOptions(t), fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	_, publicKey, _ := GenerateKeypair()
	if _, err := manager.AddPeer("bad name", publicKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid name error = %v", err)
	}
	if _, err := manager.AddPeer("iphone", "not-a-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid key error = %v", err)
	}
	if _, err := manager.AddPeer("iphone", publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("iphone", publicKey); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := manager.RenderClientConfig("iphone", "not-a-key"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid profile key error = %v", err)
	}
	otherPrivate, _, _ := GenerateKeypair()
	if _, err := manager.RenderClientConfig("iphone", otherPrivate); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched profile key error = %v", err)
	}
}

func TestAddressPoolDoesNotAllocateNetworkGatewayOrBroadcast(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, want := range []string{"10.88.0.2", "10.88.0.3", "10.88.0.4", "10.88.0.5", "10.88.0.6"} {
		_, pub, _ := GenerateKeypair()
		peer, err := manager.AddPeer("peer"+strings.ReplaceAll(want, ".", ""), pub)
		if err != nil {
			t.Fatalf("allocate %s: %v", want, err)
		}
		if peer.IPv4 != want {
			t.Errorf("allocated %s, want %s", peer.IPv4, want)
		}
	}
	_, pub, _ := GenerateKeypair()
	if _, err := manager.AddPeer("full", pub); !errors.Is(err, ErrInvalid) {
		t.Fatalf("exhausted pool error = %v", err)
	}
}

func TestLoadOrCreateTokenIsPersistentAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.token")
	first, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("token changed between loads")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("token mode = %04o, want 0640", info.Mode().Perm())
	}
}

func TestEncryptedServerKeyRequiresOriginalMasterKey(t *testing.T) {
	opts := testOptions(t)
	manager, err := Open(opts, fakeFactory{device: &fakeDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	opts.MasterKey = bytes.Repeat([]byte{0xa5}, 32)
	if _, err := Open(opts, fakeFactory{device: &fakeDevice{}}); err == nil || !strings.Contains(err.Error(), "decrypt persisted AWG server key") {
		t.Fatalf("wrong master key error = %v", err)
	}
}

func TestOptionsRejectHostInjectionAndInvalidObfuscation(t *testing.T) {
	for _, mutate := range []func(*Options){
		func(opts *Options) { opts.PublicHost = "vpn.example\n[Peer]" },
		func(opts *Options) { opts.InterfaceName = "interface-name-too-long" },
		func(opts *Options) { opts.Obfuscation = map[string]string{"jc": "4\nremove=true"} },
		func(opts *Options) { opts.Obfuscation = map[string]string{"made-up": "1"} },
		func(opts *Options) { opts.Obfuscation = map[string]string{"header_protection_key": "not-a-key"} },
	} {
		opts := testOptions(t)
		mutate(&opts)
		if err := opts.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("validate error = %v, want invalid", err)
		}
	}
}

func TestHeaderProtectionUsesHexInUAPIAndBase64InClientProfile(t *testing.T) {
	opts := testOptions(t)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	opts.Obfuscation = map[string]string{
		"header_protection_key": key,
		"s1":                    "12", "s2": "12", "s3": "12", "s4": "12",
	}
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if !strings.Contains(device.sets[0], "header_protection_key="+strings.Repeat("00", 32)) {
		t.Fatalf("UAPI must receive hex-encoded header key: %q", device.sets[0])
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "HeaderProtectionKey = "+key) || !strings.Contains(profile, "S1 = 12") {
		t.Fatalf("client profile lost AWG 3 header-protection parameters:\n%s", profile)
	}
}

func TestBooleanObfuscationOverridesUseClientOnOffFormat(t *testing.T) {
	opts := testOptions(t)
	opts.Obfuscation["random_trailers"] = "true"
	opts.Obfuscation["disable_cookies"] = "false"
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if !strings.Contains(device.sets[0], "random_trailers=true") || !strings.Contains(device.sets[0], "disable_cookies=false") {
		t.Fatalf("UAPI bool values were not normalized: %q", device.sets[0])
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "RandomTrailers = on") || !strings.Contains(profile, "DisableCookies = off") {
		t.Fatalf("client profile bool values are not on/off: %s", profile)
	}
}

func TestDefaultAWG3PresetConfiguresEngineAndClientProfileConsistently(t *testing.T) {
	opts := testOptions(t)
	opts.Obfuscation = DefaultObfuscation(opts.MasterKey)
	device := &fakeDevice{}
	manager, err := Open(opts, fakeFactory{device: device})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, expected := range []string{
		"jc=4", "jmin=10", "jmax=50", "s1=12", "s2=12", "s3=12", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4", "random_trailers=true", "disable_cookies=true",
		"content_padding_addition=10-100", "rekey_after_time=100-120", "max_handshake_attempts=15-20",
	} {
		if !strings.Contains(device.sets[0], expected) {
			t.Errorf("server UAPI config missing %q", expected)
		}
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("ios", publicKey); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.RenderClientConfig("ios", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Jc = 4", "Jmin = 10", "Jmax = 50", "S1 = 12", "S2 = 12", "S3 = 12", "S4 = 12",
		"H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4", "RandomTrailers = on", "DisableCookies = on",
		"ContentPaddingAddition = 10-100", "RekeyAfterTime = 100-120",
	} {
		if !strings.Contains(profile, expected) {
			t.Errorf("client profile missing %q", expected)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
