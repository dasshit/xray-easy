package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

var (
	// ErrInvalid indicates malformed peer or service input.
	ErrInvalid = errors.New("invalid peer")
	// ErrNotFound indicates that the requested peer does not exist.
	ErrNotFound = errors.New("peer not found")
	// ErrAlreadyExists indicates that a peer with the same name already exists.
	ErrAlreadyExists = errors.New("peer already exists")
	// ErrOperationConflict indicates reuse of an idempotency key for another operation.
	ErrOperationConflict = errors.New("operation ID was already used for a different peer")
	// ErrOperationCompleted indicates that a completed operation cannot be replayed.
	ErrOperationCompleted = errors.New("operation was already completed and its result cannot be replayed")
)

// peerNamePattern is an internal package variable.
var peerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// dnsLabelPattern is an internal package variable.
var dnsLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// stateVersion is an internal package constant.
const stateVersion = 1

// Peer is the non-secret, persisted identity and tunnel address of a client.
type Peer struct {
	// Name is the human-readable name of the object.
	Name string `json:"name"`
	// PublicKey is the public key associated with the object.
	PublicKey string `json:"publicKey"`
	// IPv4 is the assigned IPv4 address.
	IPv4 string `json:"ipv4"`
	// IPv6 is the assigned IPv6 address.
	IPv6 string `json:"ipv6"`
	// CreatedAt is the time the object was created.
	CreatedAt time.Time `json:"createdAt"`
	// OperationID is the idempotency key for the operation.
	OperationID string `json:"operationId,omitempty"`
}

// persistedState is an internal type used by the package.
type persistedState struct {
	// Version stores the value associated with the enclosing object.
	Version int `json:"version"`
	// PrivateKeyEnvelope stores the value associated with the enclosing object.
	PrivateKeyEnvelope string `json:"privateKeyEnvelope"`
	// Peers stores the value associated with the enclosing object.
	Peers []Peer `json:"peers"`
	// Operations stores the value associated with the enclosing object.
	Operations map[string]OperationReceipt `json:"operations,omitempty"`
}

// OperationReceipt makes create and revoke retries safe across service restarts.
type OperationReceipt struct {
	// Action is the operation action.
	Action string `json:"action"`
	// Name is the human-readable name of the object.
	Name string `json:"name"`
	// Peer is the peer affected by the operation.
	Peer Peer `json:"peer,omitempty"`
	// Removed is whether the peer was removed.
	Removed bool `json:"removed,omitempty"`
}

// Options are the non-secret deployment settings of the prototype service.
type Options struct {
	// DataDir is the persistent data directory.
	DataDir string
	// MasterKey is the master key used to encrypt persisted secrets.
	MasterKey []byte
	// PublicHost is the public DNS name or IP address advertised to clients.
	PublicHost string
	// PublicPort is the public listener port advertised to clients.
	PublicPort uint16
	// ListenPort is the AmneziaWG listen port.
	ListenPort uint16
	// IPv4Prefix is the IPv4 client network.
	IPv4Prefix netip.Prefix
	// IPv6Prefix is the IPv6 client network.
	IPv6Prefix netip.Prefix
	// DNS is the DNS servers advertised to clients.
	DNS []string
	// Obfuscation is the AmneziaWG obfuscation parameters.
	Obfuscation map[string]string
	// InterfaceName is the Linux tunnel interface name.
	InterfaceName string
}

// Device exposes the small part of amneziawg-go's device lifecycle used by the manager.
type Device interface {
	// Set updates the requested setting.
	Set(string) error
	// Up defines part of the interface contract.
	Up() error
	// Snapshot returns the requested state.
	Snapshot() (string, error)
	// Close releases implementation resources.
	Close()
}

// DeviceFactory creates the TUN-backed AmneziaWG device.
type DeviceFactory interface {
	// Open defines part of the interface contract.
	Open(interfaceName string, mtu int) (Device, error)
}

// Manager owns persistent server identity and live peer reconciliation.
type Manager struct {
	mu               sync.Mutex
	opts             Options
	device           Device
	state            persistedState
	serverPrivateKey string
	closed           bool
}

// Open loads or creates the persistent state, configures the TUN-backed engine, and brings it up.
func Open(opts Options, factory DeviceFactory) (*Manager, error) {
	if opts.InterfaceName == "" {
		opts.InterfaceName = "awg0"
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("create AWG data directory: %w", err)
	}
	statePath := filepath.Join(opts.DataDir, "state.json")
	state, err := readState(statePath)
	serverPrivateKey := ""
	if errors.Is(err, os.ErrNotExist) {
		privateKey, _, keyErr := GenerateKeypair()
		if keyErr != nil {
			return nil, fmt.Errorf("generate server key: %w", keyErr)
		}
		envelope, sealErr := sealPrivateKey(privateKey, opts.MasterKey)
		if sealErr != nil {
			return nil, sealErr
		}
		state = persistedState{Version: stateVersion, PrivateKeyEnvelope: envelope, Peers: []Peer{}, Operations: map[string]OperationReceipt{}}
		if err := writeState(statePath, state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if state.Operations == nil {
		state.Operations = map[string]OperationReceipt{}
	}
	serverPrivateKey, err = openPrivateKey(state.PrivateKeyEnvelope, opts.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt persisted AWG server key: %w", err)
	}
	if err := validateState(state, opts); err != nil {
		return nil, err
	}
	device, err := factory.Open(opts.InterfaceName, 1280)
	if err != nil {
		return nil, fmt.Errorf("create AmneziaWG device: %w", err)
	}
	manager := &Manager{opts: opts, device: device, state: state, serverPrivateKey: serverPrivateKey}
	if err := manager.applyAllLocked(); err != nil {
		device.Close()
		return nil, err
	}
	if err := device.Up(); err != nil {
		device.Close()
		return nil, fmt.Errorf("bring AmneziaWG device up: %w", err)
	}
	return manager, nil
}

// validate validates the supplied value.
func (o Options) validate() error {
	if strings.TrimSpace(o.DataDir) == "" {
		return fmt.Errorf("AWG data directory is required: %w", ErrInvalid)
	}
	if len(o.MasterKey) < 32 {
		return fmt.Errorf("AWG master key must contain at least 32 bytes: %w", ErrInvalid)
	}
	if strings.TrimSpace(o.PublicHost) == "" {
		return fmt.Errorf("AWG_PUBLIC_HOST is required: %w", ErrInvalid)
	}
	if !validPublicHost(o.PublicHost) {
		return fmt.Errorf("AWG public host must be an IP address or DNS name: %w", ErrInvalid)
	}
	if o.PublicPort == 0 || o.ListenPort == 0 {
		return fmt.Errorf("AWG public and listen ports must be non-zero: %w", ErrInvalid)
	}
	if !o.IPv4Prefix.IsValid() || !o.IPv4Prefix.Addr().Is4() || o.IPv4Prefix.Bits() > 29 {
		return fmt.Errorf("AWG IPv4 client network must be an IPv4 prefix no narrower than /29: %w", ErrInvalid)
	}
	if !o.IPv6Prefix.IsValid() || !o.IPv6Prefix.Addr().Is6() || o.IPv6Prefix.Bits() > 120 {
		return fmt.Errorf("AWG IPv6 client network must be an IPv6 prefix no narrower than /120: %w", ErrInvalid)
	}
	if o.IPv4Prefix != o.IPv4Prefix.Masked() || o.IPv6Prefix != o.IPv6Prefix.Masked() {
		return fmt.Errorf("AWG client networks must be canonical subnet prefixes: %w", ErrInvalid)
	}
	if len(o.InterfaceName) > 15 || !peerNamePattern.MatchString(o.InterfaceName) {
		return fmt.Errorf("AWG interface name must contain 1-15 letters, digits or hyphens: %w", ErrInvalid)
	}
	for key := range o.Obfuscation {
		if !allowedObfuscationKeys[key] {
			return fmt.Errorf("unsupported AmneziaWG parameter %q: %w", key, ErrInvalid)
		}
		if strings.ContainsAny(o.Obfuscation[key], "\r\n\x00") {
			return fmt.Errorf("AmneziaWG parameter %q contains a line break: %w", key, ErrInvalid)
		}
	}
	for _, address := range o.DNS {
		if net.ParseIP(address) == nil {
			return fmt.Errorf("AWG DNS server %q is not an IP address: %w", address, ErrInvalid)
		}
	}
	if key := o.Obfuscation["header_protection_key"]; key != "" {
		if _, err := decodeKey(key); err != nil {
			return fmt.Errorf("AWG_HEADER_PROTECTION_KEY must be a base64-encoded 32-byte key: %w", ErrInvalid)
		}
		for _, name := range []string{"s1", "s2", "s3", "s4"} {
			padding, err := strconv.ParseUint(o.Obfuscation[name], 10, 16)
			if err != nil || padding < 12 {
				return fmt.Errorf("AWG %s must be at least 12 when header protection is enabled: %w", strings.ToUpper(name), ErrInvalid)
			}
		}
	}
	for _, key := range []string{"random_trailers", "disable_cookies"} {
		if value := o.Obfuscation[key]; value != "" && value != "on" && value != "off" && value != "true" && value != "false" {
			return fmt.Errorf("AWG %s must be on or off: %w", key, ErrInvalid)
		}
	}
	return nil
}

// allowedObfuscationKeys is an internal package variable.
var allowedObfuscationKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"header_protection_key": true, "content_padding_addition": true,
	"rekey_after_time": true, "rekey_timeout": true, "reject_after_time": true,
	"keepalive_timeout": true, "max_handshake_attempts": true,
	"random_trailers": true, "disable_cookies": true,
}

// DefaultObfuscation returns the current official AmneziaWG 3.x preset.
// The secret header-protection key is derived with its own context from the installation key.
func DefaultObfuscation(masterKey []byte) map[string]string {
	mac := hmac.New(sha256.New, masterKey)
	_, _ = mac.Write([]byte("xray-easy/awg/header-protection/v1"))
	return map[string]string{
		"jc": "4", "jmin": "10", "jmax": "50",
		"s1": "12", "s2": "12", "s3": "12", "s4": "12",
		"h1": "1", "h2": "2", "h3": "3", "h4": "4",
		"i1":                       "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
		"header_protection_key":    base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		"content_padding_addition": "10-100",
		"rekey_after_time":         "100-120",
		"rekey_timeout":            "3-7",
		"reject_after_time":        "150-180",
		"keepalive_timeout":        "5-15",
		"max_handshake_attempts":   "15-20",
		"random_trailers":          "on",
		"disable_cookies":          "on",
	}
}

// GenerateKeypair creates a standard base64 AmneziaWG/WireGuard key pair.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public), nil
}

// AddPeer allocates a dual-stack address pair and activates a peer without restarting the engine.
func (m *Manager) AddPeer(name, publicKey string) (Peer, error) {
	peer, _, err := m.AddPeerForOperation(name, publicKey, "")
	return peer, err
}

// AddPeerForOperation deduplicates retries by stable operation ID and records
// the receipt atomically with the peer state. The optional persisted field is
// backward compatible with existing AWG state files.
func (m *Manager) AddPeerForOperation(name, publicKey, operationID string) (Peer, bool, error) {
	if !peerNamePattern.MatchString(name) {
		return Peer{}, false, fmt.Errorf("peer name must contain 1-32 letters, digits or hyphens: %w", ErrInvalid)
	}
	if _, err := decodeKey(publicKey); err != nil {
		return Peer{}, false, fmt.Errorf("client public key: %w", err)
	}
	if operationID != "" && !operationIDPattern.MatchString(operationID) {
		return Peer{}, false, fmt.Errorf("invalid operation ID: %w", ErrInvalid)
	}
	_, serverPublicKey, err := derivePublicKey(m.serverPrivateKey)
	if err != nil {
		return Peer{}, false, err
	}
	if serverPublicKey == publicKey {
		return Peer{}, false, fmt.Errorf("client public key cannot equal the server key: %w", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Peer{}, false, errors.New("AWG manager is closed")
	}
	if operationID != "" {
		if receipt, exists := m.state.Operations[operationID]; exists {
			if receipt.Action != "create" || receipt.Name != name {
				return Peer{}, false, ErrOperationConflict
			}
			if receipt.Removed {
				return Peer{}, false, ErrOperationCompleted
			}
			return receipt.Peer, true, nil
		}
	}
	for _, peer := range m.state.Peers {
		if operationID != "" && peer.OperationID == operationID {
			if peer.Name != name {
				return Peer{}, false, ErrOperationConflict
			}
			return peer, true, nil
		}
		if peer.Name == name || peer.PublicKey == publicKey {
			return Peer{}, false, ErrAlreadyExists
		}
	}
	ipv4, ipv6, err := m.nextAddressesLocked()
	if err != nil {
		return Peer{}, false, err
	}
	peer := Peer{Name: name, PublicKey: publicKey, IPv4: ipv4.String(), IPv6: ipv6.String(), CreatedAt: time.Now().UTC(), OperationID: operationID}
	if err := m.device.Set(peerConfig(peer)); err != nil {
		return Peer{}, false, fmt.Errorf("activate peer: %w", err)
	}
	next := cloneState(m.state)
	next.Peers = append(next.Peers, peer)
	if operationID != "" {
		next.Operations[operationID] = OperationReceipt{Action: "create", Name: name, Peer: peer}
	}
	if err := writeState(filepath.Join(m.opts.DataDir, "state.json"), next); err != nil {
		_ = m.device.Set(removePeerConfig(peer))
		return Peer{}, false, err
	}
	m.state = next
	slog.Info("AWG peer event", "service", "amneziawg-service", "component", "peer", "event", "peer_added", "peer_name", name)
	return peer, false, nil
}

// operationIDPattern is an internal package variable.
var operationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// PeerForOperation returns a persisted peer created by an earlier operation.
func (m *Manager) PeerForOperation(operationID string) (Peer, bool) {
	if !operationIDPattern.MatchString(operationID) {
		return Peer{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if receipt, ok := m.state.Operations[operationID]; ok && receipt.Action == "create" && !receipt.Removed {
		return receipt.Peer, true
	}
	return Peer{}, false
}

// OperationReceipt returns a durable result record for an operation ID.
func (m *Manager) OperationReceipt(operationID string) (OperationReceipt, bool) {
	if !operationIDPattern.MatchString(operationID) {
		return OperationReceipt{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	receipt, ok := m.state.Operations[operationID]
	return receipt, ok
}

// RemovePeer removes a client from the live device and persisted desired state.
func (m *Manager) RemovePeer(name string) error {
	_, err := m.RemovePeerForOperation(name, "")
	return err
}

// RemovePeerForOperation revokes a peer and records the result atomically.
// Replaying a revoke cannot remove a later peer that reused the same name.
func (m *Manager) RemovePeerForOperation(name, operationID string) (bool, error) {
	if operationID != "" && !operationIDPattern.MatchString(operationID) {
		return false, fmt.Errorf("invalid operation ID: %w", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false, errors.New("AWG manager is closed")
	}
	if operationID != "" {
		if receipt, exists := m.state.Operations[operationID]; exists {
			if receipt.Action != "remove" || receipt.Name != name {
				return false, ErrOperationConflict
			}
			return true, nil
		}
	}
	index := -1
	for i, peer := range m.state.Peers {
		if peer.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		if operationID == "" {
			return false, ErrNotFound
		}
		next := cloneState(m.state)
		next.Operations[operationID] = OperationReceipt{Action: "remove", Name: name, Removed: true}
		if err := writeState(filepath.Join(m.opts.DataDir, "state.json"), next); err != nil {
			return false, err
		}
		m.state = next
		return false, nil
	}
	peer := m.state.Peers[index]
	if err := m.device.Set(removePeerConfig(peer)); err != nil {
		return false, fmt.Errorf("deactivate peer: %w", err)
	}
	next := cloneState(m.state)
	next.Peers = append(next.Peers[:index], next.Peers[index+1:]...)
	if peer.OperationID != "" {
		next.Operations[peer.OperationID] = OperationReceipt{Action: "create", Name: name, Peer: peer, Removed: true}
	}
	if operationID != "" {
		next.Operations[operationID] = OperationReceipt{Action: "remove", Name: name, Peer: peer, Removed: true}
	}
	if err := writeState(filepath.Join(m.opts.DataDir, "state.json"), next); err != nil {
		_ = m.device.Set(peerConfig(peer))
		return false, err
	}
	m.state = next
	slog.Info("AWG peer event", "service", "amneziawg-service", "component", "peer", "event", "peer_removed", "peer_name", name)
	return false, nil
}

// RestorePersistedState validates and applies a state snapshot using the
// installation master key. The live device and state file are rolled back if
// applying the restored identity or peer set fails.
func (m *Manager) RestorePersistedState(data []byte) error {
	var next persistedState
	if err := json.Unmarshal(data, &next); err != nil {
		return fmt.Errorf("decode restored AWG state: %w", err)
	}
	if next.Peers == nil {
		next.Peers = []Peer{}
	}
	if err := validateState(next, m.opts); err != nil {
		return fmt.Errorf("validate restored AWG state: %w", err)
	}
	nextPrivateKey, err := openPrivateKey(next.PrivateKeyEnvelope, m.opts.MasterKey)
	if err != nil {
		return fmt.Errorf("decrypt restored AWG server key: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("AWG manager is closed")
	}
	previous := cloneState(m.state)
	previousPrivateKey := m.serverPrivateKey
	next = cloneState(next)
	if err := m.restoreDeviceLocked(next, nextPrivateKey, previous, previousPrivateKey); err != nil {
		return err
	}
	statePath := filepath.Join(m.opts.DataDir, "state.json")
	if err := writeState(statePath, next); err != nil {
		rollbackErr := m.restoreDeviceLocked(previous, previousPrivateKey, next, nextPrivateKey)
		if rollbackErr != nil {
			return fmt.Errorf("persist restored AWG state: %w; roll back live device: %v", err, rollbackErr)
		}
		return fmt.Errorf("persist restored AWG state: %w", err)
	}
	m.state, m.serverPrivateKey = next, nextPrivateKey
	return nil
}

// restoreDeviceLocked performs the operation represented by its name.
func (m *Manager) restoreDeviceLocked(next persistedState, nextPrivateKey string, previous persistedState, previousPrivateKey string) error {
	removePeers := func(states ...persistedState) error {
		seen := make(map[string]bool)
		for _, state := range states {
			for _, peer := range state.Peers {
				if seen[peer.PublicKey] {
					continue
				}
				seen[peer.PublicKey] = true
				if err := m.device.Set(removePeerConfig(peer)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := removePeers(previous, next); err != nil {
		if rollbackErr := m.applyAllLocked(); rollbackErr != nil {
			return fmt.Errorf("remove current AWG peers before restore: %w; reapply current state: %v", err, rollbackErr)
		}
		return fmt.Errorf("remove current AWG peers before restore: %w", err)
	}
	m.state, m.serverPrivateKey = cloneState(next), nextPrivateKey
	if err := m.applyAllLocked(); err != nil {
		applyErr := err
		_ = removePeers(previous, next)
		m.state, m.serverPrivateKey = cloneState(previous), previousPrivateKey
		if rollbackErr := m.applyAllLocked(); rollbackErr != nil {
			return fmt.Errorf("apply restored AWG state: %w; roll back live device: %v", applyErr, rollbackErr)
		}
		return fmt.Errorf("apply restored AWG state: %w", applyErr)
	}
	return nil
}

// Peers returns a stable copy of the currently managed peers.
func (m *Manager) Peers() []Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	peers := append([]Peer(nil), m.state.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	return peers
}

// PeerTelemetry reads current endpoint, handshake, and traffic counters from
// the live engine and returns them joined to managed peers by public key.
func (m *Manager) PeerTelemetry() ([]PeerTelemetry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("AWG manager is closed")
	}
	snapshot, err := m.device.Snapshot()
	if err != nil {
		slog.Error("AWG telemetry error", "service", "amneziawg-service", "component", "telemetry", "event", "snapshot_failed")
		return nil, fmt.Errorf("read AWG peer telemetry: %w", err)
	}
	observed, err := ParsePeerTelemetry(snapshot)
	if err != nil {
		return nil, err
	}
	managed := make(map[string]string, len(m.state.Peers))
	for _, peer := range m.state.Peers {
		managed[peer.PublicKey] = peer.Name
	}
	result := make([]PeerTelemetry, 0, len(observed))
	for _, peer := range observed {
		if name, ok := managed[peer.PublicKey]; ok {
			peer.Name = name
			result = append(result, peer)
		}
	}
	return result, nil
}

// Status reports server public identity and current peer count.
func (m *Manager) Status() (publicKey string, peers int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", 0, errors.New("AWG manager is closed")
	}
	_, publicKey, err = derivePublicKey(m.serverPrivateKey)
	return publicKey, len(m.state.Peers), err
}

// RenderClientConfig renders a native AmneziaWG profile for a previously registered peer.
func (m *Manager) RenderClientConfig(name, privateKey string) (string, error) {
	priv, err := decodeKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("client private key: %w", ErrInvalid)
	}
	public, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("client private key: %w", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("AWG manager is closed")
	}
	var peer *Peer
	for i := range m.state.Peers {
		if m.state.Peers[i].Name == name {
			peer = &m.state.Peers[i]
			break
		}
	}
	if peer == nil {
		return "", ErrNotFound
	}
	if base64.StdEncoding.EncodeToString(public) != peer.PublicKey {
		return "", fmt.Errorf("client private key does not match registered peer: %w", ErrInvalid)
	}
	_, serverPublic, err := derivePublicKey(m.serverPrivateKey)
	if err != nil {
		return "", err
	}
	endpoint := net.JoinHostPort(m.opts.PublicHost, strconv.Itoa(int(m.opts.PublicPort)))
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32, %s/128\n", privateKey, peer.IPv4, peer.IPv6)
	if len(m.opts.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(m.opts.DNS, ", "))
	}
	for _, key := range sortedKeys(m.opts.Obfuscation) {
		fmt.Fprintf(&b, "%s = %s\n", profileObfuscationName(key), profileObfuscationValue(key, m.opts.Obfuscation[key]))
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\nPersistentKeepalive = 25\n", serverPublic, endpoint)
	return b.String(), nil
}

// Close shuts down the engine and prevents future state changes.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.device.Close()
	}
}

// nextAddressesLocked performs the operation represented by its name.
func (m *Manager) nextAddressesLocked() (netip.Addr, netip.Addr, error) {
	used4 := make(map[netip.Addr]bool, len(m.state.Peers))
	used6 := make(map[netip.Addr]bool, len(m.state.Peers))
	for _, peer := range m.state.Peers {
		if addr, err := netip.ParseAddr(peer.IPv4); err == nil {
			used4[addr] = true
		}
		if addr, err := netip.ParseAddr(peer.IPv6); err == nil {
			used6[addr] = true
		}
	}
	server4, server6 := m.opts.IPv4Prefix.Addr(), m.opts.IPv6Prefix.Addr()
	a4, a6 := server4.Next().Next(), server6.Next().Next()
	broadcast := ipv4Broadcast(m.opts.IPv4Prefix)
	for i := 0; i < len(m.state.Peers)+1; i++ {
		if !m.opts.IPv4Prefix.Contains(a4) || a4 == broadcast || !m.opts.IPv6Prefix.Contains(a6) {
			break
		}
		if !used4[a4] && !used6[a6] {
			return a4, a6, nil
		}
		a4, a6 = a4.Next(), a6.Next()
	}
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("AWG client address pool is exhausted: %w", ErrInvalid)
}

// applyAllLocked performs the operation represented by its name.
func (m *Manager) applyAllLocked() error {
	private, err := decodeKey(m.serverPrivateKey)
	if err != nil {
		return fmt.Errorf("invalid persisted server private key: %w", err)
	}
	lines := []string{"private_key=" + hex.EncodeToString(private), fmt.Sprintf("listen_port=%d", m.opts.ListenPort)}
	for _, key := range sortedKeys(m.opts.Obfuscation) {
		value := m.opts.Obfuscation[key]
		if key == "header_protection_key" {
			decoded, err := decodeKey(value)
			if err != nil {
				return fmt.Errorf("decode AmneziaWG header-protection key: %w", err)
			}
			value = hex.EncodeToString(decoded)
		}
		if key == "random_trailers" || key == "disable_cookies" {
			value = strconv.FormatBool(value == "on" || value == "true")
		}
		lines = append(lines, key+"="+value)
	}
	if err := m.device.Set(strings.Join(lines, "\n") + "\n\n"); err != nil {
		return fmt.Errorf("configure AmneziaWG device: %w", err)
	}
	for _, peer := range m.state.Peers {
		if err := m.device.Set(peerConfig(peer)); err != nil {
			return fmt.Errorf("restore peer %q: %w", peer.Name, err)
		}
	}
	return nil
}

// peerConfig performs the operation represented by its name.
func peerConfig(peer Peer) string {
	key, _ := decodeKey(peer.PublicKey)
	return fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\nallowed_ip=%s/128\n\n", hex.EncodeToString(key), peer.IPv4, peer.IPv6)
}

// removePeerConfig removes the supplied value.
func removePeerConfig(peer Peer) string {
	key, _ := decodeKey(peer.PublicKey)
	return fmt.Sprintf("public_key=%s\nremove=true\n\n", hex.EncodeToString(key))
}

// readState reads the requested value.
func readState(path string) (persistedState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedState{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return persistedState{}, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return persistedState{}, errors.New("AWG state permissions are too broad; expected mode 0600")
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode AWG state: %w", err)
	}
	if state.Version != stateVersion {
		return persistedState{}, fmt.Errorf("unsupported AWG state version %d", state.Version)
	}
	if state.Peers == nil {
		state.Peers = []Peer{}
	}
	return state, nil
}

// writeState writes the supplied value.
func writeState(path string, state persistedState) error {
	return writeStateWith(path, state, func(dir, pattern string) (stateTempFile, error) {
		return os.CreateTemp(dir, pattern)
	})
}

// stateTempFile is an internal type used by the package.
type stateTempFile interface {
	// Name defines part of the interface contract.
	Name() string
	// Chmod defines part of the interface contract.
	Chmod(os.FileMode) error
	// Write defines part of the interface contract.
	Write([]byte) (int, error)
	// Sync defines part of the interface contract.
	Sync() error
	// Close defines part of the interface contract.
	Close() error
}

// writeStateWith writes the supplied value.
func writeStateWith(path string, state persistedState, createTemp func(string, string) (stateTempFile, error)) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode AWG state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := createTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create AWG state temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure AWG state temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write AWG state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync AWG state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close AWG state: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("activate AWG state: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// validateState validates the supplied value.
func validateState(state persistedState, opts Options) error {
	if state.Version != stateVersion {
		return fmt.Errorf("unsupported AWG state version %d", state.Version)
	}
	if state.PrivateKeyEnvelope == "" {
		return fmt.Errorf("persisted server key envelope is missing: %w", ErrInvalid)
	}
	seenName, seenKey, seen4, seen6, seenOperation := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, peer := range state.Peers {
		if !peerNamePattern.MatchString(peer.Name) || seenName[peer.Name] || seenKey[peer.PublicKey] {
			return fmt.Errorf("invalid or duplicate persisted AWG peer: %w", ErrInvalid)
		}
		if _, err := decodeKey(peer.PublicKey); err != nil {
			return fmt.Errorf("invalid persisted peer key: %w", err)
		}
		if peer.OperationID != "" && (!operationIDPattern.MatchString(peer.OperationID) || seenOperation[peer.OperationID]) {
			return fmt.Errorf("invalid or duplicate persisted operation ID: %w", ErrInvalid)
		}
		ip4, err4 := netip.ParseAddr(peer.IPv4)
		ip6, err6 := netip.ParseAddr(peer.IPv6)
		if err4 != nil || !opts.IPv4Prefix.Contains(ip4) || !ip4.Is4() || ip4 == opts.IPv4Prefix.Addr().Next() || ip4 == ipv4Broadcast(opts.IPv4Prefix) || seen4[peer.IPv4] {
			return fmt.Errorf("invalid persisted peer IPv4 address: %w", ErrInvalid)
		}
		if err6 != nil || !opts.IPv6Prefix.Contains(ip6) || !ip6.Is6() || ip6 == opts.IPv6Prefix.Addr().Next() || seen6[peer.IPv6] {
			return fmt.Errorf("invalid persisted peer IPv6 address: %w", ErrInvalid)
		}
		seenName[peer.Name], seenKey[peer.PublicKey], seen4[peer.IPv4], seen6[peer.IPv6] = true, true, true, true
		if peer.OperationID != "" {
			seenOperation[peer.OperationID] = true
		}
	}
	for operationID, receipt := range state.Operations {
		if !operationIDPattern.MatchString(operationID) || !peerNamePattern.MatchString(receipt.Name) || (receipt.Action != "create" && receipt.Action != "remove") {
			return fmt.Errorf("invalid persisted AWG operation receipt: %w", ErrInvalid)
		}
		if receipt.Action == "create" && (!peerNamePattern.MatchString(receipt.Peer.Name) || receipt.Peer.Name != receipt.Name) {
			return fmt.Errorf("invalid persisted AWG create receipt: %w", ErrInvalid)
		}
	}
	return nil
}

// cloneState performs the operation represented by its name.
func cloneState(state persistedState) persistedState {
	state.Peers = append([]Peer(nil), state.Peers...)
	operations := make(map[string]OperationReceipt, len(state.Operations))
	for operationID, receipt := range state.Operations {
		operations[operationID] = receipt
	}
	state.Operations = operations
	return state
}

// decodeKey performs the operation represented by its name.
func decodeKey(key string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(data) != 32 {
		return nil, fmt.Errorf("key must be base64-encoded 32 bytes: %w", ErrInvalid)
	}
	return data, nil
}

// sealPrivateKey performs the operation represented by its name.
func sealPrivateKey(privateKey string, masterKey []byte) (string, error) {
	key, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveEncryptionKey(masterKey))
	if err != nil {
		return "", fmt.Errorf("create AWG key cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create AWG key envelope: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate AWG key nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, key, []byte("xray-easy/awg/private-key/v1"))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// openPrivateKey opens the requested resource.
func openPrivateKey(envelope string, masterKey []byte) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return "", fmt.Errorf("decode AWG key envelope: %w", err)
	}
	block, err := aes.NewCipher(deriveEncryptionKey(masterKey))
	if err != nil {
		return "", fmt.Errorf("create AWG key cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create AWG key envelope: %w", err)
	}
	if len(sealed) < aead.NonceSize() {
		return "", errors.New("AWG key envelope is truncated")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	key, err := aead.Open(nil, nonce, ciphertext, []byte("xray-easy/awg/private-key/v1"))
	if err != nil {
		return "", fmt.Errorf("AWG key authentication failed: %w", err)
	}
	if len(key) != 32 {
		return "", errors.New("AWG private key has an invalid length")
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// deriveEncryptionKey performs the operation represented by its name.
func deriveEncryptionKey(masterKey []byte) []byte {
	key := sha256.Sum256(masterKey)
	return key[:]
}

// derivePublicKey performs the operation represented by its name.
func derivePublicKey(privateKey string) ([]byte, string, error) {
	private, err := decodeKey(privateKey)
	if err != nil {
		return nil, "", err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, "", err
	}
	return public, base64.StdEncoding.EncodeToString(public), nil
}

// sortedKeys performs the operation represented by its name.
func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// profileObfuscationName performs the operation represented by its name.
func profileObfuscationName(key string) string {
	var names = map[string]string{
		"header_protection_key": "HeaderProtectionKey", "content_padding_addition": "ContentPaddingAddition",
		"rekey_after_time": "RekeyAfterTime", "rekey_timeout": "RekeyTimeout",
		"reject_after_time": "RejectAfterTime", "keepalive_timeout": "KeepaliveTimeout",
		"max_handshake_attempts": "MaxHandshakeAttempts", "random_trailers": "RandomTrailers",
		"disable_cookies": "DisableCookies",
	}
	if name, ok := names[key]; ok {
		return name
	}
	parts := strings.Split(key, "_")
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

// profileObfuscationValue performs the operation represented by its name.
func profileObfuscationValue(key, value string) string {
	if key == "random_trailers" || key == "disable_cookies" {
		if value == "on" || value == "true" {
			return "on"
		}
		return "off"
	}
	return value
}

// ipv4Broadcast performs the operation represented by its name.
func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr().As4()
	maskBits := prefix.Bits()
	for bit := maskBits; bit < 32; bit++ {
		byteIndex := bit / 8
		bitInByte := uint(7 - bit%8)
		addr[byteIndex] |= byte(1 << bitInByte)
	}
	return netip.AddrFrom4(addr)
}

// validPublicHost performs the operation represented by its name.
func validPublicHost(host string) bool {
	if strings.ContainsAny(host, "\r\n\t /\\") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	trimmed := strings.TrimSuffix(host, ".")
	if len(trimmed) == 0 || len(trimmed) > 253 {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
