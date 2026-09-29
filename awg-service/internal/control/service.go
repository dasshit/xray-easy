package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// Service maps the prototype's gRPC methods onto the AWG lifecycle manager.
type Service struct {
	manager *Manager
	options Options
	mu      sync.Mutex
}

var servicePeerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// NewService creates the RPC adapter for a configured lifecycle manager.
func NewService(manager *Manager, options Options) *Service {
	return &Service{manager: manager, options: options}
}

// GetStatus returns the running device identity and its configured listener.
func (s *Service) GetStatus(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	publicKey, peers, err := s.manager.Status()
	if err != nil {
		return nil, mapError(err)
	}
	return response(map[string]any{
		"running":        true,
		"publicKey":      publicKey,
		"listenPort":     float64(s.options.ListenPort),
		"publicHost":     s.options.PublicHost,
		"publicPort":     float64(s.options.PublicPort),
		"peerCount":      float64(peers),
		"ipv4Network":    s.options.IPv4Prefix.String(),
		"ipv6Network":    s.options.IPv6Prefix.String(),
		"protocol":       "AmneziaWG",
		"serviceVersion": "prototype-v1",
	})
}

// ListPeers returns current peer labels, public keys, and allocated tunnel addresses.
func (s *Service) ListPeers(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	peers := s.manager.Peers()
	items := make([]any, 0, len(peers))
	for _, peer := range peers {
		items = append(items, peerMap(peer))
	}
	return response(map[string]any{"peers": items})
}

// GetPeerStats returns the live endpoint, handshake, and counters for each
// managed peer without returning any private configuration material.
func (s *Service) GetPeerStats(context.Context, *structpb.Struct) (*structpb.Struct, error) {
	peers, err := s.manager.PeerTelemetry()
	if err != nil {
		return nil, mapError(err)
	}
	items := make([]any, 0, len(peers))
	for _, peer := range peers {
		lastHandshake := ""
		if !peer.LastHandshake.IsZero() {
			lastHandshake = peer.LastHandshake.UTC().Format(time.RFC3339Nano)
		}
		items = append(items, map[string]any{
			"name": peer.Name, "sourceIp": peer.SourceIP,
			"lastHandshake": lastHandshake,
			"uploadBytes":   strconv.FormatInt(peer.UploadBytes, 10),
			"downloadBytes": strconv.FormatInt(peer.DownloadBytes, 10),
		})
	}
	return response(map[string]any{"peers": items})
}

// CreatePeer creates a keypair, registers its public key, and persists the
// corresponding private client profile for later authenticated delivery.
func (s *Service) CreatePeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	if !servicePeerNamePattern.MatchString(name) {
		return nil, mapError(fmt.Errorf("invalid peer name: %w", ErrInvalid))
	}
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		return nil, statusError("generate peer keypair", err)
	}
	peer, err := s.manager.AddPeer(name, publicKey)
	if err != nil {
		return nil, mapError(err)
	}
	config, err := s.manager.RenderClientConfig(name, privateKey)
	if err != nil {
		_ = s.manager.RemovePeer(name)
		return nil, statusError("render client profile", err)
	}
	if err := writeClientProfile(s.options.DataDir, name, config); err != nil {
		_ = s.manager.RemovePeer(name)
		return nil, statusError("persist client profile", err)
	}
	return response(peerMap(peer))
}

// AddPeer activates a peer immediately and persists it for process recovery.
func (s *Service) AddPeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	publicKey, err := stringField(request, "publicKey")
	if err != nil {
		return nil, err
	}
	peer, err := s.manager.AddPeer(name, publicKey)
	if err != nil {
		return nil, mapError(err)
	}
	return response(peerMap(peer))
}

// RemovePeer revokes the selected peer in the live device and persistent state.
func (s *Service) RemovePeer(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	if err := s.manager.RemovePeer(name); err != nil {
		return nil, mapError(err)
	}
	if err := removeClientProfile(s.options.DataDir, name); err != nil {
		return nil, statusError("remove saved client profile", err)
	}
	return response(map[string]any{"removed": true, "name": name})
}

// GetClientConfig returns the private client profile for an active peer.
func (s *Service) GetClientConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	if !servicePeerNamePattern.MatchString(name) {
		return nil, mapError(fmt.Errorf("invalid peer name: %w", ErrInvalid))
	}
	active := false
	for _, peer := range s.manager.Peers() {
		if peer.Name == name {
			active = true
			break
		}
	}
	if !active {
		return nil, mapError(ErrNotFound)
	}
	config, err := readClientProfile(s.options.DataDir, name)
	if err != nil {
		return nil, statusError("read saved client profile", err)
	}
	privateKey, err := privateKeyFromProfile(config)
	if err != nil {
		return nil, statusError("read saved client profile", err)
	}
	config, err = s.manager.RenderClientConfig(name, privateKey)
	if err != nil {
		return nil, mapError(err)
	}
	if err := writeClientProfile(s.options.DataDir, name, config); err != nil {
		return nil, statusError("refresh saved client profile", err)
	}
	return response(map[string]any{"config": config})
}

// RenderClientConfig returns a native profile without ever persisting the client private key.
func (s *Service) RenderClientConfig(_ context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	name, err := stringField(request, "name")
	if err != nil {
		return nil, err
	}
	privateKey, err := stringField(request, "privateKey")
	if err != nil {
		return nil, err
	}
	config, err := s.manager.RenderClientConfig(name, privateKey)
	if err != nil {
		return nil, mapError(err)
	}
	return response(map[string]any{"config": config})
}

func peerMap(peer Peer) map[string]any {
	return map[string]any{
		"name": peer.Name, "publicKey": peer.PublicKey, "ipv4": peer.IPv4, "ipv6": peer.IPv6,
		"createdAt": peer.CreatedAt.UTC().Format(time.RFC3339),
	}
}

var _ API = (*Service)(nil)

func clientProfilePath(dataDir, name string) (string, error) {
	if !servicePeerNamePattern.MatchString(name) {
		return "", ErrInvalid
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("AWG data directory is not configured")
	}
	return filepath.Join(dataDir, "profiles", name+".conf"), nil
}

func writeClientProfile(dataDir, name, config string) error {
	path, err := clientProfilePath(dataDir, name)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".profile-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.WriteString(config); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

func readClientProfile(dataDir, name string) (string, error) {
	path, err := clientProfilePath(dataDir, name)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return "", errors.New("saved client profile is not a regular file or exceeds 64 KiB")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !strings.Contains(string(data), "[Interface]") || !strings.Contains(string(data), "[Peer]") {
		return "", errors.New("saved client profile is malformed")
	}
	return string(data), nil
}

func privateKeyFromProfile(config string) (string, error) {
	section := ""
	privateKey := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Interface" || !strings.HasPrefix(line, "PrivateKey") {
			continue
		}
		key, ok := strings.CutPrefix(line, "PrivateKey = ")
		if !ok || privateKey != "" || strings.TrimSpace(key) == "" {
			return "", errors.New("saved client profile must contain exactly one valid Interface PrivateKey")
		}
		privateKey = strings.TrimSpace(key)
	}
	if privateKey == "" {
		return "", errors.New("saved client profile does not contain an Interface PrivateKey")
	}
	return privateKey, nil
}

func removeClientProfile(dataDir, name string) error {
	path, err := clientProfilePath(dataDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func statusError(operation string, _ error) error {
	return status.Error(codes.Internal, operation+" failed")
}
