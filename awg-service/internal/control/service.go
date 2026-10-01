package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service maps the prototype's gRPC methods onto the AWG lifecycle manager.
type Service struct {
	awgapi.UnimplementedControlServer
	manager           *Manager
	options           Options
	mu                sync.Mutex
	startedAt         time.Time
	telemetrySequence uint64
	telemetryNow      func() time.Time
}

var servicePeerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// NewService creates the RPC adapter for a configured lifecycle manager.
func NewService(manager *Manager, options Options) *Service {
	service := &Service{manager: manager, options: options, startedAt: time.Now().UTC()}
	service.removeOrphanedOperationKeys()
	return service
}

func (s *Service) removeOrphanedOperationKeys() {
	if s == nil || s.manager == nil || strings.TrimSpace(s.options.DataDir) == "" {
		return
	}
	directory := filepath.Join(s.options.DataDir, "operations")
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		operationID := strings.TrimSuffix(entry.Name(), ".key")
		if peer, active := s.manager.PeerForOperation(operationID); active {
			if _, err := readClientProfile(s.options.DataDir, peer.Name); err != nil {
				continue
			}
		}
		_ = os.Remove(filepath.Join(directory, entry.Name()))
	}
}

// GetStatus returns the running device identity and its configured listener.
func (s *Service) GetStatus(context.Context, *emptypb.Empty) (*awgapi.StatusResponse, error) {
	publicKey, peers, err := s.manager.Status()
	if err != nil {
		return nil, mapError(err)
	}
	return &awgapi.StatusResponse{
		Running: true, PublicKey: publicKey,
		ListenPort: int32(s.options.ListenPort), PublicHost: s.options.PublicHost,
		PublicPort: int32(s.options.PublicPort), PeerCount: int32(peers),
		Ipv4Network: s.options.IPv4Prefix.String(), Ipv6Network: s.options.IPv6Prefix.String(),
		Protocol: "AmneziaWG", ServiceVersion: "prototype-v1",
	}, nil
}

// ListPeers returns current peer labels, public keys, and allocated tunnel addresses.
func (s *Service) ListPeers(context.Context, *emptypb.Empty) (*awgapi.ListPeersResponse, error) {
	peers := s.manager.Peers()
	items := make([]*awgapi.Peer, 0, len(peers))
	for _, peer := range peers {
		items = append(items, peerMessage(peer))
	}
	return &awgapi.ListPeersResponse{Peers: items}, nil
}

// GetPeerStats returns the live endpoint, handshake, and counters for each
// managed peer without returning any private configuration material.
func (s *Service) GetPeerStats(context.Context, *emptypb.Empty) (*awgapi.GetPeerStatsResponse, error) {
	peers, err := s.manager.PeerTelemetry()
	if err != nil {
		return nil, mapError(err)
	}
	items := make([]*awgapi.PeerStats, 0, len(peers))
	for _, peer := range peers {
		var lastHandshake *timestamppb.Timestamp
		if !peer.LastHandshake.IsZero() {
			lastHandshake = timestamppb.New(peer.LastHandshake.UTC())
		}
		items = append(items, &awgapi.PeerStats{
			Name: peer.Name, SourceIp: peer.SourceIP, LastHandshake: lastHandshake,
			UploadBytes: peer.UploadBytes, DownloadBytes: peer.DownloadBytes,
		})
	}
	return &awgapi.GetPeerStatsResponse{Peers: items}, nil
}

// WatchPeerStats streams coalesced peer counters. Online state is based on
// observed counter growth, with a recent handshake used only as an initial
// activity hint until the first sample delta is available.
func (s *Service) WatchPeerStats(request *awgapi.WatchPeerStatsRequest, stream awgapi.Control_WatchPeerStatsServer) error {
	if request == nil {
		return status.Error(codes.InvalidArgument, "watch request is required")
	}
	interval := time.Duration(request.GetSampleIntervalMs()) * time.Millisecond
	if interval < 500*time.Millisecond {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	previous := make(map[string][2]int64)
	lastActivity := make(map[string]time.Time)
	generation := s.startedAt.Format(time.RFC3339Nano)
	send := func() error {
		peers, err := s.manager.PeerTelemetry()
		if err != nil {
			return mapError(err)
		}
		now := time.Now().UTC()
		if s.telemetryNow != nil {
			now = s.telemetryNow().UTC()
		}
		seenPeers := make(map[string]struct{}, len(peers))
		update := &awgapi.PeerStatsUpdate{SampledAt: timestamppb.New(now), SourceGeneration: generation, FullSnapshot: true}
		for _, peer := range peers {
			current := [2]int64{peer.UploadBytes, peer.DownloadBytes}
			prior, sampled := previous[peer.Name]
			if sampled && (current[0] > prior[0] || current[1] > prior[1]) {
				lastActivity[peer.Name] = now
			} else if !sampled && !peer.LastHandshake.IsZero() {
				lastActivity[peer.Name] = peer.LastHandshake.UTC()
			}
			previous[peer.Name] = current
			seenPeers[peer.Name] = struct{}{}
			activity := lastActivity[peer.Name]
			item := &awgapi.PeerStats{Name: peer.Name, SourceIp: peer.SourceIP, UploadBytes: peer.UploadBytes, DownloadBytes: peer.DownloadBytes}
			if !peer.LastHandshake.IsZero() {
				item.LastHandshake = timestamppb.New(peer.LastHandshake.UTC())
			}
			if !activity.IsZero() {
				item.LastActivity = timestamppb.New(activity)
				item.Online = now.Sub(activity) <= 15*time.Second
			}
			if !item.Online {
				item.SourceIp = ""
			}
			update.Peers = append(update.Peers, item)
		}
		for name := range previous {
			if _, exists := seenPeers[name]; !exists {
				delete(previous, name)
				delete(lastActivity, name)
			}
		}
		s.mu.Lock()
		s.telemetrySequence++
		update.Sequence = s.telemetrySequence
		s.mu.Unlock()
		return stream.Send(update)
	}
	if err := send(); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			if err := send(); err != nil {
				return err
			}
		}
	}
}

// CreatePeer creates a keypair, registers its public key, and persists the
// corresponding private client profile for later authenticated delivery.
func (s *Service) CreatePeer(ctx context.Context, request *awgapi.CreatePeerRequest) (*awgapi.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := request.GetName()
	var err error
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if !servicePeerNamePattern.MatchString(name) {
		return nil, mapError(fmt.Errorf("invalid peer name: %w", ErrInvalid))
	}
	operationID := OperationID(ctx)
	if operationID != "" {
		if receipt, ok := s.manager.OperationReceipt(operationID); ok && (receipt.Action != "create" || receipt.Name != name) {
			return nil, status.Error(codes.Aborted, "operation ID was already used for a different peer")
		} else if ok && receipt.Removed {
			return nil, status.Error(codes.FailedPrecondition, "peer creation operation was already revoked")
		}
		if peer, ok := s.manager.PeerForOperation(operationID); ok {
			if peer.Name != name {
				return nil, status.Error(codes.Aborted, "operation ID was already used for a different peer")
			}
			if _, err := readClientProfile(s.options.DataDir, name); err == nil {
				_ = removePendingOperationKey(s.options.DataDir, operationID)
				return peerMessage(peer), nil
			}
			privateKey, err := readPendingOperationKey(s.options.DataDir, operationID)
			if err != nil {
				return nil, statusError("recover interrupted peer creation", err)
			}
			if err := s.persistPeerProfile(peer, privateKey, operationID); err != nil {
				return nil, statusError("recover interrupted peer creation", err)
			}
			return peerMessage(peer), nil
		}
	}

	privateKey, publicKey := "", ""
	if operationID != "" {
		privateKey, err = readPendingOperationKey(s.options.DataDir, operationID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, statusError("read peer creation intent", err)
		}
	}
	if privateKey != "" {
		_, publicKey, err = derivePublicKey(privateKey)
	} else {
		privateKey, publicKey, err = GenerateKeypair()
	}
	if err != nil {
		return nil, statusError("generate peer keypair", err)
	}
	if operationID != "" {
		if err := writePendingOperationKey(s.options.DataDir, operationID, privateKey); err != nil {
			return nil, statusError("persist peer creation intent", err)
		}
	}
	peer, repeated, err := s.manager.AddPeerForOperation(name, publicKey, operationID)
	if err != nil {
		return nil, mapError(err)
	}
	if repeated {
		privateKey, err = readPendingOperationKey(s.options.DataDir, operationID)
		if err != nil {
			return nil, statusError("recover interrupted peer creation", err)
		}
	}
	if err := s.persistPeerProfile(peer, privateKey, operationID); err != nil {
		if operationID == "" {
			_ = s.manager.RemovePeer(name)
		}
		return nil, statusError("persist client profile", err)
	}
	return peerMessage(peer), nil
}

func (s *Service) persistPeerProfile(peer Peer, privateKey, operationID string) error {
	config, err := s.manager.RenderClientConfig(peer.Name, privateKey)
	if err != nil {
		return fmt.Errorf("render client profile: %w", err)
	}
	if err := writeClientProfile(s.options.DataDir, peer.Name, config); err != nil {
		return fmt.Errorf("persist client profile: %w", err)
	}
	if operationID != "" {
		if err := removePendingOperationKey(s.options.DataDir, operationID); err != nil {
			return fmt.Errorf("complete peer creation receipt: %w", err)
		}
	}
	return nil
}

// AddPeer activates a peer immediately and persists it for process recovery.
func (s *Service) AddPeer(_ context.Context, request *awgapi.AddPeerRequest) (*awgapi.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.GetName() == "" || request.GetPublicKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "name and public key are required")
	}
	peer, err := s.manager.AddPeer(request.GetName(), request.GetPublicKey())
	if err != nil {
		return nil, mapError(err)
	}
	return peerMessage(peer), nil
}

// RemovePeer revokes the selected peer in the live device and persistent state.
func (s *Service) RemovePeer(ctx context.Context, request *awgapi.RemovePeerRequest) (*awgapi.RemovePeerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := request.GetName()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	var err error
	if operationID := OperationID(ctx); operationID != "" {
		_, err = s.manager.RemovePeerForOperation(name, operationID)
	} else {
		err = s.manager.RemovePeer(name)
	}
	if err != nil {
		return nil, mapError(err)
	}
	if err := removeClientProfile(s.options.DataDir, name); err != nil {
		return nil, statusError("remove saved client profile", err)
	}
	return &awgapi.RemovePeerResponse{Removed: true, Name: name}, nil
}

// GetClientConfig returns the private client profile for an active peer.
func (s *Service) GetClientConfig(_ context.Context, request *awgapi.GetClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := request.GetName()
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
	return &awgapi.ClientConfigResponse{Config: config}, nil
}

// RenderClientConfig returns a native profile without ever persisting the client private key.
func (s *Service) RenderClientConfig(_ context.Context, request *awgapi.RenderClientConfigRequest) (*awgapi.ClientConfigResponse, error) {
	name, privateKey := request.GetName(), request.GetPrivateKey()
	if name == "" || privateKey == "" {
		return nil, status.Error(codes.InvalidArgument, "name and private key are required")
	}
	config, err := s.manager.RenderClientConfig(name, privateKey)
	if err != nil {
		return nil, mapError(err)
	}
	return &awgapi.ClientConfigResponse{Config: config}, nil
}

func peerMessage(peer Peer) *awgapi.Peer {
	var createdAt *timestamppb.Timestamp
	if !peer.CreatedAt.IsZero() {
		createdAt = timestamppb.New(peer.CreatedAt.UTC())
	}
	return &awgapi.Peer{Name: peer.Name, PublicKey: peer.PublicKey, Ipv4: peer.IPv4, Ipv6: peer.IPv6, CreatedAt: createdAt}
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
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	return writeClientProfileWithPath(path, directory, config, func(dir, pattern string) (savedProfileFile, error) {
		return os.CreateTemp(dir, pattern)
	})
}

func pendingOperationKeyPath(dataDir, operationID string) (string, error) {
	if !operationIDPattern.MatchString(operationID) || strings.TrimSpace(dataDir) == "" {
		return "", ErrInvalid
	}
	return filepath.Join(dataDir, "operations", operationID+".key"), nil
}

func writePendingOperationKey(dataDir, operationID, privateKey string) error {
	path, err := pendingOperationKeyPath(dataDir, operationID)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if key, err := readPendingOperationKey(dataDir, operationID); err == nil {
		if key == privateKey {
			return nil
		}
		return ErrOperationConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(privateKey); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func readPendingOperationKey(dataDir, operationID string) (string, error) {
	path, err := pendingOperationKeyPath(dataDir, operationID)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256 {
		return "", errors.New("pending peer key is not a private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if _, err := decodeKey(key); err != nil {
		return "", errors.New("pending peer key is malformed")
	}
	return key, nil
}

func removePendingOperationKey(dataDir, operationID string) error {
	path, err := pendingOperationKeyPath(dataDir, operationID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type savedProfileFile interface {
	Name() string
	Chmod(os.FileMode) error
	WriteString(string) (int, error)
	Sync() error
	Close() error
}

func writeClientProfileWithPath(path, directory, config string, createTemp func(string, string) (savedProfileFile, error)) error {
	file, err := createTemp(directory, ".profile-*")
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
