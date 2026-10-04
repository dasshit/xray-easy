package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

const (
	// connectionMonitorInterval is the interval between background connection samples.
	connectionMonitorInterval = time.Second
	// peerOnlineWindow is the maximum time since observed activity for a peer to remain online.
	peerOnlineWindow = 15 * time.Second
	// expirationMonitorInterval is the cadence for durable AWG expiry enforcement.
	expirationMonitorInterval = time.Second
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

// servicePeerNamePattern is an internal package variable.
var servicePeerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// NewService creates the RPC adapter for a configured lifecycle manager.
func NewService(manager *Manager, options Options) *Service {
	service := &Service{manager: manager, options: options, startedAt: time.Now().UTC()}
	service.removeOrphanedOperationKeys()
	return service
}

// removeOrphanedOperationKeys removes the supplied value.
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
				item.Online = now.Sub(activity) <= peerOnlineWindow
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

// RunConnectionMonitor continuously samples peer telemetry and logs connection
// state transitions independently of WatchPeerStats subscribers.
func (s *Service) RunConnectionMonitor(ctx context.Context) {
	s.runConnectionMonitor(ctx, connectionMonitorInterval)
}

// runConnectionMonitor samples peers until ctx is canceled.
func (s *Service) runConnectionMonitor(ctx context.Context, interval time.Duration) {
	if s == nil || s.manager == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = connectionMonitorInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	previous := make(map[string][2]int64)
	lastActivity := make(map[string]time.Time)
	previousOnline := make(map[string]bool)
	knownState := make(map[string]bool)
	snapshotFailed := false
	sample := func() {
		peers, err := s.manager.PeerTelemetry()
		if err != nil {
			if !snapshotFailed {
				slog.Warn("AWG connection monitor snapshot failed", "service", "amneziawg-service", "component", "connection", "event", "snapshot_failed")
			}
			snapshotFailed = true
			return
		}
		if snapshotFailed {
			slog.Info("AWG connection monitor snapshot recovered", "service", "amneziawg-service", "component", "connection", "event", "snapshot_recovered")
			snapshotFailed = false
		}
		now := time.Now().UTC()
		if s.telemetryNow != nil {
			now = s.telemetryNow().UTC()
		}
		seenPeers := make(map[string]struct{}, len(peers))
		for _, peer := range peers {
			if peer.Name == "" {
				continue
			}
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
			online := !activity.IsZero() && now.Sub(activity) <= peerOnlineWindow
			if online != previousOnline[peer.Name] && (knownState[peer.Name] || online) {
				event, detail := "peer_offline", "no traffic observed for the online window"
				if online {
					event, detail = "peer_online", "traffic observed within the online window"
				}
				attrs := []any{"service", "amneziawg-service", "component", "connection", "event", event, "peer_name", peer.Name, "detail", detail}
				if peer.SourceIP != "" {
					attrs = append(attrs, "source_ip", peer.SourceIP)
				}
				slog.Info("AWG connection event", attrs...)
			}
			previousOnline[peer.Name] = online
			knownState[peer.Name] = true
		}
		for name := range previous {
			if _, exists := seenPeers[name]; !exists {
				delete(previous, name)
				delete(lastActivity, name)
				delete(previousOnline, name)
				delete(knownState, name)
			}
		}
	}
	sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}

// CreatePeer creates a keypair, registers its public key, and persists the
// corresponding private client profile for later authenticated delivery.
func (s *Service) CreatePeer(ctx context.Context, request *awgapi.CreatePeerRequest) (*awgapi.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "create peer request is required")
	}
	name := request.GetName()
	var err error
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if !servicePeerNamePattern.MatchString(name) {
		return nil, mapError(fmt.Errorf("invalid peer name: %w", ErrInvalid))
	}
	expiresAt, err := expiryFromProto(request.GetExpiresAt(), s.nowUTC())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	operationID := OperationID(ctx)
	if operationID != "" {
		if receipt, ok := s.manager.OperationReceipt(operationID); ok && (receipt.Action != "create" || receipt.Name != name) {
			return nil, status.Error(codes.Aborted, "operation ID was already used for a different peer")
		} else if ok && receipt.Removed {
			return nil, status.Error(codes.FailedPrecondition, "peer creation operation was already revoked")
		}
		if peer, ok := s.manager.PeerForOperation(operationID); ok {
			if peer.Name != name || !sameExpiry(peer.ExpiresAt, expiresAt) {
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
	peer, repeated, err := s.manager.AddPeerWithExpiry(name, publicKey, operationID, expiresAt)
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

// SetPeerEnabled enables or reversibly disables a peer without deleting its identity.
func (s *Service) SetPeerEnabled(_ context.Context, request *awgapi.SetPeerEnabledRequest) (*awgapi.Peer, error) {
	if request == nil || !servicePeerNamePattern.MatchString(request.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "valid peer name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, err := s.manager.SetPeerEnabled(request.GetName(), request.GetEnabled())
	if err != nil {
		return nil, mapError(err)
	}
	return peerMessage(peer), nil
}

// SetPeerExpiry sets or clears a peer's UTC expiration deadline without enabling it.
func (s *Service) SetPeerExpiry(_ context.Context, request *awgapi.SetPeerExpiryRequest) (*awgapi.Peer, error) {
	if request == nil || !servicePeerNamePattern.MatchString(request.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "valid peer name is required")
	}
	if request.GetClearExpiry() && request.GetExpiresAt() != nil {
		return nil, status.Error(codes.InvalidArgument, "clear_expiry and expires_at are mutually exclusive")
	}
	if !request.GetClearExpiry() && request.GetExpiresAt() == nil {
		return nil, status.Error(codes.InvalidArgument, "expires_at or clear_expiry is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var expiresAt *time.Time
	if !request.GetClearExpiry() {
		value, err := expiryFromProto(request.GetExpiresAt(), s.nowUTC())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		expiresAt = value
	}
	peer, err := s.manager.SetPeerExpiry(request.GetName(), expiresAt)
	if err != nil {
		return nil, mapError(err)
	}
	return peerMessage(peer), nil
}

// RunExpirationMonitor sweeps due peer deadlines independently of gRPC streams.
func (s *Service) RunExpirationMonitor(ctx context.Context) {
	s.runExpirationMonitor(ctx, expirationMonitorInterval)
}

// runExpirationMonitor repeatedly disables due peers until ctx is canceled.
func (s *Service) runExpirationMonitor(ctx context.Context, interval time.Duration) {
	if s == nil || s.manager == nil || ctx == nil {
		return
	}
	if interval <= 0 {
		interval = expirationMonitorInterval
	}
	sweep := func() {
		peers, err := s.manager.ExpireDuePeers(s.nowUTC())
		for _, peer := range peers {
			slog.Info("AWG peer expired", "service", "amneziawg-service", "component", "peer", "event", "peer_expired", "peer_name", peer.Name)
		}
		if err != nil {
			slog.Warn("AWG peer expiry enforcement will retry", "service", "amneziawg-service", "component", "peer", "event", "peer_expiry_retry", "error", err)
		}
	}
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// nowUTC returns the service clock in UTC, using the injected clock in tests.
func (s *Service) nowUTC() time.Time {
	if s != nil && s.telemetryNow != nil {
		return s.telemetryNow().UTC()
	}
	return time.Now().UTC()
}

// expiryFromProto validates a protobuf deadline and returns its UTC instant.
func expiryFromProto(value *timestamppb.Timestamp, now time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	if err := value.CheckValid(); err != nil {
		return nil, fmt.Errorf("expires_at must be a valid timestamp: %w", err)
	}
	deadline := value.AsTime().UTC()
	if !deadline.After(now) {
		return nil, errors.New("expires_at must be in the future")
	}
	return &deadline, nil
}

// persistPeerProfile performs the operation represented by its name.
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

// peerMessage performs the operation represented by its name.
func peerMessage(peer Peer) *awgapi.Peer {
	var createdAt *timestamppb.Timestamp
	var expiresAt *timestamppb.Timestamp
	if !peer.CreatedAt.IsZero() {
		createdAt = timestamppb.New(peer.CreatedAt.UTC())
	}
	if peer.ExpiresAt != nil {
		expiresAt = timestamppb.New(peer.ExpiresAt.UTC())
	}
	return &awgapi.Peer{Name: peer.Name, PublicKey: peer.PublicKey, Ipv4: peer.IPv4, Ipv6: peer.IPv6, CreatedAt: createdAt, ExpiresAt: expiresAt, Disabled: peer.Disabled}
}

var _ API = (*Service)(nil)

// clientProfilePath performs the operation represented by its name.
func clientProfilePath(dataDir, name string) (string, error) {
	if !servicePeerNamePattern.MatchString(name) {
		return "", ErrInvalid
	}
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("AWG data directory is not configured")
	}
	return filepath.Join(dataDir, "profiles", name+".conf"), nil
}

// writeClientProfile writes the supplied value.
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

// pendingOperationKeyPath performs the operation represented by its name.
func pendingOperationKeyPath(dataDir, operationID string) (string, error) {
	if !operationIDPattern.MatchString(operationID) || strings.TrimSpace(dataDir) == "" {
		return "", ErrInvalid
	}
	return filepath.Join(dataDir, "operations", operationID+".key"), nil
}

// writePendingOperationKey writes the supplied value.
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
	return persistPendingOperationKey(file, path, privateKey, os.Remove)
}

// pendingOperationFile is the durable writer used to stage an encrypted operation key.
type pendingOperationFile interface {
	// WriteString writes the complete key representation to the staged file.
	WriteString(string) (int, error)
	// Sync flushes staged key bytes before the file is published.
	Sync() error
	// Close releases the staged key file.
	Close() error
}

// persistPendingOperationKey writes, syncs, and closes a pending key, removing it on failure.
func persistPendingOperationKey(file pendingOperationFile, path, privateKey string, remove func(string) error) error {
	if _, err := file.WriteString(privateKey); err != nil {
		_ = file.Close()
		_ = remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = remove(path)
		return err
	}
	return file.Close()
}

// readPendingOperationKey reads the requested value.
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

// removePendingOperationKey removes the supplied value.
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

// savedProfileFile is an internal type used by the package.
type savedProfileFile interface {
	// Name defines part of the interface contract.
	Name() string
	// Chmod defines part of the interface contract.
	Chmod(os.FileMode) error
	// WriteString defines part of the interface contract.
	WriteString(string) (int, error)
	// Sync defines part of the interface contract.
	Sync() error
	// Close defines part of the interface contract.
	Close() error
}

// writeClientProfileWithPath writes the supplied value.
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

// readClientProfile reads the requested value.
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

// privateKeyFromProfile performs the operation represented by its name.
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

// removeClientProfile removes the supplied value.
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

// statusError performs the operation represented by its name.
func statusError(operation string, _ error) error {
	return status.Error(codes.Internal, operation+" failed")
}
