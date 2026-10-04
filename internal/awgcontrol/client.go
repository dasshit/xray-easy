// Package awgcontrol provides the authenticated gRPC gateway to the optional
// AmneziaWG service container.
package awgcontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	awgapi "xray-easy/awg-contract/api/v1"
	"xray-easy/internal/domain"
	"xray-easy/internal/interaction"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// serviceName is an internal package constant.
const serviceName = "/xrayeasy.awg.v1.Control/"

// Gateway exposes only the AWG operations needed by the application layer.
type Gateway interface {
	// Status returns the requested state.
	Status(context.Context) (domain.AmneziaWGStatus, error)
	// ListPeers returns the requested collection.
	ListPeers(context.Context) ([]domain.AmneziaWGPeer, error)
	// CreatePeer creates the requested value.
	CreatePeer(context.Context, string, *time.Time) (domain.AmneziaWGPeer, error)
	// SetPeerEnabled changes active state without removing peer identity or profile material.
	SetPeerEnabled(context.Context, string, bool) (domain.AmneziaWGPeer, error)
	// SetPeerExpiry updates or clears the peer's expiration deadline.
	SetPeerExpiry(context.Context, string, *time.Time) (domain.AmneziaWGPeer, error)
	// RemovePeer removes the supplied value.
	RemovePeer(context.Context, string) error
	// ClientConfig returns the requested state.
	ClientConfig(context.Context, string) (string, error)
}

// connection is an internal type used by the package.
type connection interface {
	grpc.ClientConnInterface
	// Close defines part of the interface contract.
	Close() error
}

// Client invokes the private AWG gRPC API using its shared bearer token.
type Client struct {
	connection      connection
	client          awgapi.ControlClient
	token           string
	makeOutgoingCtx func(context.Context) (context.Context, string, error)
}

// Dial reads the private token file and prepares a connection to the AWG
// service. Network connectivity is checked on the first RPC.
func Dial(address, tokenPath string) (*Client, error) {
	return dialWith(address, tokenPath, func(target string, options ...grpc.DialOption) (connection, error) {
		return grpc.NewClient(target, options...)
	})
}

func dialWith(address, tokenPath string, newConnection func(string, ...grpc.DialOption) (connection, error)) (*Client, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read AWG control token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("AWG control token is empty")
	}
	conn, err := newConnection(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("create AWG gRPC client: %w", err)
	}
	return &Client{connection: conn, client: awgapi.NewControlClient(conn), token: token}, nil
}

// Status reads the current server endpoint and peer count.
func (c *Client) Status(ctx context.Context) (domain.AmneziaWGStatus, error) {
	var response *awgapi.StatusResponse
	err := c.call(ctx, "GetStatus", func(ctx context.Context) error {
		var err error
		response, err = c.client.GetStatus(ctx, &emptypb.Empty{})
		return err
	})
	if err != nil {
		return domain.AmneziaWGStatus{}, err
	}
	if response == nil || response.GetPublicKey() == "" || response.GetPublicHost() == "" ||
		response.GetIpv4Network() == "" || response.GetIpv6Network() == "" || response.GetServiceVersion() == "" ||
		response.GetListenPort() <= 0 || response.GetPublicPort() <= 0 || response.GetPeerCount() < 0 {
		return domain.AmneziaWGStatus{}, errors.New("AWG response has invalid status fields")
	}
	return domain.AmneziaWGStatus{
		Running: response.GetRunning(), PublicKey: response.GetPublicKey(),
		ListenPort: int(response.GetListenPort()), PublicPort: int(response.GetPublicPort()),
		PublicHost: response.GetPublicHost(), PeerCount: int(response.GetPeerCount()),
		IPv4Network: response.GetIpv4Network(), IPv6Network: response.GetIpv6Network(),
		ServiceVersion: response.GetServiceVersion(),
	}, nil
}

// ListPeers reads the peers currently persisted by the AWG service.
func (c *Client) ListPeers(ctx context.Context) ([]domain.AmneziaWGPeer, error) {
	var response *awgapi.ListPeersResponse
	if err := c.call(ctx, "ListPeers", func(ctx context.Context) error {
		var err error
		response, err = c.client.ListPeers(ctx, &emptypb.Empty{})
		return err
	}); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("AWG response is missing")
	}
	peers := make([]domain.AmneziaWGPeer, 0, len(response.GetPeers()))
	for _, item := range response.GetPeers() {
		peer, err := parsePeer(item)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

// PeerStats reads live per-peer counters and endpoint metadata. Empty handshake
// and source fields mean that no peer connection has been observed yet.
func (c *Client) PeerStats(ctx context.Context) ([]domain.AmneziaWGPeerStats, error) {
	var response *awgapi.GetPeerStatsResponse
	if err := c.call(ctx, "GetPeerStats", func(ctx context.Context) error {
		var err error
		response, err = c.client.GetPeerStats(ctx, &emptypb.Empty{})
		return err
	}); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("AWG response is missing")
	}
	peers := make([]domain.AmneziaWGPeerStats, 0, len(response.GetPeers()))
	for _, item := range response.GetPeers() {
		if item == nil || item.GetName() == "" || item.GetUploadBytes() < 0 || item.GetDownloadBytes() < 0 {
			return nil, errors.New("AWG response contains invalid peer stats")
		}
		lastSeen := time.Time{}
		if item.GetLastHandshake() != nil {
			if err := item.GetLastHandshake().CheckValid(); err != nil {
				return nil, fmt.Errorf("AWG response field lastHandshake is invalid: %w", err)
			}
			lastSeen = item.GetLastHandshake().AsTime()
		}
		peers = append(peers, domain.AmneziaWGPeerStats{
			Name: item.GetName(), SourceIP: item.GetSourceIp(), LastSeen: lastSeen,
			UploadBytes: item.GetUploadBytes(), DownloadBytes: item.GetDownloadBytes(),
		})
	}
	return peers, nil
}

// WatchPeerStats opens the authenticated AWG peer telemetry stream.
func (c *Client) WatchPeerStats(ctx context.Context, interval time.Duration) (awgapi.Control_WatchPeerStatsClient, error) {
	if interval < 500*time.Millisecond {
		interval = time.Second
	}
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	ctx, requestID, err := c.outgoingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create AWG stream request ID: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	method := serviceName + "WatchPeerStats"
	started := time.Now()
	stream, err := c.client.WatchPeerStats(ctx, &awgapi.WatchPeerStatsRequest{SampleIntervalMs: uint32(interval.Milliseconds())})
	if err != nil {
		interaction.LogRPC(slog.Default(), "awg-client", method, requestID, "amneziawg", started, err, interaction.TraceFromContext(ctx))
		return nil, fmt.Errorf("open AWG telemetry stream: %w", err)
	}
	slog.Default().Info("grpc stream started", "service", "awg-client", "method", method, "request_id", requestID, "protocol", "amneziawg")
	return &loggedPeerStatsStream{Control_WatchPeerStatsClient: stream, requestID: requestID, started: started}, nil
}

// loggedPeerStatsStream is an internal type used by the package.
type loggedPeerStatsStream struct {
	awgapi.Control_WatchPeerStatsClient
	requestID string
	started   time.Time
	logged    bool
}

// Recv receives the next value from the stream.
func (s *loggedPeerStatsStream) Recv() (*awgapi.PeerStatsUpdate, error) {
	response, err := s.Control_WatchPeerStatsClient.Recv()
	if err != nil && !s.logged {
		s.logged = true
		logErr := err
		if errors.Is(logErr, io.EOF) {
			logErr = nil
		}
		interaction.LogRPC(slog.Default(), "awg-client", serviceName+"WatchPeerStats", s.requestID, "amneziawg", s.started, logErr, interaction.Trace{})
	}
	return response, err
}

// CreatePeer generates the device keypair and registers a persistent peer.
func (c *Client) CreatePeer(ctx context.Context, name string, expiresAt *time.Time) (domain.AmneziaWGPeer, error) {
	var response *awgapi.Peer
	if err := c.call(ctx, "CreatePeer", func(ctx context.Context) error {
		var err error
		request := &awgapi.CreatePeerRequest{Name: name}
		if expiresAt != nil {
			request.ExpiresAt = timestamppb.New(expiresAt.UTC())
		}
		response, err = c.client.CreatePeer(ctx, request)
		return err
	}); err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return parsePeer(response)
}

// SetPeerEnabled changes active state through the private AWG service API.
func (c *Client) SetPeerEnabled(ctx context.Context, name string, enabled bool) (domain.AmneziaWGPeer, error) {
	var response *awgapi.Peer
	if err := c.call(ctx, "SetPeerEnabled", func(ctx context.Context) error {
		var err error
		response, err = c.client.SetPeerEnabled(ctx, &awgapi.SetPeerEnabledRequest{Name: name, Enabled: enabled})
		return err
	}); err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return parsePeer(response)
}

// SetPeerExpiry changes or clears the peer expiry through the private AWG service API.
func (c *Client) SetPeerExpiry(ctx context.Context, name string, expiresAt *time.Time) (domain.AmneziaWGPeer, error) {
	var response *awgapi.Peer
	if err := c.call(ctx, "SetPeerExpiry", func(ctx context.Context) error {
		var err error
		request := &awgapi.SetPeerExpiryRequest{Name: name, ClearExpiry: expiresAt == nil}
		if expiresAt != nil {
			request.ExpiresAt = timestamppb.New(expiresAt.UTC())
		}
		response, err = c.client.SetPeerExpiry(ctx, request)
		return err
	}); err != nil {
		return domain.AmneziaWGPeer{}, err
	}
	return parsePeer(response)
}

// RemovePeer revokes the peer and deletes its saved client profile.
func (c *Client) RemovePeer(ctx context.Context, name string) error {
	return c.call(ctx, "RemovePeer", func(ctx context.Context) error {
		_, err := c.client.RemovePeer(ctx, &awgapi.RemovePeerRequest{Name: name})
		return err
	})
}

// ClientConfig returns the credential-bearing profile for an active peer.
func (c *Client) ClientConfig(ctx context.Context, name string) (string, error) {
	var response *awgapi.ClientConfigResponse
	if err := c.call(ctx, "GetClientConfig", func(ctx context.Context) error {
		var err error
		response, err = c.client.GetClientConfig(ctx, &awgapi.GetClientConfigRequest{Name: name})
		return err
	}); err != nil {
		return "", err
	}
	if response == nil || response.GetConfig() == "" {
		return "", errors.New("AWG response field config is missing or empty")
	}
	return response.GetConfig(), nil
}

// ExportBackup reads a validated, compressed snapshot containing server state
// and client profiles. The returned archive includes private client keys.
func (c *Client) ExportBackup(ctx context.Context) ([]byte, error) {
	var response *awgapi.BackupResponse
	if err := c.call(ctx, "ExportBackup", func(ctx context.Context) error {
		var err error
		response, err = c.client.ExportBackup(ctx, &emptypb.Empty{})
		return err
	}); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("AWG backup response is missing")
	}
	return response.GetData(), nil
}

// RestoreBackup validates and applies a snapshot, including its client private
// profiles, through the private AWG control service.
func (c *Client) RestoreBackup(ctx context.Context, data []byte) error {
	return c.call(ctx, "RestoreBackup", func(ctx context.Context) error {
		_, err := c.client.RestoreBackup(ctx, &awgapi.RestoreBackupRequest{Data: data})
		return err
	})
}

// Close releases the underlying HTTP/2 connection.
func (c *Client) Close() error { return c.connection.Close() }

// call performs the operation represented by its name.
func (c *Client) call(ctx context.Context, method string, invoke func(context.Context) error) error {
	ctx, requestID, err := c.outgoingContext(ctx)
	if err != nil {
		return fmt.Errorf("create AWG request ID: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	fullMethod := serviceName + method
	started := time.Now()
	err = invoke(ctx)
	interaction.LogRPC(slog.Default(), "awg-client", fullMethod, requestID, "amneziawg", started, err, interaction.TraceFromContext(ctx))
	if err != nil {
		return fmt.Errorf("AWG %s failed: %w", method, err)
	}
	return nil
}

func (c *Client) outgoingContext(ctx context.Context) (context.Context, string, error) {
	if c.makeOutgoingCtx != nil {
		return c.makeOutgoingCtx(ctx)
	}
	return interaction.OutgoingContext(ctx)
}

// parsePeer parses the supplied value.
func parsePeer(peer *awgapi.Peer) (domain.AmneziaWGPeer, error) {
	if peer == nil || peer.GetName() == "" || peer.GetPublicKey() == "" || peer.GetIpv4() == "" || peer.GetIpv6() == "" {
		return domain.AmneziaWGPeer{}, errors.New("AWG response contains an incomplete peer")
	}
	if peer.GetCreatedAt() == nil {
		return domain.AmneziaWGPeer{}, errors.New("AWG response field createdAt is missing")
	}
	if err := peer.GetCreatedAt().CheckValid(); err != nil {
		return domain.AmneziaWGPeer{}, fmt.Errorf("AWG response field createdAt is invalid: %w", err)
	}
	var expiresAt *time.Time
	if peer.GetExpiresAt() != nil {
		if err := peer.GetExpiresAt().CheckValid(); err != nil {
			return domain.AmneziaWGPeer{}, fmt.Errorf("AWG response field expiresAt is invalid: %w", err)
		}
		deadline := peer.GetExpiresAt().AsTime().UTC()
		expiresAt = &deadline
	}
	return domain.AmneziaWGPeer{
		Name: peer.GetName(), PublicKey: peer.GetPublicKey(), IPv4: peer.GetIpv4(), IPv6: peer.GetIpv6(),
		CreatedAt: peer.GetCreatedAt().AsTime(), ExpiresAt: expiresAt, Disabled: peer.GetDisabled(),
	}, nil
}

var _ Gateway = (*Client)(nil)
var _ interface {
	ExportBackup(context.Context) ([]byte, error)
	RestoreBackup(context.Context, []byte) error
} = (*Client)(nil)
