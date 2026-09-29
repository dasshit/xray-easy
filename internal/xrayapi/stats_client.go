package xrayapi

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	statscommand "xray-easy/internal/xrayapi/stats"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// UserStats is the small, versioned representation consumed by the control
// plane. Keeping the generated Xray protobuf types behind this adapter makes
// the rest of the application independent from upstream package paths.
type UserStats struct {
	Email         string
	UploadBytes   int64
	DownloadBytes int64
	LastSeen      time.Time
	SourceIPs     []IPObservation
}

// IPObservation is one client source address and its latest Xray timestamp.
type IPObservation struct {
	Address  string
	LastSeen time.Time
}

type StatsClient struct {
	address     string
	dialOptions []grpc.DialOption

	mu     sync.Mutex
	conn   *grpc.ClientConn
	client statscommand.StatsServiceClient
}

func NewStatsClient(address string) *StatsClient {
	return &StatsClient{address: address}
}

func (c *StatsClient) Poll(ctx context.Context) ([]UserStats, error) {
	client, err := c.service(ctx)
	if err != nil {
		return nil, err
	}
	response, err := client.GetUsersStats(ctx, &statscommand.GetUsersStatsRequest{IncludeTraffic: true})
	if err != nil {
		c.reset()
		return nil, fmt.Errorf("get users stats: %w", err)
	}
	result := make([]UserStats, 0, len(response.GetUsers()))
	for _, user := range response.GetUsers() {
		if user == nil || user.GetEmail() == "" {
			continue
		}
		var lastSeen time.Time
		sourceIPs := make([]IPObservation, 0, len(user.GetIps()))
		seenIPs := make(map[string]int, len(user.GetIps()))
		for _, ip := range user.GetIps() {
			if ip == nil || ip.GetLastSeen() <= 0 {
				continue
			}
			address, err := netip.ParseAddr(ip.GetIp())
			if err != nil {
				continue
			}
			candidate := time.Unix(ip.GetLastSeen(), 0).UTC()
			if candidate.After(lastSeen) {
				lastSeen = candidate
			}
			canonical := address.WithZone("").String()
			if index, exists := seenIPs[canonical]; exists {
				if candidate.After(sourceIPs[index].LastSeen) {
					sourceIPs[index].LastSeen = candidate
				}
			} else {
				seenIPs[canonical] = len(sourceIPs)
				sourceIPs = append(sourceIPs, IPObservation{Address: canonical, LastSeen: candidate})
			}
		}
		var upload, download int64
		if traffic := user.GetTraffic(); traffic != nil {
			upload, download = traffic.GetUplink(), traffic.GetDownlink()
		}
		result = append(result, UserStats{Email: user.GetEmail(), UploadBytes: nonNegative(upload), DownloadBytes: nonNegative(download), LastSeen: lastSeen, SourceIPs: sourceIPs})
	}
	return result, nil
}

func (c *StatsClient) service(ctx context.Context) (statscommand.StatsServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	if c.address == "" {
		return nil, fmt.Errorf("Xray API address is empty")
	}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, c.address, append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock()}, c.dialOptions...)...)
	if err != nil {
		return nil, fmt.Errorf("connect to Xray API %s: %w", c.address, err)
	}
	c.conn = conn
	c.client = statscommand.NewStatsServiceClient(conn)
	return c.client, nil
}

func (c *StatsClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.client = nil, nil
}

func (c *StatsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.client = nil, nil
	return err
}

func nonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}
