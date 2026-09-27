package xrayapi

import (
	"context"
	"fmt"
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
}

type StatsClient struct {
	address string

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
		for _, ip := range user.GetIps() {
			if ip == nil || ip.GetLastSeen() <= 0 {
				continue
			}
			candidate := time.Unix(ip.GetLastSeen(), 0).UTC()
			if candidate.After(lastSeen) {
				lastSeen = candidate
			}
		}
		var upload, download int64
		if traffic := user.GetTraffic(); traffic != nil {
			upload, download = traffic.GetUplink(), traffic.GetDownlink()
		}
		result = append(result, UserStats{Email: user.GetEmail(), UploadBytes: nonNegative(upload), DownloadBytes: nonNegative(download), LastSeen: lastSeen})
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
	conn, err := grpc.DialContext(dialCtx, c.address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
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
