package xrayapi

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	statscommand "xray-easy/internal/xrayapi/stats"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type statsTestServer struct {
	statscommand.UnimplementedStatsServiceServer
	users   []*statscommand.UserStat
	err     error
	calls   int
	request *statscommand.GetUsersStatsRequest
}

func (s *statsTestServer) GetUsersStats(_ context.Context, request *statscommand.GetUsersStatsRequest) (*statscommand.GetUsersStatsResponse, error) {
	s.calls++
	s.request = request
	if s.err != nil {
		return nil, s.err
	}
	return &statscommand.GetUsersStatsResponse{Users: s.users}, nil
}

func newStatsTestClient(t *testing.T, implementation statscommand.StatsServiceServer) *StatsClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	statscommand.RegisterStatsServiceServer(server, implementation)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	client := NewStatsClient("passthrough:///stats-test")
	client.dialOptions = []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	})}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestStatsClientPollMapsAndSanitizesUserStats(t *testing.T) {
	implementation := &statsTestServer{users: []*statscommand.UserStat{
		nil,
		{},
		{Email: "phone@example.test", Ips: []*statscommand.OnlineIPEntry{
			nil,
			{Ip: "192.0.2.1", LastSeen: -1},
			{Ip: "192.0.2.2", LastSeen: 100},
			{Ip: "192.0.2.3", LastSeen: 200},
			{Ip: "192.0.2.4", LastSeen: 150},
		}, Traffic: &statscommand.TrafficUserStat{Uplink: 1234, Downlink: 5678}},
		{Email: "legacy@example.test", Ips: []*statscommand.OnlineIPEntry{{Ip: "192.0.2.5", LastSeen: 0}}, Traffic: nil},
		{Email: "negative@example.test", Traffic: &statscommand.TrafficUserStat{Uplink: -10, Downlink: -20}},
	}}
	client := newStatsTestClient(t, implementation)
	users, err := client.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("Poll returned %d users: %+v", len(users), users)
	}
	if users[0].Email != "phone@example.test" || users[0].UploadBytes != 1234 || users[0].DownloadBytes != 5678 || !users[0].LastSeen.Equal(time.Unix(200, 0).UTC()) {
		t.Fatalf("mapped traffic stats = %+v", users[0])
	}
	if users[1].Email != "legacy@example.test" || users[1].UploadBytes != 0 || users[1].DownloadBytes != 0 || !users[1].LastSeen.IsZero() {
		t.Fatalf("missing traffic/IP stats = %+v", users[1])
	}
	if users[2].UploadBytes != 0 || users[2].DownloadBytes != 0 {
		t.Fatalf("negative traffic values were not clamped: %+v", users[2])
	}
	if implementation.calls != 1 || implementation.request == nil || !implementation.request.GetIncludeTraffic() || implementation.request.GetReset_() {
		t.Fatalf("GetUsersStats request = %+v, calls=%d", implementation.request, implementation.calls)
	}
}

func TestStatsClientHandlesUnimplementedMethodAndReconnectsAfterRPCError(t *testing.T) {
	legacyServer := statscommand.UnimplementedStatsServiceServer{}
	legacy := newStatsTestClient(t, legacyServer)
	_, err := legacy.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "get users stats") || status.Code(errors.Unwrap(err)) != codes.Unimplemented {
		t.Fatalf("legacy Xray GetUsersStats error = %v", err)
	}
	if legacy.conn != nil || legacy.client != nil {
		t.Fatal("Unimplemented response did not reset gRPC connection")
	}
	_ = legacy.Close()

	implementation := &statsTestServer{err: status.Error(codes.Unavailable, "restarting")}
	client := newStatsTestClient(t, implementation)
	if _, err := client.Poll(context.Background()); err == nil {
		t.Fatal("temporary StatsService failure was ignored")
	}
	if client.conn != nil || client.client != nil {
		t.Fatal("failed StatsService call did not reset the connection")
	}
	implementation.err = nil
	implementation.users = []*statscommand.UserStat{{Email: "recovered@example.test"}}
	users, err := client.Poll(context.Background())
	if err != nil || len(users) != 1 || users[0].Email != "recovered@example.test" {
		t.Fatalf("StatsService after reconnect = %+v, %v", users, err)
	}
}

func TestStatsClientEmptyAddressDialFailureAndClose(t *testing.T) {
	if _, err := NewStatsClient("").Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "address is empty") {
		t.Fatalf("empty address error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	failedDial := NewStatsClient("stats-test")
	failedDial.dialOptions = []grpc.DialOption{grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return nil, errors.New("dial denied") })}
	if _, err := failedDial.Poll(ctx); err == nil || !strings.Contains(err.Error(), "connect to Xray API") {
		t.Fatalf("dial failure error = %v", err)
	}
	client := newStatsTestClient(t, &statsTestServer{})
	if _, err := client.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.conn == nil || client.client == nil {
		t.Fatal("successful Poll did not retain its gRPC connection")
	}
	if err := client.Close(); err != nil || client.conn != nil || client.client != nil {
		t.Fatalf("Close state = conn:%v client:%v error:%v", client.conn, client.client, err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestNonNegative(t *testing.T) {
	for _, test := range []struct{ input, want int64 }{{-1, 0}, {0, 0}, {1, 1}} {
		if got := nonNegative(test.input); got != test.want {
			t.Errorf("nonNegative(%d) = %d, want %d", test.input, got, test.want)
		}
	}
}
