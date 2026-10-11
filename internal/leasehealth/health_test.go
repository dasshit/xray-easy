package leasehealth

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestCheckWithDialerReportsReadyAndNotReady(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Error("health gRPC server did not stop")
		}
	})
	dialer := func(context.Context, string) (net.Conn, error) { return listener.Dial() }

	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	ready, err := CheckWithDialer(context.Background(), "bufnet:8091", dialer)
	if err != nil || !ready {
		t.Fatalf("serving health check = %v, %v", ready, err)
	}
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	ready, err = CheckWithDialer(context.Background(), "bufnet:8091", dialer)
	if err != nil || ready {
		t.Fatalf("not-serving health check = %v, %v", ready, err)
	}
}

func TestCheckWithDialerValidatesAddressAndReturnsTransportErrors(t *testing.T) {
	for _, address := range []string{"", "invalid", ":8091", "host:0", "host:65536", "bad host:8091"} {
		if _, err := Check(context.Background(), address); err == nil || !strings.Contains(err.Error(), "address is invalid") {
			t.Errorf("Check(%q) error = %v, want invalid address", address, err)
		}
	}
	ready, err := CheckWithDialer(context.Background(), "bufnet:8091", func(context.Context, string) (net.Conn, error) {
		return nil, net.ErrClosed
	})
	if err == nil || ready || !strings.Contains(err.Error(), "health gRPC check failed") {
		t.Fatalf("failed transport check = %v, %v", ready, err)
	}
}

func TestCheckUsesBoundedContextAndPlaintextGRPC(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ready, err := CheckWithDialer(ctx, "bufnet:8091", func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	})
	if err == nil || ready {
		t.Fatalf("canceled health check = %v, %v", ready, err)
	}
}

func TestCheckReturnsWhenCallerDeadlineExpiresDuringDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	ready, err := CheckWithDialer(ctx, "bufnet:8091", func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err == nil || ready {
		t.Fatalf("deadline health check = %v, %v; want an error", ready, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("health check ignored caller deadline for %v", elapsed)
	}
}
