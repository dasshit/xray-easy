package grpcshutdown

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestStopReturnsAfterGracefulShutdown(t *testing.T) {
	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())
	listener := bufconn.Listen(1 << 20)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	Stop(server, time.Second)
	select {
	case <-serveErr:
	case <-time.After(time.Second):
		t.Fatal("gRPC Serve remained blocked after graceful shutdown")
	}
	_ = listener.Close()
}

func TestStopForcesShutdownWhenStreamStaysOpen(t *testing.T) {
	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())
	listener := bufconn.Listen(1 << 20)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	stream, err := healthpb.NewHealthClient(connection).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("health Watch did not become active: %v", err)
	}

	start := time.Now()
	Stop(server, 25*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("forced gRPC shutdown took %v", elapsed)
	}
	select {
	case <-serveErr:
	case <-time.After(time.Second):
		t.Fatal("gRPC Serve remained blocked after forced shutdown")
	}
	_ = listener.Close()
}

func TestStopHandlesNilServerAndDefaultTimeout(t *testing.T) {
	Stop(nil, time.Millisecond)
	server := grpc.NewServer()
	Stop(server, 0)
}
