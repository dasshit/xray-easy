// Package grpcshutdown provides bounded graceful shutdown for long-lived gRPC
// streams used by the backend services.
package grpcshutdown

import (
	"time"

	"google.golang.org/grpc"
)

const defaultTimeout = 3 * time.Second

// Stop gives active RPCs a bounded grace period, then forces the server down.
func Stop(server *grpc.Server, timeout time.Duration) {
	if server == nil {
		return
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-stopped:
	case <-timer.C:
		server.Stop()
		<-stopped
	}
}
