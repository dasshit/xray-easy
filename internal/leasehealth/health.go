// Package leasehealth provides the private gRPC readiness check shared by the
// lease service and the control-plane.
package leasehealth

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const checkTimeout = 2 * time.Second

// Check reports whether the standard gRPC health service is SERVING.
func Check(ctx context.Context, address string) (bool, error) {
	return CheckWithDialer(ctx, address, nil)
}

// CheckWithDialer is Check with an optional gRPC context dialer, used by
// hermetic tests and in-process transports.
func CheckWithDialer(ctx context.Context, address string, dialer func(context.Context, string) (net.Conn, error)) (bool, error) {
	address = strings.TrimSpace(address)
	host, portText, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.ContainsAny(host, " \t\r\n/?#") {
		return false, fmt.Errorf("lease health gRPC address is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false, fmt.Errorf("lease health gRPC address is invalid")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if dialer != nil {
		options = append(options, grpc.WithContextDialer(dialer))
	}
	connection, err := grpc.NewClient("passthrough:///"+address, options...)
	if err != nil {
		return false, fmt.Errorf("create lease health gRPC client: %w", err)
	}
	defer connection.Close()
	response, err := healthpb.NewHealthClient(connection).Check(callCtx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return false, fmt.Errorf("lease health gRPC check failed: %w", err)
	}
	return response.GetStatus() == healthpb.HealthCheckResponse_SERVING, nil
}
