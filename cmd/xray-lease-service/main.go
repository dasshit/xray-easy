// Package main starts the optional Xray source-lease policy service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"xray-easy/internal/controller"
	"xray-easy/internal/grpcshutdown"
	"xray-easy/internal/lease"
	"xray-easy/internal/leasehealth"
)

const (
	// defaultControllerAddress is the internal Controller endpoint.
	defaultControllerAddress = "172.31.241.5:10088"
	// defaultControllerToken is the read-only mounted lease identity token.
	defaultControllerToken = "/run/lease-auth/lease.token"
	// defaultHealthAddress is the private gRPC readiness listener.
	defaultHealthAddress = ":8091"
	// defaultHealthCheck is the loopback gRPC target used by the container probe.
	defaultHealthCheck      = "127.0.0.1:8091"
	leaseHealthPollInterval = 250 * time.Millisecond
	leaseHealthStopTimeout  = 2 * time.Second
	leaseWorkerStopTimeout  = 3 * time.Second
)

// leaseHealthCheck performs the health probe selected by the CLI healthcheck command.
var leaseHealthCheck = checkHealth

// leaseServiceWorker is the worker contract needed by the process entrypoint.
type leaseServiceWorker interface {
	healthProvider
	// Run starts lease enforcement until its context is canceled or an error occurs.
	Run(context.Context) error
}

// newLeaseWorker constructs the lease policy worker.
var newLeaseWorker = defaultNewLeaseWorker

// defaultNewLeaseWorker creates the production lease policy worker.
func defaultNewLeaseWorker(client lease.Controller, config lease.Config, logger *slog.Logger) (leaseServiceWorker, error) {
	return lease.NewService(client, config, logger)
}

// leaseSignalContext is the shutdown signal context factory.
var leaseSignalContext = defaultLeaseSignalContext

// defaultLeaseSignalContext returns a context canceled by process termination signals.
func defaultLeaseSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// runLeaseHealthServer serves the private gRPC readiness API.
var runLeaseHealthServer = defaultRunLeaseHealthServer

// listenLeaseHealth opens the private readiness listener.
var listenLeaseHealth = net.Listen

// defaultRunLeaseHealthServer runs the gRPC readiness server.
func defaultRunLeaseHealthServer(server *grpc.Server, listener net.Listener) error {
	return server.Serve(listener)
}

// exitProcess terminates the process after a startup failure.
var exitProcess = os.Exit

// main runs the lease service or its container health check.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
}

// run serves the worker, or executes the container health check.
func run(args []string) error {
	if len(args) == 1 && args[0] == "healthcheck" {
		return leaseHealthCheck(defaultHealthCheck)
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "serve" {
		return errors.New("usage: xray-lease-service [serve|healthcheck]")
	}
	ctx, stop := leaseSignalContext()
	defer stop()
	client, err := controller.Dial(envOr("XRAY_CONTROLLER_ADDR", defaultControllerAddress), envOr("XRAY_LEASE_TOKEN_FILE", defaultControllerToken))
	if err != nil {
		return fmt.Errorf("initialize lease Controller client: %w", err)
	}
	defer client.Close()
	config, err := readConfig()
	if err != nil {
		return err
	}
	worker, err := newLeaseWorker(client, config, slog.Default())
	if err != nil {
		return fmt.Errorf("initialize lease policy: %w", err)
	}
	healthAddress := envOr("XRAY_LEASE_GRPC_LISTEN", defaultHealthAddress)
	listener, err := listenLeaseHealth("tcp", healthAddress)
	if err != nil {
		return fmt.Errorf("listen for lease health gRPC: %w", err)
	}
	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthContext, stopHealth := context.WithCancel(ctx)
	defer stopHealth()
	readinessDone := make(chan struct{})
	go func() {
		defer close(readinessDone)
		monitorLeaseReadiness(healthContext, worker, healthServer, leaseHealthPollInterval)
	}()
	serverErr := make(chan error, 1)
	serveHealth := runLeaseHealthServer
	go func() { serverErr <- serveHealth(grpcServer, listener) }()
	workerErr := make(chan error, 1)
	go func() { workerErr <- worker.Run(ctx) }()
	slog.Info("lease service started", "service", "xray-lease-service", "health_grpc_address", listener.Addr().String(), "max_active_leases", config.MaxActiveLeases, "grace_period", config.GracePeriod.String())
	select {
	case <-ctx.Done():
		stopHealth()
		grpcshutdown.Stop(grpcServer, leaseHealthStopTimeout)
		if err := waitLeaseWorker(workerErr); err != nil {
			return err
		}
		<-readinessDone
		return nil
	case err := <-serverErr:
		stop()
		stopHealth()
		grpcServer.Stop()
		workerStopErr := waitLeaseWorker(workerErr)
		<-readinessDone
		if workerStopErr != nil {
			return workerStopErr
		}
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("lease service health gRPC server: %w", err)
		}
		return nil
	case err := <-workerErr:
		stop()
		stopHealth()
		grpcServer.Stop()
		<-readinessDone
		return leaseWorkerExitError(err)
	}
}

func monitorLeaseReadiness(ctx context.Context, worker healthProvider, server *health.Server, interval time.Duration) {
	if interval <= 0 {
		interval = leaseHealthPollInterval
	}
	updateLeaseReadiness(worker, server)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateLeaseReadiness(worker, server)
		}
	}
}

func updateLeaseReadiness(worker healthProvider, server *health.Server) {
	state := healthpb.HealthCheckResponse_NOT_SERVING
	if worker != nil && worker.Ready() {
		state = healthpb.HealthCheckResponse_SERVING
	}
	server.SetServingStatus("", state)
}

func waitLeaseWorker(workerErr <-chan error) error {
	timer := time.NewTimer(leaseWorkerStopTimeout)
	defer timer.Stop()
	select {
	case err := <-workerErr:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("lease policy worker stopped: %w", err)
	case <-timer.C:
		return errors.New("lease policy worker did not stop before the shutdown deadline")
	}
}

func leaseWorkerExitError(err error) error {
	if err == nil {
		return errors.New("lease policy worker stopped unexpectedly")
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return fmt.Errorf("lease policy worker stopped: %w", err)
}

// readConfig loads lease policy values from the process environment.
func readConfig() (lease.Config, error) {
	config := lease.DefaultConfig()
	if value := strings.TrimSpace(os.Getenv("XRAY_LEASE_MAX_ACTIVE")); value != "" {
		count, err := strconv.Atoi(value)
		if err != nil {
			return lease.Config{}, fmt.Errorf("XRAY_LEASE_MAX_ACTIVE: %w", err)
		}
		config.MaxActiveLeases = count
	}
	if value := strings.TrimSpace(os.Getenv("XRAY_LEASE_GRACE")); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return lease.Config{}, fmt.Errorf("XRAY_LEASE_GRACE: %w", err)
		}
		config.GracePeriod = duration
	}
	if value := strings.TrimSpace(os.Getenv("XRAY_LEASE_RETRY_DELAY")); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return lease.Config{}, fmt.Errorf("XRAY_LEASE_RETRY_DELAY: %w", err)
		}
		config.RetryDelay = duration
	}
	if err := config.Validate(); err != nil {
		return lease.Config{}, fmt.Errorf("invalid lease service configuration: %w", err)
	}
	return config, nil
}

// checkHealth verifies that the lease service reports itself ready over gRPC.
func checkHealth(address string) error {
	ready, err := leasehealth.Check(context.Background(), address)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("lease service is not ready: gRPC health status is NOT_SERVING")
	}
	return nil
}

// healthProvider exposes the readiness state used by the standard gRPC health service.
type healthProvider interface {
	// Ready reports whether usable Xray lease telemetry has arrived.
	Ready() bool
}

// envOr returns a non-empty environment value or its fallback.
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
