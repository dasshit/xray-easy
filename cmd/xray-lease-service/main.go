// Package main starts the optional Xray source-lease policy service.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xray-easy/internal/controller"
	"xray-easy/internal/lease"
)

const (
	// defaultControllerAddress is the internal Controller endpoint.
	defaultControllerAddress = "172.31.241.5:10088"
	// defaultControllerToken is the read-only mounted lease identity token.
	defaultControllerToken = "/run/lease-auth/lease.token"
	// defaultHealthAddress is the address used by the internal health server.
	defaultHealthAddress = ":8091"
	// defaultHealthCheck is the loopback endpoint used by the container probe.
	defaultHealthCheck = "127.0.0.1:8091"
)

// leaseHealthCheck performs the health probe selected by the CLI healthcheck command.
var leaseHealthCheck = checkHealth

// main runs the lease service or its container health check.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
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
	worker, err := lease.NewService(client, config, slog.Default())
	if err != nil {
		return fmt.Errorf("initialize lease policy: %w", err)
	}
	server := &http.Server{
		Addr:              envOr("XRAY_LEASE_HEALTH_ADDR", defaultHealthAddress),
		Handler:           newHealthHandler(worker),
		ReadHeaderTimeout: 2 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.ListenAndServe() }()
	workerErr := make(chan error, 1)
	go func() { workerErr <- worker.Run(ctx) }()
	slog.Info("lease service started", "service", "xray-lease-service", "health_address", server.Addr, "max_active_leases", config.MaxActiveLeases, "grace_period", config.GracePeriod.String())
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return nil
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			return fmt.Errorf("lease service health server: %w", err)
		}
		return nil
	case err := <-workerErr:
		stop()
		if !errors.Is(err, context.Canceled) {
			return fmt.Errorf("lease policy worker stopped: %w", err)
		}
		return nil
	}
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

// checkHealth verifies that the local lease service is connected to Controller.
func checkHealth(address string) error {
	return checkHealthWithClient(address, &http.Client{Timeout: 3 * time.Second})
}

// checkHealthWithClient performs the health request with the provided HTTP client.
func checkHealthWithClient(address string, client *http.Client) error {
	response, err := client.Get("http://" + address + "/healthz")
	if err != nil {
		return fmt.Errorf("lease service health request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("lease service is not ready: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

// healthProvider exposes the stream state needed by the health endpoint.
type healthProvider interface {
	// Ready reports whether usable Xray lease telemetry has arrived.
	Ready() bool
	// StreamConnected reports whether the Controller snapshot stream is open.
	StreamConnected() bool
}

// newHealthHandler creates the internal JSON readiness endpoint.
func newHealthHandler(worker healthProvider) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/healthz" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		streamConnected := worker != nil && worker.StreamConnected()
		if !streamConnected {
			response.WriteHeader(http.StatusServiceUnavailable)
		}
		ready := worker != nil && worker.Ready()
		_ = json.NewEncoder(response).Encode(map[string]any{"ready": ready, "controllerStreamConnected": streamConnected})
	})
}

// envOr returns a non-empty environment value or its fallback.
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
