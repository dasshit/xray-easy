// Package main runs the protocol controller service used by Xray-easy.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"xray-easy/internal/awgcontrol"
	"xray-easy/internal/controller"
	"xray-easy/internal/grpcshutdown"

	"google.golang.org/grpc"
)

const (
	// defaultListenAddr is an internal package constant.
	defaultListenAddr = "172.31.241.5:10088"
	// defaultControllerToken is an internal package constant.
	defaultControllerToken = "/run/controller-auth/controller.token"
	// defaultLeaseToken is an internal package constant.
	defaultLeaseToken = "/run/lease-auth/lease.token"
	// defaultRuntimeAddr is an internal package constant.
	defaultRuntimeAddr = "172.31.241.2:10086"
	// defaultRuntimeToken is an internal package constant.
	defaultRuntimeToken = "/run/runtime-auth/xray_runtime_token"
	// defaultConfigDir is an internal package constant.
	defaultConfigDir = "/etc/xray"
	// controllerShutdownTimeout bounds graceful draining of long-lived RPCs.
	controllerShutdownTimeout = 3 * time.Second
)

// healthClient is an internal type used by the package.
type healthClient interface {
	// Health defines part of the interface contract.
	Health(context.Context) error
	// Close defines part of the interface contract.
	Close() error
}

// closeableAWGRuntime is an internal type used by the package.
type closeableAWGRuntime interface {
	controller.AmneziaWGRuntime
	// Close defines part of the interface contract.
	Close() error
}

// closeableXrayRuntime is an internal type used by the package.
type closeableXrayRuntime interface {
	controller.XrayRuntime
	controller.XrayHandlerRuntime
	controller.XrayStatsRuntime
	// Close defines part of the interface contract.
	Close() error
}

// dialHealthClient is an internal package variable.
var dialHealthClient = defaultDialHealthClient

// defaultDialHealthClient creates a Controller client for health checks.
func defaultDialHealthClient(address, tokenPath string) (healthClient, error) {
	return controller.Dial(address, tokenPath)
}

// dialEmbeddedXray is an internal package variable.
var dialEmbeddedXray = defaultDialEmbeddedXray

// defaultDialEmbeddedXray creates the embedded Xray runtime adapter.
func defaultDialEmbeddedXray(address, tokenPath, configDir string) (closeableXrayRuntime, error) {
	return controller.DialEmbeddedXray(address, tokenPath, configDir)
}

// dialAWG is an internal package variable.
var dialAWG = defaultDialAWG

// defaultDialAWG creates the optional AmneziaWG adapter.
func defaultDialAWG(address, tokenPath string) (closeableAWGRuntime, error) {
	return awgcontrol.Dial(address, tokenPath)
}

// listenController is an internal package variable.
var listenController = net.Listen

// serveController is an internal package variable.
var serveController = defaultServeController

// defaultServeController runs the gRPC server on the supplied listener.
func defaultServeController(server *grpc.Server, listener net.Listener) error {
	return server.Serve(listener)
}

// controllerSignalContext is an internal package variable.
var controllerSignalContext = defaultControllerSignalContext

// defaultControllerSignalContext returns a context canceled by process termination signals.
func defaultControllerSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// main starts the program.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
}

// exitProcess is an internal package variable.
var exitProcess = os.Exit

// run runs the requested operation.
func run(args []string) error {
	if len(args) == 1 && args[0] == "healthcheck" {
		client, err := dialHealthClient(envOr("XRAY_CONTROLLER_ADDR", defaultListenAddr), envOr("XRAY_CONTROLLER_TOKEN_FILE", defaultControllerToken))
		if err != nil {
			return err
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		return client.Health(ctx)
	}
	if len(args) != 0 && !(len(args) == 1 && args[0] == "serve") {
		return errors.New("usage: xray-controller [serve|healthcheck]")
	}
	return serve()
}

// serve serves the requested endpoint.
func serve() error {
	token, err := readToken(envOr("XRAY_CONTROLLER_TOKEN_FILE", defaultControllerToken))
	if err != nil {
		return fmt.Errorf("load Controller token: %w", err)
	}
	leaseToken, err := readOptionalToken(envOr("XRAY_LEASE_TOKEN_FILE", defaultLeaseToken))
	if err != nil {
		return fmt.Errorf("load lease-service token: %w", err)
	}
	runtime, err := dialEmbeddedXray(envOr("XRAY_RUNTIME_ADDR", defaultRuntimeAddr), envOr("XRAY_RUNTIME_TOKEN_FILE", defaultRuntimeToken), envOr("XRAY_CONFIG_DIR", defaultConfigDir))
	if err != nil {
		return fmt.Errorf("initialize embedded Xray runtime: %w", err)
	}
	defer runtime.Close()
	listener, err := listenController("tcp", envOr("XRAY_CONTROLLER_LISTEN", defaultListenAddr))
	if err != nil {
		return fmt.Errorf("listen for Controller gRPC: %w", err)
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(24<<20),
		grpc.MaxSendMsgSize(24<<20),
		grpc.ChainUnaryInterceptor(controller.LoggingInterceptor("xray-controller"), controller.AuthInterceptorWithLeaseToken(token, leaseToken)),
		grpc.ChainStreamInterceptor(controller.LoggingStreamInterceptor("xray-controller"), controller.AuthStreamInterceptorWithLeaseToken(token, leaseToken)),
	)
	var awg controller.AmneziaWGRuntime
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		client, dialErr := dialAWG(envOr("AWG_CONTROL_ADDR", "172.31.241.4:10087"), envOr("AWG_CONTROL_TOKEN_FILE", "/run/awg-auth/control.token"))
		if dialErr != nil || client == nil {
			if dialErr == nil {
				dialErr = errors.New("adapter dial returned a nil client")
			}
			slog.Warn("optional AmneziaWG adapter is unavailable; Controller will continue without it", "error", dialErr)
		} else {
			defer client.Close()
			awg = client
		}
	}
	controller.RegisterRPC(server, controller.NewServiceWithAdapters(runtime, runtime, runtime, awg))
	slog.Info("Controller gRPC listening", "service", "xray-controller", "address", listener.Addr().String())
	shutdown, stop := controllerSignalContext()
	defer stop()
	serveErr := make(chan error, 1)
	serveFn := serveController
	go func() { serveErr <- serveFn(server, listener) }()
	select {
	case <-shutdown.Done():
		grpcshutdown.Stop(server, controllerShutdownTimeout)
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			server.Stop()
			return fmt.Errorf("serve Controller gRPC: %w", err)
		}
		return nil
	}
}

// readOptionalToken reads an optional token file, treating absence as disabled.
func readOptionalToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	value, err := readToken(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return value, err
}

// readToken reads the requested value.
func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("token file path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file is accessible by group or other users")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("token file is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) < 32 {
		return "", errors.New("token must be base64 encoded and contain at least 32 bytes")
	}
	return value, nil
}

// envOr performs the operation represented by its name.
func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
