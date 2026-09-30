package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"xray-easy/internal/diagnostics"
	"xray-easy/internal/interaction"
	"xray-easy/internal/runtimeauth"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
	runtime "xray-easy/xray-runtime/internal/runtime"
)

var runtimeVersion = "dev"

const (
	defaultListen    = "0.0.0.0:10086"
	defaultTokenFile = "/run/secrets/xray_runtime_token"
	defaultConfig    = "/etc/xray/active.json"
)

var newHealthConnection = func(address string) (*grpc.ClientConn, error) {
	return grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(24<<20), grpc.MaxCallSendMsgSize(24<<20)),
	)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, diagnostics.Redact(err.Error()))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 1 && args[0] == "healthcheck" {
		return healthcheck(envOr("XRAY_RUNTIME_ADDR", "127.0.0.1:10086"), envOr("XRAY_RUNTIME_TOKEN_FILE", defaultTokenFile))
	}
	flags := flag.NewFlagSet("xray-runtime", flag.ContinueOnError)
	listen := flags.String("listen", envOr("XRAY_RUNTIME_LISTEN", defaultListen), "private gRPC listen address")
	configPath := flags.String("config", envOr("XRAY_CONFIG_PATH", defaultConfig), "active Xray configuration path")
	tokenPath := flags.String("token-file", envOr("XRAY_RUNTIME_TOKEN_FILE", defaultTokenFile), "service authentication token path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: xray-runtime [--listen address] [--config path] [--token-file path] | healthcheck")
	}
	return serve(*listen, *configPath, *tokenPath)
}

func serve(listenAddress, configPath, tokenPath string) error {
	token, err := readToken(tokenPath)
	if err != nil {
		return fmt.Errorf("load runtime authentication token: %w", err)
	}
	configuration, err := readOptionalConfig(configPath)
	if err != nil {
		return fmt.Errorf("load active Xray configuration: %w", err)
	}
	service, err := runtime.NewService(nil, runtimeVersion, configuration, 0)
	if err != nil {
		return err
	}
	defer service.Close()
	authenticator, err := runtimeauth.NewAuthenticator(token, allowedRuntimeCall)
	if err != nil {
		return fmt.Errorf("initialize runtime authentication: %w", err)
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen for Xray runtime gRPC: %w", err)
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(24<<20), grpc.MaxSendMsgSize(24<<20),
		grpc.ChainUnaryInterceptor(runtimeLoggingInterceptor, authenticator.UnaryServerInterceptor()),
	)
	xrayruntimev1.RegisterRuntimeServer(server, service)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()

	shutdown, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-shutdown.Done():
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			server.Stop()
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			server.Stop()
			return fmt.Errorf("serve Xray runtime gRPC: %w", err)
		}
		return nil
	}
}

func runtimeLoggingInterceptor(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, requestID, traceErr := interaction.EnsureIncoming(ctx)
	if traceErr != nil {
		slog.Warn("could not create runtime request ID", "service", "xray-runtime")
	}
	started := time.Now()
	response, err := handler(ctx, request)
	interaction.LogRPC(slog.Default(), "xray-runtime", info.FullMethod, requestID, "xray", started, err, interaction.TraceFromContext(ctx))
	return response, err
}

func healthcheck(address, tokenPath string) error {
	token, err := readToken(tokenPath)
	if err != nil {
		return fmt.Errorf("read runtime token: %w", err)
	}
	connection, err := newHealthConnection(address)
	if err != nil {
		return fmt.Errorf("connect to Xray runtime: %w", err)
	}
	defer connection.Close()
	request := &xrayruntimev1.HealthRequest{ProbeId: "container-healthcheck"}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ctx, err = runtimeauth.SignContext(ctx, token, "healthcheck", xrayruntimev1.Runtime_Health_FullMethodName, request)
	if err != nil {
		return err
	}
	response, err := xrayruntimev1.NewRuntimeClient(connection).Health(ctx, request)
	if err != nil {
		return fmt.Errorf("Xray runtime health RPC: %w", err)
	}
	if !response.GetReady() {
		return errors.New("Xray runtime is not ready")
	}
	return nil
}

func readToken(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("runtime token path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	token := []byte(strings.TrimSpace(string(data)))
	if len(token) < 32 {
		return nil, errors.New("runtime token must contain at least 32 bytes")
	}
	return token, nil
}

func readOptionalConfig(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func allowedRuntimeCall(method, identity string) bool {
	if identity == "healthcheck" {
		return method == xrayruntimev1.Runtime_Health_FullMethodName
	}
	if identity != "control-plane" {
		return false
	}
	return strings.HasPrefix(method, "/xrayeasy.xray.v1.Runtime/")
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
