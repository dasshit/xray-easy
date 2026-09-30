package main

import (
	"context"
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
	"xray-easy/internal/supervisor"

	"google.golang.org/grpc"
)

const (
	defaultListenAddr      = "172.31.241.5:10088"
	defaultControllerToken = "/run/controller-auth/controller.token"
	defaultSupervisorAddr  = "172.31.241.2:10086"
	defaultSupervisorToken = "/run/secrets/xray_supervisor_token"
	defaultRuntimeAddr     = "172.31.241.2:10086"
	defaultRuntimeToken    = "/run/runtime-auth/xray_runtime_token"
	defaultConfigDir       = "/etc/xray"
)

type healthClient interface {
	Health(context.Context) error
	Close() error
}

type closeableAWGRuntime interface {
	controller.AmneziaWGRuntime
	Close() error
}

type closeableXrayRuntime interface {
	controller.XrayRuntime
	controller.XrayHandlerRuntime
	controller.XrayStatsRuntime
	Close() error
}

var dialHealthClient = func(address, tokenPath string) (healthClient, error) {
	return controller.Dial(address, tokenPath)
}
var dialSupervisor = supervisor.Dial
var dialEmbeddedXray = func(address, tokenPath, configDir string) (closeableXrayRuntime, error) {
	return controller.DialEmbeddedXray(address, tokenPath, configDir)
}
var dialAWG = func(address, tokenPath string) (closeableAWGRuntime, error) {
	return awgcontrol.Dial(address, tokenPath)
}
var listenController = net.Listen
var serveController = func(server *grpc.Server, listener net.Listener) error { return server.Serve(listener) }
var controllerSignalContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
}

var exitProcess = os.Exit

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

func serve() error {
	token, err := readToken(envOr("XRAY_CONTROLLER_TOKEN_FILE", defaultControllerToken))
	if err != nil {
		return fmt.Errorf("load Controller token: %w", err)
	}
	adapterKind := strings.ToLower(envOr("XRAY_ADAPTER", "supervisor"))
	var xrayRuntime controller.XrayRuntime
	var handler controller.XrayHandlerRuntime
	var stats controller.XrayStatsRuntime
	var closeXray func() error
	switch adapterKind {
	case "supervisor":
		sup, dialErr := dialSupervisor(envOr("XRAY_SUPERVISOR_ADDR", defaultSupervisorAddr), envOr("XRAY_SUPERVISOR_TOKEN_FILE", defaultSupervisorToken))
		if dialErr != nil {
			return fmt.Errorf("initialize Xray supervisor adapter: %w", dialErr)
		}
		xrayRuntime, handler, stats, closeXray = sup, sup, sup, sup.Close
	case "embedded":
		runtime, dialErr := dialEmbeddedXray(envOr("XRAY_RUNTIME_ADDR", defaultRuntimeAddr), envOr("XRAY_RUNTIME_TOKEN_FILE", defaultRuntimeToken), envOr("XRAY_CONFIG_DIR", defaultConfigDir))
		if dialErr != nil {
			return fmt.Errorf("initialize embedded Xray runtime adapter: %w", dialErr)
		}
		xrayRuntime, handler, stats, closeXray = runtime, runtime, runtime, runtime.Close
	default:
		return fmt.Errorf("unsupported XRAY_ADAPTER %q; expected supervisor or embedded", adapterKind)
	}
	defer closeXray()
	listener, err := listenController("tcp", envOr("XRAY_CONTROLLER_LISTEN", defaultListenAddr))
	if err != nil {
		return fmt.Errorf("listen for Controller gRPC: %w", err)
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(24<<20),
		grpc.MaxSendMsgSize(24<<20),
		grpc.ChainUnaryInterceptor(controller.LoggingInterceptor("xray-controller"), controller.AuthInterceptor(token)),
	)
	var awg controller.AmneziaWGRuntime
	if strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")) != "" {
		client, dialErr := dialAWG(envOr("AWG_CONTROL_ADDR", "172.31.241.4:10087"), envOr("AWG_CONTROL_TOKEN_FILE", "/run/awg-auth/control.token"))
		if dialErr != nil {
			return fmt.Errorf("initialize AmneziaWG adapter: %w", dialErr)
		}
		defer client.Close()
		awg = client
	}
	controller.RegisterRPC(server, controller.NewServiceWithAdapters(xrayRuntime, handler, stats, awg))
	slog.Info("Controller gRPC listening", "service", "xray-controller", "address", listener.Addr().String())
	shutdown, stop := controllerSignalContext()
	defer stop()
	serveErr := make(chan error, 1)
	serveFn := serveController
	go func() { serveErr <- serveFn(server, listener) }()
	select {
	case <-shutdown.Done():
		server.GracefulStop()
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			return fmt.Errorf("serve Controller gRPC: %w", err)
		}
		return nil
	}
}

func readToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("token file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", errors.New("token file is empty")
	}
	return value, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
