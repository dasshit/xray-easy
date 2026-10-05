// Package main starts the AmneziaWG service process and its authenticated gRPC endpoint.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"xray-easy/awg-service/internal/control"
)

const (
	// defaultDataDir is an internal package constant.
	defaultDataDir = "/data"
	// defaultPublicPort is an internal package constant.
	defaultPublicPort = 1234
	// defaultListenPort is an internal package constant.
	defaultListenPort = 51820
	// defaultControlAddr is an internal package constant.
	defaultControlAddr = "172.31.241.4:10087"
	// defaultTokenPath is an internal package constant.
	defaultTokenPath = "/data/control.token"
	// defaultIPv4Pool is an internal package constant.
	defaultIPv4Pool = "10.88.0.0/24"
	// defaultIPv6Pool is an internal package constant.
	defaultIPv6Pool = "fd88:88:88::/64"
	// defaultInterface is an internal package constant.
	defaultInterface       = "awg0"
	controlShutdownTimeout = 3 * time.Second
)

// peerNamePattern is an internal package variable.
var peerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// controlRPC is an internal type used by the package.
type controlRPC interface {
	// Invoke defines part of the interface contract.
	Invoke(context.Context, string, map[string]any) (map[string]any, error)
	// Close defines part of the interface contract.
	Close() error
}

// dialControlRPC is an internal package variable.
var dialControlRPC = func() (controlRPC, error) { return dialControl() }

// exitProcess is the process termination function used by main.
var exitProcess = os.Exit

// openControlManager is an internal package variable.
var openControlManager = control.Open

// listenControl is an internal package variable.
var listenControl = net.Listen

// main starts the program.
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
}

// run runs the requested operation.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "serve" {
		return serve()
	}
	switch args[0] {
	case "health":
		return checkHealth()
	case "status":
		return printRPC("GetStatus", nil, stdout)
	case "peer-list":
		return printRPC("ListPeers", nil, stdout)
	case "peer-add":
		return addPeer(args[1:], stdout, stderr)
	case "peer-remove":
		return removePeer(args[1:], stdout)
	case "profile":
		return refreshProfile(args[1:], stdout, stderr)
	case "keygen":
		privateKey, publicKey, err := control.GenerateKeypair()
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]string{"privateKey": privateKey, "publicKey": publicKey})
	default:
		return fmt.Errorf("unknown command %q; use serve, health, status, peer-list, peer-add, peer-remove, profile, or keygen", args[0])
	}
}

// serve serves the requested endpoint.
func serve() error {
	opts, err := optionsFromEnvironment()
	if err != nil {
		return err
	}
	tokenPath := envOr("AWG_CONTROL_TOKEN_FILE", defaultTokenPath)
	token, err := control.LoadOrCreateToken(tokenPath)
	if err != nil {
		return err
	}
	manager, err := openControlManager(opts, control.KernelFactory{Options: opts})
	if err != nil {
		return err
	}
	defer manager.Close()
	listener, err := listenControl("tcp", envOr("AWG_GRPC_LISTEN", defaultControlAddr))
	if err != nil {
		return fmt.Errorf("listen on private AWG control address: %w", err)
	}
	shutdown := make(chan os.Signal, 1)
	signalNotify(shutdown)
	return serveControlService(manager, opts, token, listener, shutdown)
}

// serveControlService serves the requested endpoint.
func serveControlService(manager *control.Manager, opts control.Options, token string, listener net.Listener, shutdown <-chan os.Signal) error {
	service := control.NewService(manager, opts)
	monitorContext, stopMonitor := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		service.RunConnectionMonitor(monitorContext)
	}()
	expirationDone := make(chan struct{})
	go func() {
		defer close(expirationDone)
		service.RunExpirationMonitor(monitorContext)
	}()
	defer func() {
		stopMonitor()
		<-monitorDone
		<-expirationDone
	}()
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(control.LoggingInterceptor(), control.AuthInterceptor(token)),
		grpc.ChainStreamInterceptor(control.LoggingStreamInterceptor(), control.AuthStreamInterceptor(token)),
		grpc.MaxRecvMsgSize(24<<20),
		grpc.MaxSendMsgSize(24<<20),
	)
	control.Register(server, service)
	return serveControlServer(server, listener, shutdown)
}

// serveControlServer serves the requested endpoint.
func serveControlServer(server *grpc.Server, listener net.Listener, shutdown <-chan os.Signal) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			server.Stop()
			return fmt.Errorf("serve AWG control API: %w", err)
		}
		return nil
	case <-shutdown:
		stopControlServer(server, controlShutdownTimeout)
		return nil
	}
}

func stopControlServer(server *grpc.Server, timeout time.Duration) {
	if server == nil {
		return
	}
	if timeout <= 0 {
		timeout = controlShutdownTimeout
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

// optionsFromEnvironment performs the operation represented by its name.
func optionsFromEnvironment() (control.Options, error) {
	masterKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("AWG_MASTER_KEY")))
	if err != nil || len(masterKey) < 32 {
		return control.Options{}, errors.New("AWG_MASTER_KEY must be base64 with at least 32 decoded bytes; reuse XRAY_EASY_MASTER_KEY")
	}
	publicPort, err := envPort("AWG_PUBLIC_PORT", defaultPublicPort)
	if err != nil {
		return control.Options{}, err
	}
	listenPort, err := envPort("AWG_LISTEN_PORT", defaultListenPort)
	if err != nil {
		return control.Options{}, err
	}
	ipv4, err := netip.ParsePrefix(envOr("AWG_IPV4_POOL", defaultIPv4Pool))
	if err != nil {
		return control.Options{}, fmt.Errorf("AWG_IPV4_POOL: %w", err)
	}
	ipv6, err := netip.ParsePrefix(envOr("AWG_IPV6_POOL", defaultIPv6Pool))
	if err != nil {
		return control.Options{}, fmt.Errorf("AWG_IPV6_POOL: %w", err)
	}
	dns := splitNonEmpty(envOr("AWG_DNS_SERVERS", "1.1.1.1,2606:4700:4700::1111"))
	for _, address := range dns {
		if net.ParseIP(address) == nil {
			return control.Options{}, fmt.Errorf("AWG_DNS_SERVERS contains invalid address %q", address)
		}
	}
	obfuscation := control.DefaultObfuscation(masterKey)
	for key, value := range obfuscationFromEnvironment() {
		obfuscation[key] = value
	}
	return control.Options{
		DataDir:       envOr("AWG_DATA_DIR", defaultDataDir),
		MasterKey:     masterKey,
		PublicHost:    strings.TrimSpace(os.Getenv("AWG_PUBLIC_HOST")),
		PublicPort:    publicPort,
		ListenPort:    listenPort,
		IPv4Prefix:    ipv4,
		IPv6Prefix:    ipv6,
		DNS:           dns,
		Obfuscation:   obfuscation,
		InterfaceName: envOr("AWG_INTERFACE", defaultInterface),
	}, nil
}

// obfuscationFromEnvironment performs the operation represented by its name.
func obfuscationFromEnvironment() map[string]string {
	variables := map[string]string{
		"jc": "AWG_JC", "jmin": "AWG_JMIN", "jmax": "AWG_JMAX",
		"s1": "AWG_S1", "s2": "AWG_S2", "s3": "AWG_S3", "s4": "AWG_S4",
		"h1": "AWG_H1", "h2": "AWG_H2", "h3": "AWG_H3", "h4": "AWG_H4",
		"i1": "AWG_I1", "i2": "AWG_I2", "i3": "AWG_I3", "i4": "AWG_I4", "i5": "AWG_I5",
		"header_protection_key": "AWG_HEADER_PROTECTION_KEY", "content_padding_addition": "AWG_CONTENT_PADDING_ADDITION",
		"rekey_after_time": "AWG_REKEY_AFTER_TIME", "rekey_timeout": "AWG_REKEY_TIMEOUT",
		"reject_after_time": "AWG_REJECT_AFTER_TIME", "keepalive_timeout": "AWG_KEEPALIVE_TIMEOUT",
		"max_handshake_attempts": "AWG_MAX_HANDSHAKE_ATTEMPTS",
		"random_trailers":        "AWG_RANDOM_TRAILERS", "disable_cookies": "AWG_DISABLE_COOKIES",
	}
	values := make(map[string]string)
	for key, variable := range variables {
		if value := strings.TrimSpace(os.Getenv(variable)); value != "" {
			values[key] = value
		}
	}
	return values
}

// addPeer adds the supplied value.
func addPeer(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("peer-add", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "device name (letters, digits and hyphens)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("peer-add requires --name")
	}
	privateKey, publicKey, err := control.GenerateKeypair()
	if err != nil {
		return err
	}
	client, err := dialControlRPC()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peer, err := client.Invoke(ctx, "AddPeer", map[string]any{"name": *name, "publicKey": publicKey})
	if err != nil {
		return fmt.Errorf("add AWG peer: %w", err)
	}
	profile, err := client.Invoke(ctx, "RenderClientConfig", map[string]any{"name": *name, "privateKey": privateKey})
	if err != nil {
		rollbackPeer(client, *name)
		return fmt.Errorf("render AWG client profile: %w", err)
	}
	config, _ := profile["config"].(string)
	if config == "" {
		rollbackPeer(client, *name)
		return errors.New("AWG service returned an empty client profile")
	}
	path := filepath.Join(envOr("AWG_DATA_DIR", defaultDataDir), "profiles", *name+".conf")
	if err := writePrivateProfile(path, config); err != nil {
		rollbackPeer(client, *name)
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"peer": peer, "profilePath": path,
		"message": "Profile contains a private key; transfer it to the client securely.",
	})
}

// removePeer removes the supplied value.
func removePeer(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("peer-remove", flag.ContinueOnError)
	name := flags.String("name", "", "peer name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("peer-remove requires --name")
	}
	client, err := dialControlRPC()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Invoke(ctx, "RemovePeer", map[string]any{"name": *name})
	if err != nil {
		return err
	}
	if err := removeSavedProfile(envOr("AWG_DATA_DIR", defaultDataDir), *name); err != nil {
		return fmt.Errorf("peer was revoked, but its saved client profile could not be deleted: %w", err)
	}
	return json.NewEncoder(stdout).Encode(result)
}

// removeSavedProfile removes the supplied value.
func removeSavedProfile(dataDir, name string) error {
	if !peerNamePattern.MatchString(name) {
		return errors.New("peer name must contain 1-32 letters, digits or hyphens")
	}
	path := filepath.Join(dataDir, "profiles", name+".conf")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// refreshProfile performs the operation represented by its name.
func refreshProfile(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("profile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "peer name whose saved profile should be refreshed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !peerNamePattern.MatchString(*name) {
		return errors.New("profile requires --name with 1-32 letters, digits or hyphens")
	}
	dataDir := envOr("AWG_DATA_DIR", defaultDataDir)
	path := filepath.Join(dataDir, "profiles", *name+".conf")
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read saved client profile: %w", err)
	}
	privateKey, err := privateKeyFromProfile(string(contents))
	if err != nil {
		return err
	}
	client, err := dialControlRPC()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Invoke(ctx, "RenderClientConfig", map[string]any{"name": *name, "privateKey": privateKey})
	if err != nil {
		return fmt.Errorf("render refreshed AWG profile: %w", err)
	}
	updated, _ := result["config"].(string)
	if updated == "" {
		return errors.New("AWG service returned an empty client profile")
	}
	if err := writePrivateProfileAtomic(path, updated); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{
		"profilePath": path,
		"message":     "Profile refreshed; it contains a private key, so transfer it securely.",
	})
}

// privateKeyFromProfile performs the operation represented by its name.
func privateKeyFromProfile(config string) (string, error) {
	section := ""
	privateKey := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Interface" || !strings.HasPrefix(line, "PrivateKey") {
			continue
		}
		key, ok := strings.CutPrefix(line, "PrivateKey = ")
		if !ok || privateKey != "" || strings.TrimSpace(key) == "" {
			return "", errors.New("saved client profile must contain exactly one valid Interface PrivateKey")
		}
		privateKey = strings.TrimSpace(key)
	}
	if privateKey == "" {
		return "", errors.New("saved client profile has no Interface PrivateKey")
	}
	return privateKey, nil
}

// writePrivateProfileAtomic writes the supplied value.
func writePrivateProfileAtomic(path, contents string) error {
	return writePrivateProfileAtomicWith(path, contents, profileFileOperations{
		createTemp: func(dir, pattern string) (profileFile, error) { return os.CreateTemp(dir, pattern) },
		rename:     os.Rename,
		remove:     os.Remove,
	})
}

// profileFile is an internal type used by the package.
type profileFile interface {
	// Name defines part of the interface contract.
	Name() string
	// Chmod defines part of the interface contract.
	Chmod(os.FileMode) error
	// Write defines part of the interface contract.
	Write([]byte) (int, error)
	// Sync defines part of the interface contract.
	Sync() error
	// Close defines part of the interface contract.
	Close() error
}

// profileFileOperations is an internal type used by the package.
type profileFileOperations struct {
	openExclusive func(string) (profileFile, error)
	createTemp    func(string, string) (profileFile, error)
	rename        func(string, string) error
	remove        func(string) error
}

// writePrivateProfileAtomicWith writes the supplied value.
func writePrivateProfileAtomicWith(path, contents string, files profileFileOperations) error {
	tmp, err := files.createTemp(filepath.Dir(path), ".profile-*.tmp")
	if err != nil {
		return fmt.Errorf("create refreshed profile temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer files.remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure refreshed profile: %w", err)
	}
	if _, err := io.WriteString(tmp, contents); err != nil {
		tmp.Close()
		return fmt.Errorf("write refreshed profile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync refreshed profile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close refreshed profile: %w", err)
	}
	if err := files.rename(tmpPath, path); err != nil {
		return fmt.Errorf("activate refreshed profile: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// printRPC performs the operation represented by its name.
func printRPC(method string, fields map[string]any, stdout io.Writer) error {
	client, err := dialControlRPC()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := client.Invoke(ctx, method, fields)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(result)
}

// checkHealth performs the operation represented by its name.
func checkHealth() error {
	client, err := dialControlRPC()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = client.Invoke(ctx, "GetStatus", nil)
	return err
}

// dialControl performs the operation represented by its name.
func dialControl() (*control.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return control.DialClient(ctx, envOr("AWG_CONTROL_ADDR", defaultControlAddr), envOr("AWG_CONTROL_TOKEN_FILE", defaultTokenPath))
}

// rollbackPeer performs the operation represented by its name.
func rollbackPeer(client controlRPC, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = client.Invoke(ctx, "RemovePeer", map[string]any{"name": name})
}

// writePrivateProfile writes the supplied value.
func writePrivateProfile(path, contents string) error {
	return writePrivateProfileWith(path, contents, profileFileOperations{
		openExclusive: func(path string) (profileFile, error) {
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		},
		remove: os.Remove,
	})
}

// writePrivateProfileWith writes the supplied value.
func writePrivateProfileWith(path, contents string, files profileFileOperations) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}
	file, err := files.openExclusive(path)
	if err != nil {
		return fmt.Errorf("create profile securely: %w", err)
	}
	if _, err := io.WriteString(file, contents); err != nil {
		file.Close()
		_ = files.remove(path)
		return fmt.Errorf("write profile: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = files.remove(path)
		return fmt.Errorf("sync profile: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = files.remove(path)
		return fmt.Errorf("close profile: %w", err)
	}
	return nil
}

// envPort performs the operation represented by its name.
func envPort(key string, fallback int) (uint16, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return uint16(fallback), nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s must be a valid TCP/UDP port", key)
	}
	return uint16(port), nil
}

// envOr performs the operation represented by its name.
func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

// splitNonEmpty performs the operation represented by its name.
func splitNonEmpty(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// signalNotify registers the process shutdown signals.
var signalNotify = func(channel chan<- os.Signal) {
	signal.Notify(channel, syscall.SIGINT, syscall.SIGTERM)
}
