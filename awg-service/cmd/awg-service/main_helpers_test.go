package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"xray-easy/awg-service/internal/control"
)

type scriptedListener struct {
	closed    chan struct{}
	closeOnce sync.Once
	acceptErr error
}

type faultProfileFile struct {
	*os.File
	chmodErr error
	writeErr error
	syncErr  error
	closeErr error
}

func (f *faultProfileFile) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.File.Chmod(mode)
}

func (f *faultProfileFile) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.File.Write(data)
}

func (f *faultProfileFile) WriteString(value string) (int, error) {
	return f.Write([]byte(value))
}

func (f *faultProfileFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func (f *faultProfileFile) Close() error {
	actualErr := f.File.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return actualErr
}

func newScriptedListener(acceptErr error) *scriptedListener {
	return &scriptedListener{closed: make(chan struct{}), acceptErr: acceptErr}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (*scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

type recordingControlRPC struct {
	methods []string
}

type inertAWGDevice struct{}

func (inertAWGDevice) Set(string) error          { return nil }
func (inertAWGDevice) Up() error                 { return nil }
func (inertAWGDevice) Snapshot() (string, error) { return "", nil }
func (inertAWGDevice) Close()                    {}

type inertAWGFactory struct{}

func (inertAWGFactory) Open(string, int) (control.Device, error) { return inertAWGDevice{}, nil }

func (c *recordingControlRPC) Invoke(_ context.Context, method string, _ map[string]any) (map[string]any, error) {
	c.methods = append(c.methods, method)
	return map[string]any{"removed": true}, nil
}
func (*recordingControlRPC) Close() error { return nil }

func TestCommandHelpersDialAndRollback(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("secret-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWG_CONTROL_ADDR", "passthrough:///unused")
	t.Setenv("AWG_CONTROL_TOKEN_FILE", tokenPath)
	client, err := dialControl()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingControlRPC{}
	rollbackPeer(recorder, "phone")
	if len(recorder.methods) != 1 || recorder.methods[0] != "RemovePeer" {
		t.Fatalf("rollback calls = %v", recorder.methods)
	}
	if err := run([]string{"serve"}, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "AWG_MASTER_KEY") {
		t.Fatalf("serve without master key = %v", err)
	}
}

func TestCommandProfileWritersProtectExistingDataAndReportBadPaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profiles", "phone.conf")
	if err := writePrivateProfile(path, "private"); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateProfile(path, "overwrite"); err == nil {
		t.Fatal("writePrivateProfile replaced an existing private profile")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "private" {
		t.Fatalf("original profile changed: %q, %v", data, err)
	}
	if err := os.Mkdir(filepath.Join(root, "profiles", "blocked"), 0o700); err != nil {
		t.Fatal(err)
	}
	blockedPath := filepath.Join(root, "profiles", "blocked", "child")
	if err := os.WriteFile(blockedPath, []byte("not directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateProfile(filepath.Join(blockedPath, "profile.conf"), "x"); err == nil {
		t.Fatal("profile writer accepted a regular file as parent")
	}
	if err := writePrivateProfileAtomic(filepath.Join(blockedPath, "profile.conf"), "new"); err == nil {
		t.Fatal("atomic profile writer accepted a regular file as parent")
	}
	if err := os.Mkdir(filepath.Join(root, "profiles", "occupied.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateProfileAtomic(filepath.Join(root, "profiles", "occupied.conf"), "new"); err == nil || !strings.Contains(err.Error(), "activate refreshed profile") {
		t.Fatalf("atomic writer replacing a directory = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("failed atomic write left temporary file %q", entry.Name())
		}
	}
}

func TestSignalNotifyRegistersShutdownSignals(t *testing.T) {
	channel := make(chan os.Signal, 1)
	signalNotify(channel)
	syscallSignal := make(chan os.Signal, 1)
	signalNotify(syscallSignal)
	// Keep registration scoped to this test; no process signal is sent.
	signal.Stop(channel)
	signal.Stop(syscallSignal)
}

func TestServeControlServerStopsGracefullyAndReportsServeFailure(t *testing.T) {
	t.Run("graceful shutdown", func(t *testing.T) {
		listener := newScriptedListener(nil)
		shutdown := make(chan os.Signal, 1)
		server := grpc.NewServer()
		result := make(chan error, 1)
		go func() { result <- serveControlServer(server, listener, shutdown) }()
		shutdown <- os.Interrupt
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("serveControlServer shutdown = %v", err)
			}
		case <-time.After(2 * time.Second):
			server.Stop()
			t.Fatal("gRPC server did not stop after the shutdown signal")
		}
	})

	t.Run("listener failure", func(t *testing.T) {
		listener := newScriptedListener(errors.New("listener unavailable"))
		server := grpc.NewServer()
		shutdown := make(chan os.Signal)
		if err := serveControlServer(server, listener, shutdown); err == nil || !strings.Contains(err.Error(), "serve AWG control API") {
			t.Fatalf("closed listener error = %v", err)
		}
	})
}

func TestServeControlServiceRegistersAPIAndStopsGracefully(t *testing.T) {
	options := control.Options{
		DataDir: t.TempDir(), MasterKey: make([]byte, 32), PublicHost: "vpn.example.test",
		PublicPort: 1234, ListenPort: 51820,
		IPv4Prefix: netip.MustParsePrefix("10.88.0.0/24"),
		IPv6Prefix: netip.MustParsePrefix("fd88:88:88::/64"),
	}
	manager, err := control.Open(options, inertAWGFactory{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	shutdown := make(chan os.Signal, 1)
	shutdown <- os.Interrupt
	if err := serveControlService(manager, options, "test-token", newScriptedListener(nil), shutdown); err != nil {
		t.Fatalf("serveControlService() = %v", err)
	}
}

func TestServeClosesManagerWhenPrivateListenerCannotStart(t *testing.T) {
	options := control.Options{
		DataDir: t.TempDir(), MasterKey: make([]byte, 32), PublicHost: "vpn.example.test",
		PublicPort: 1234, ListenPort: 51820,
		IPv4Prefix: netip.MustParsePrefix("10.88.0.0/24"),
		IPv6Prefix: netip.MustParsePrefix("fd88:88:88::/64"),
	}
	manager, err := control.Open(options, inertAWGFactory{})
	if err != nil {
		t.Fatal(err)
	}
	previousOpen, previousListen := openControlManager, listenControl
	t.Cleanup(func() {
		openControlManager, listenControl = previousOpen, previousListen
	})
	openControlManager = func(control.Options, control.DeviceFactory) (*control.Manager, error) { return manager, nil }
	listenControl = func(network, address string) (net.Listener, error) {
		if network != "tcp" {
			t.Errorf("listener network = %q", network)
		}
		return nil, errors.New("injected bind failure")
	}
	t.Setenv("AWG_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("AWG_PUBLIC_HOST", "vpn.example.test")
	t.Setenv("AWG_PUBLIC_PORT", "1234")
	t.Setenv("AWG_LISTEN_PORT", "51820")
	t.Setenv("AWG_DATA_DIR", t.TempDir())
	t.Setenv("AWG_CONTROL_TOKEN_FILE", filepath.Join(t.TempDir(), "control.token"))
	if err := serve(); err == nil || !strings.Contains(err.Error(), "listen on private AWG control address") {
		t.Fatalf("serve() listener failure = %v", err)
	}
	_, publicKey, err := control.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AddPeer("closed", publicKey); err == nil || !strings.Contains(err.Error(), "manager is closed") {
		t.Fatalf("serve() did not close the manager on startup failure: %v", err)
	}
}

func TestPrivateProfileWritersPropagateIOFailuresAndCleanUp(t *testing.T) {
	writeErr := errors.New("injected write failure")
	syncErr := errors.New("injected sync failure")
	closeErr := errors.New("injected close failure")
	chmodErr := errors.New("injected chmod failure")

	t.Run("exclusive profile writer", func(t *testing.T) {
		for _, test := range []struct {
			name string
			file *faultProfileFile
			want string
		}{
			{name: "write", file: &faultProfileFile{writeErr: writeErr}, want: "write profile"},
			{name: "sync", file: &faultProfileFile{syncErr: syncErr}, want: "sync profile"},
			{name: "close", file: &faultProfileFile{closeErr: closeErr}, want: "close profile"},
		} {
			t.Run(test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "phone.conf")
				test.file.File = createBackingFile(t, path)
				err := writePrivateProfileWith(path, "profile", profileFileOperations{
					openExclusive: func(string) (profileFile, error) { return test.file, nil },
					remove:        os.Remove,
				})
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("writePrivateProfileWith error = %v, want %q", err, test.want)
				}
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed profile write left a private file: %v", err)
				}
			})
		}
		err := writePrivateProfileWith(filepath.Join(t.TempDir(), "phone.conf"), "profile", profileFileOperations{
			openExclusive: func(string) (profileFile, error) { return nil, errors.New("open rejected") },
		})
		if err == nil || !strings.Contains(err.Error(), "create profile securely") {
			t.Fatalf("exclusive profile open error = %v", err)
		}
	})

	t.Run("atomic profile writer", func(t *testing.T) {
		for _, test := range []struct {
			name string
			file *faultProfileFile
			want string
		}{
			{name: "chmod", file: &faultProfileFile{chmodErr: chmodErr}, want: "secure refreshed profile"},
			{name: "write", file: &faultProfileFile{writeErr: writeErr}, want: "write refreshed profile"},
			{name: "sync", file: &faultProfileFile{syncErr: syncErr}, want: "sync refreshed profile"},
			{name: "close", file: &faultProfileFile{closeErr: closeErr}, want: "close refreshed profile"},
		} {
			t.Run(test.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "phone.conf")
				if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
				err := writePrivateProfileAtomicWith(path, "replacement", profileFileOperations{
					createTemp: func(dir, pattern string) (profileFile, error) {
						file, err := os.CreateTemp(dir, pattern)
						if err != nil {
							return nil, err
						}
						test.file.File = file
						return test.file, nil
					},
					rename: os.Rename,
					remove: os.Remove,
				})
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("writePrivateProfileAtomicWith error = %v, want %q", err, test.want)
				}
				if data, err := os.ReadFile(path); err != nil || string(data) != "original" {
					t.Fatalf("failed atomic write changed existing profile: %q, %v", data, err)
				}
				entries, err := os.ReadDir(root)
				if err != nil || len(entries) != 1 {
					t.Fatalf("failed atomic write left temporary files: %v, %v", entries, err)
				}
			})
		}
	})
}

func createBackingFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
