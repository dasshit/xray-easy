//go:build linux

package control

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func TestKernelNetworkSetup(t *testing.T) {
	log := filepath.Join(t.TempDir(), "commands.log")
	installKernelCommands(t, log, `
case "$1" in
  -4) echo '1.1.1.1 dev eth4' ;;
  -6) echo '2606:4700:4700::1111 dev eth6' ;;
esac
`)
	t.Setenv("FIREWALL_MODE", "add")
	opts := kernelTestOptions()

	if err := configureTunnel("awg0", 1280, opts); err != nil {
		t.Fatalf("configureTunnel() error = %v", err)
	}
	if err := configureForwarding("awg0", opts); err != nil {
		t.Fatalf("configureForwarding() error = %v", err)
	}

	commands, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"ip addr add 10.88.0.1/24 dev awg0",
		"ip -6 addr add fd88:88:88::1/64 dev awg0",
		"ip link set dev awg0 mtu 1280 up",
		"ip -4 -o route get 1.1.1.1",
		"ip -6 -o route get 2606:4700:4700::1111",
		"iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o eth4 -j MASQUERADE",
		"ip6tables -t nat -A POSTROUTING -s fd88:88:88::/64 -o eth6 -j MASQUERADE",
	} {
		if !strings.Contains(string(commands), expected) {
			t.Errorf("network commands do not contain %q:\n%s", expected, commands)
		}
	}
}

func TestKernelNetworkSetupReturnsCommandFailures(t *testing.T) {
	t.Run("configure tunnel", func(t *testing.T) {
		installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
if [ "$IP_MODE" = "ipv6-fail" ] && [ "$1" = "-6" ]; then echo 'bad address' >&2; exit 1; fi
`)
		t.Setenv("IP_MODE", "ipv6-fail")
		if err := configureTunnel("awg0", 1280, kernelTestOptions()); err == nil || !strings.Contains(err.Error(), "configure TUN interface") {
			t.Fatalf("configureTunnel() error = %v, want command error", err)
		}
	})

	t.Run("IPv4 route", func(t *testing.T) {
		installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
if [ "$IP_MODE" = "route4-fail" ] && [ "$1" = "-4" ]; then exit 1; fi
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac
`)
		t.Setenv("IP_MODE", "route4-fail")
		if err := configureForwarding("awg0", kernelTestOptions()); err == nil || !strings.Contains(err.Error(), "find IPv4 egress interface") {
			t.Fatalf("configureForwarding() error = %v, want IPv4 route error", err)
		}
	})

	t.Run("IPv6 route", func(t *testing.T) {
		installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
if [ "$IP_MODE" = "route6-fail" ] && [ "$1" = "-6" ]; then exit 1; fi
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac
`)
		t.Setenv("IP_MODE", "route6-fail")
		if err := configureForwarding("awg0", kernelTestOptions()); err == nil || !strings.Contains(err.Error(), "find IPv6 egress interface") {
			t.Fatalf("configureForwarding() error = %v, want IPv6 route error", err)
		}
	})

	for _, rule := range []struct {
		name string
		args string
		want string
	}{
		{"IPv4 forward", "-A FORWARD -i awg0 -o eth4 -j ACCEPT", "allow IPv4 forwarding"},
		{"IPv4 return", "-A FORWARD -i eth4 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "allow IPv4 return traffic"},
		{"IPv4 masquerade", "-t nat -A POSTROUTING -s 10.88.0.0/24 -o eth4 -j MASQUERADE", "enable IPv4 NAT for AWG clients"},
		{"IPv6 forward", "-A FORWARD -i awg0 -o eth6 -j ACCEPT", "allow IPv6 forwarding"},
		{"IPv6 return", "-A FORWARD -i eth6 -o awg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "allow IPv6 return traffic"},
		{"IPv6 masquerade", "-t nat -A POSTROUTING -s fd88:88:88::/64 -o eth6 -j MASQUERADE", "enable IPv6 NAT for AWG clients"},
	} {
		t.Run(rule.name, func(t *testing.T) {
			installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac
`)
			t.Setenv("FIREWALL_MODE", "add-fail-match")
			t.Setenv("FIREWALL_FAIL_ARGS", rule.args)
			if err := configureForwarding("awg0", kernelTestOptions()); err == nil || !strings.Contains(err.Error(), rule.want) {
				t.Fatalf("configureForwarding() error = %v, want %q", err, rule.want)
			}
		})
	}

	t.Run("existing firewall rule", func(t *testing.T) {
		installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac
`)
		t.Setenv("FIREWALL_MODE", "existing")
		if err := configureForwarding("awg0", kernelTestOptions()); err != nil {
			t.Fatalf("configureForwarding() with existing rules error = %v", err)
		}
	})
}

func TestKernelRouteAndCommandErrors(t *testing.T) {
	log := filepath.Join(t.TempDir(), "commands.log")
	installKernelCommands(t, log, `echo 'route unreachable'`)
	if _, err := routeDeviceFor("-4", "1.1.1.1"); err == nil || !strings.Contains(err.Error(), "route has no device") {
		t.Fatalf("routeDeviceFor() error = %v, want missing device error", err)
	}
	if err := run("missing-kernel-test-command"); err == nil {
		t.Fatal("run() succeeded for a missing command")
	}
	if err := run("ip", "fail"); err == nil || !strings.Contains(err.Error(), "ip fail") {
		t.Fatalf("run() error = %v, want wrapped command failure", err)
	}
}

func TestKernelFactoryReportsTunCreationFailure(t *testing.T) {
	factory := KernelFactory{
		Options: kernelTestOptions(),
		createTUN: func(string, int) (tun.Device, error) {
			return nil, errors.New("TUN unavailable")
		},
	}
	if _, err := factory.Open("awg-test", 1280); err == nil || !strings.Contains(err.Error(), "create /dev/net/tun interface") {
		t.Fatalf("KernelFactory.Open() error = %v, want TUN creation error", err)
	}
}

func TestKernelFactoryClosesTunAfterSetupFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		ipScript string
		ipMode   string
		nameErr  error
		wantErr  string
	}{
		{name: "read interface name", nameErr: errors.New("name unavailable"), wantErr: "read TUN interface name"},
		{name: "configure interface", ipScript: `if [ "$IP_MODE" = "ipv6-fail" ] && [ "$1" = "-6" ]; then exit 1; fi`, ipMode: "ipv6-fail", wantErr: "configure TUN interface"},
		{name: "configure forwarding", ipScript: `if [ "$IP_MODE" = "route4-fail" ] && [ "$1" = "-4" ]; then exit 1; fi
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac`, ipMode: "route4-fail", wantErr: "find IPv4 egress interface"},
	} {
		t.Run(test.name, func(t *testing.T) {
			installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), test.ipScript)
			t.Setenv("IP_MODE", test.ipMode)
			fakeTun := &kernelTunStub{name: "awg-test", nameErr: test.nameErr}
			factory := KernelFactory{Options: kernelTestOptions(), createTUN: func(string, int) (tun.Device, error) {
				return fakeTun, nil
			}}
			if _, err := factory.Open("awg-test", 1280); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("KernelFactory.Open() error = %v, want %q", err, test.wantErr)
			}
			if !fakeTun.closed {
				t.Fatal("KernelFactory.Open() did not close TUN after setup failure")
			}
		})
	}
}

func TestKernelFactoryOpensDevice(t *testing.T) {
	installKernelCommands(t, filepath.Join(t.TempDir(), "commands.log"), `
case "$1" in -4) echo 'route dev eth4';; -6) echo 'route dev eth6';; esac
`)
	t.Setenv("FIREWALL_MODE", "existing")
	fakeTun := &kernelTunStub{name: "awg-test"}
	engine := &kernelEngineStub{tunDevice: fakeTun}
	factory := KernelFactory{
		Options:   kernelTestOptions(),
		createTUN: func(string, int) (tun.Device, error) { return fakeTun, nil },
		newEngine: func(tun.Device) kernelEngine { return engine },
	}
	dev, err := factory.Open("awg-test", 1280)
	if err != nil {
		t.Fatalf("KernelFactory.Open() error = %v", err)
	}
	dev.Close()
	if !fakeTun.closed {
		t.Fatal("closing the kernel device did not close its TUN device")
	}
}

func TestKernelDeviceDelegatesOperations(t *testing.T) {
	engine := &kernelEngineStub{}
	dev := &kernelDevice{engine: engine}
	if err := dev.Set("device config"); err != nil || engine.setInput != "device config" {
		t.Fatalf("Set() error/input = %v/%q", err, engine.setInput)
	}
	if err := dev.Up(); err != nil || !engine.upCalled {
		t.Fatalf("Up() error/called = %v/%v", err, engine.upCalled)
	}
	if snapshot, err := dev.Snapshot(); err != nil || snapshot != "test snapshot" {
		t.Fatalf("Snapshot() = %q, %v", snapshot, err)
	}
	engine.snapshotErr = errors.New("snapshot unavailable")
	if snapshot, err := dev.Snapshot(); err == nil || snapshot != "" {
		t.Fatalf("Snapshot() with engine error = %q, %v", snapshot, err)
	}
	dev.Close()
	if !engine.closed {
		t.Fatal("Close() did not close the engine")
	}
}

func installKernelCommands(t *testing.T, commandLog, ipScript string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("COMMAND_LOG", commandLog)
	t.Setenv("PATH", dir)
	writeExecutable(t, filepath.Join(dir, "ip"), "#!/bin/sh\nprintf 'ip %s\\n' \"$*\" >> \"$COMMAND_LOG\"\n"+ipScript+"\nif [ \"$1\" = fail ]; then echo 'command failed' >&2; exit 1; fi\nexit 0\n")
	for _, binary := range []string{"iptables", "ip6tables"} {
		script := "#!/bin/sh\nprintf '" + binary + " %s\\n' \"$*\" >> \"$COMMAND_LOG\"\n" +
			"if [ \"$FIREWALL_MODE\" = add-fail-match ] && [ \"$*\" = \"$FIREWALL_FAIL_ARGS\" ]; then echo 'rule add failed' >&2; exit 1; fi\n" +
			"case \"$FIREWALL_MODE\" in\n" +
			"  existing) exit 0 ;;\n" +
			"  add-fail) echo 'rule add failed' >&2; exit 1 ;;\n" +
			"  add-fail-match) case \" $* \" in *\" -C \"*) echo 'rule missing' >&2; exit 1 ;; esac ;;\n" +
			"  add) case \" $* \" in *\" -C \"*) echo 'rule missing' >&2; exit 1 ;; esac ;;\n" +
			"esac\nexit 0\n"
		writeExecutable(t, filepath.Join(dir, binary), script)
	}
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func kernelTestOptions() Options {
	return Options{
		IPv4Prefix: netip.MustParsePrefix("10.88.0.0/24"),
		IPv6Prefix: netip.MustParsePrefix("fd88:88:88::/64"),
	}
}

type kernelTunStub struct {
	name    string
	nameErr error
	closed  bool
}

func (t *kernelTunStub) File() *os.File { return nil }

func (t *kernelTunStub) Read([][]byte, []int, int) (int, error) { return 0, nil }

func (t *kernelTunStub) Write([][]byte, int) (int, error) { return 0, nil }

func (t *kernelTunStub) MTU() (int, error) { return 1280, nil }

func (t *kernelTunStub) Name() (string, error) { return t.name, t.nameErr }

func (t *kernelTunStub) Events() <-chan tun.Event { return nil }

func (t *kernelTunStub) Close() error {
	t.closed = true
	return nil
}

func (t *kernelTunStub) BatchSize() int { return 1 }

type kernelEngineStub struct {
	setInput    string
	setErr      error
	upCalled    bool
	upErr       error
	snapshotErr error
	closed      bool
	tunDevice   tun.Device
}

func (e *kernelEngineStub) IpcSetOperation(input io.Reader) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return err
	}
	e.setInput = string(data)
	return e.setErr
}

func (e *kernelEngineStub) Up() error {
	e.upCalled = true
	return e.upErr
}

func (e *kernelEngineStub) IpcGetOperation(output io.Writer) error {
	if e.snapshotErr != nil {
		return e.snapshotErr
	}
	_, err := io.WriteString(output, "test snapshot")
	return err
}

func (e *kernelEngineStub) Close() {
	e.closed = true
	if e.tunDevice != nil {
		_ = e.tunDevice.Close()
	}
}
