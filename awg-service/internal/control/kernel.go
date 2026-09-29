//go:build linux

package control

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// KernelFactory creates a userspace AmneziaWG engine on Linux.
type KernelFactory struct {
	Options Options
}

// Open creates the TUN interface, installs routes and NAT, then wraps amneziawg-go.
func (f KernelFactory) Open(name string, mtu int) (Device, error) {
	tunDevice, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create /dev/net/tun interface: %w", err)
	}
	actualName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("read TUN interface name: %w", err)
	}
	if err := configureTunnel(actualName, mtu, f.Options); err != nil {
		tunDevice.Close()
		return nil, err
	}
	if err := configureForwarding(actualName, f.Options); err != nil {
		tunDevice.Close()
		return nil, err
	}
	engine := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "(awg) "))
	return &kernelDevice{engine: engine}, nil
}

type kernelDevice struct {
	engine *device.Device
}

func (d *kernelDevice) Set(config string) error {
	return d.engine.IpcSetOperation(strings.NewReader(config))
}

func (d *kernelDevice) Up() error { return d.engine.Up() }

func (d *kernelDevice) Snapshot() (string, error) {
	var output bytes.Buffer
	if err := d.engine.IpcGetOperation(&output); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (d *kernelDevice) Close() { d.engine.Close() }

func configureTunnel(name string, mtu int, opts Options) error {
	commands := [][]string{
		{"addr", "add", opts.IPv4Prefix.Addr().Next().String() + "/" + fmt.Sprint(opts.IPv4Prefix.Bits()), "dev", name},
		{"-6", "addr", "add", opts.IPv6Prefix.Addr().Next().String() + "/" + fmt.Sprint(opts.IPv6Prefix.Bits()), "dev", name},
		{"link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up"},
	}
	for _, args := range commands {
		if err := run("ip", args...); err != nil {
			return fmt.Errorf("configure TUN interface: %w", err)
		}
	}
	return nil
}

func configureForwarding(name string, opts Options) error {
	egress4, err := routeDeviceFor("-4", "1.1.1.1")
	if err != nil {
		return fmt.Errorf("find IPv4 egress interface: %w", err)
	}
	egress6, err := routeDeviceFor("-6", "2606:4700:4700::1111")
	if err != nil {
		return fmt.Errorf("find IPv6 egress interface (the AWG full-tunnel profile requires IPv6 egress): %w", err)
	}
	if err := ensureRule("iptables", []string{"-C", "FORWARD", "-i", name, "-o", egress4, "-j", "ACCEPT"}, []string{"-A", "FORWARD", "-i", name, "-o", egress4, "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("allow IPv4 forwarding from AWG interface: %w", err)
	}
	if err := ensureRule("iptables", []string{"-C", "FORWARD", "-i", egress4, "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, []string{"-A", "FORWARD", "-i", egress4, "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("allow IPv4 return traffic: %w", err)
	}
	if err := ensureRule("iptables", []string{"-t", "nat", "-C", "POSTROUTING", "-s", opts.IPv4Prefix.String(), "-o", egress4, "-j", "MASQUERADE"}, []string{"-t", "nat", "-A", "POSTROUTING", "-s", opts.IPv4Prefix.String(), "-o", egress4, "-j", "MASQUERADE"}); err != nil {
		return fmt.Errorf("enable IPv4 NAT for AWG clients: %w", err)
	}
	if err := ensureRule("ip6tables", []string{"-C", "FORWARD", "-i", name, "-o", egress6, "-j", "ACCEPT"}, []string{"-A", "FORWARD", "-i", name, "-o", egress6, "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("allow IPv6 forwarding from AWG interface: %w", err)
	}
	if err := ensureRule("ip6tables", []string{"-C", "FORWARD", "-i", egress6, "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}, []string{"-A", "FORWARD", "-i", egress6, "-o", name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}); err != nil {
		return fmt.Errorf("allow IPv6 return traffic: %w", err)
	}
	if err := ensureRule("ip6tables", []string{"-t", "nat", "-C", "POSTROUTING", "-s", opts.IPv6Prefix.String(), "-o", egress6, "-j", "MASQUERADE"}, []string{"-t", "nat", "-A", "POSTROUTING", "-s", opts.IPv6Prefix.String(), "-o", egress6, "-j", "MASQUERADE"}); err != nil {
		return fmt.Errorf("enable IPv6 NAT for AWG clients: %w", err)
	}
	return nil
}

func routeDeviceFor(family, destination string) (string, error) {
	args := []string{"-o", "route", "get", destination}
	if family != "" {
		args = append([]string{family}, args...)
	}
	route, err := exec.Command("ip", args...).Output()
	if err != nil {
		return "", err
	}
	return routeDevice(string(route))
}

func ensureRule(binary string, check, add []string) error {
	if err := runRule(binary, check); err == nil {
		return nil
	}
	return runRule(binary, add)
}

func runRule(binary string, args []string) error { return run(binary, args...) }

func run(binary string, args ...string) error {
	command := exec.Command(binary, args...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", binary, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
