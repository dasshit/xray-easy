package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestProbeIPv6UsesTCP6ClosesConnectionAndReportsErrors(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	calls := 0
	err := probeIPv6With(context.Background(), func(_ context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp6" || address != ipv6ProbeAddress {
			t.Fatalf("IPv6 probe dial = %s %s", network, address)
		}
		return local, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("probe result: calls=%d err=%v", calls, err)
	}
	if _, err := local.Write([]byte("closed")); err == nil {
		t.Fatal("IPv6 probe kept the connection open")
	}
	wantErr := errors.New("no IPv6 route")
	if err := probeIPv6With(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("IPv6 probe error = %v, want wrapped %v", err, wantErr)
	}
	if err := probeIPv6With(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "no connection") {
		t.Fatalf("nil IPv6 connection error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeIPv6(canceled); err == nil {
		t.Fatal("canceled real IPv6 probe succeeded")
	}
}

func TestProbeTargetUsesResolvedAddressesAndTLSName(t *testing.T) {
	publicIP := net.ParseIP("93.184.216.34")
	var lookedUp, dialed string
	var dialConfig *tls.Config
	var receivedDeadline bool
	peer, remote := net.Pipe()
	defer remote.Close()
	err := probeTargetWith("example.test:443", "front.example", func(ctx context.Context, network, host string) ([]net.IP, error) {
		lookedUp = network + ":" + host
		_, receivedDeadline = ctx.Deadline()
		return []net.IP{publicIP}, nil
	}, func(address string, config *tls.Config) (net.Conn, error) {
		dialed, dialConfig = address, config
		return peer, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookedUp != "ip:example.test" || !receivedDeadline || dialed != "93.184.216.34:443" {
		t.Fatalf("lookup/dial = %q, deadline=%v, %q", lookedUp, receivedDeadline, dialed)
	}
	if dialConfig.ServerName != "front.example" || dialConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config = %+v", dialConfig)
	}
	if err := probeTargetWith("93.184.216.34:8443", "", func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("literal IP should not use DNS")
		return nil, nil
	}, func(address string, config *tls.Config) (net.Conn, error) {
		if address != "93.184.216.34:8443" || config.ServerName != "93.184.216.34" {
			t.Fatalf("literal IP dial config = %q %+v", address, config)
		}
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}); err != nil {
		t.Fatalf("public IP probe failed: %v", err)
	}
	if err := probeTarget("bad-target", ""); err == nil {
		t.Fatal("probeTarget accepted a malformed target")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeTargetContext(canceled, "cancelled.example:443", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("probeTargetContext canceled error = %v", err)
	}
}

func TestProbeTargetRejectsBadTargetsUnsafeAddressesAndFailures(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]net.IP, error) {
		switch host {
		case "private.test":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}, nil
		case "empty.test":
			return nil, nil
		case "broken.test":
			return nil, errors.New("DNS unavailable")
		default:
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
	}
	neverDial := func(string, *tls.Config) (net.Conn, error) {
		t.Fatal("unsafe target reached TLS dial")
		return nil, nil
	}
	for _, target := range []string{"", "example.test", "example.test:0", "example.test:65536", "example.test:https"} {
		if err := probeTargetWith(target, "", lookup, neverDial); err == nil {
			t.Errorf("invalid target %q accepted", target)
		}
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "169.254.10.1", "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::"} {
		if err := probeTargetWith(net.JoinHostPort(host, "443"), "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), "private or local") {
			t.Errorf("unsafe literal %q error = %v", host, err)
		}
	}
	for _, testcase := range []struct {
		host string
		want string
	}{
		{"private.test", "private or local"},
		{"empty.test", "no addresses"},
		{"broken.test", "DNS unavailable"},
	} {
		if err := probeTargetWith(testcase.host+":443", "", lookup, neverDial); err == nil || !strings.Contains(err.Error(), testcase.want) {
			t.Errorf("%s error = %v", testcase.host, err)
		}
	}
	if err := probeTargetWith("example.test:443", "", lookup, func(string, *tls.Config) (net.Conn, error) { return nil, errors.New("handshake failed") }); err == nil || !strings.Contains(err.Error(), "TLS probe failed") || !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("TLS dial failure = %v", err)
	}
	if err := probeTargetWith("example.test:443", "", lookup, func(string, *tls.Config) (net.Conn, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "dialer returned no connection") {
		t.Fatalf("nil TLS connection error = %v", err)
	}
}

func TestProbeTargetRetriesPublicAddressesAndHonorsCancellation(t *testing.T) {
	addresses := []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("1.1.1.1")}
	calls := 0
	err := probeTargetWith("multi.example.test:443", "front.example.test", func(context.Context, string, string) ([]net.IP, error) {
		return addresses, nil
	}, func(address string, _ *tls.Config) (net.Conn, error) {
		calls++
		if calls == 1 {
			if address != "93.184.216.34:443" {
				t.Fatalf("first candidate address = %q", address)
			}
			return nil, errors.New("first address timed out")
		}
		if address != "1.1.1.1:443" {
			t.Fatalf("second candidate address = %q", address)
		}
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("probe retry result: calls=%d err=%v", calls, err)
	}
	if err := probeTargetWith("multi.example.test:443", "", func(context.Context, string, string) ([]net.IP, error) { return addresses, nil }, func(string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("all addresses timed out")
	}); err == nil || !strings.Contains(err.Error(), "all addresses timed out") {
		t.Fatalf("final probe error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = probeTargetContextWith(ctx, "cancelled.example:443", "", func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, func(context.Context, string, *tls.Config) (net.Conn, error) {
		t.Fatal("cancelled lookup reached dialer")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled target probe error = %v", err)
	}
}

func TestForbiddenProbeIP(t *testing.T) {
	for _, test := range []struct {
		name string
		ip   net.IP
		want bool
	}{
		{name: "public", ip: net.ParseIP("93.184.216.34")},
		{name: "loopback", ip: net.ParseIP("127.0.0.1"), want: true},
		{name: "private", ip: net.ParseIP("192.168.1.1"), want: true},
		{name: "link local", ip: net.ParseIP("169.254.1.1"), want: true},
		{name: "unspecified", ip: net.ParseIP("::"), want: true},
		{name: "multicast", ip: net.ParseIP("ff02::1"), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := forbiddenProbeIP(test.ip); got != test.want {
				t.Fatalf("forbiddenProbeIP(%s) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}
