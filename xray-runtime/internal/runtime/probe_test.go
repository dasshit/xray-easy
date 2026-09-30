package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type probeTestConn struct{ closeErr error }

func (*probeTestConn) Read([]byte) (int, error)           { return 0, nil }
func (*probeTestConn) Write([]byte) (int, error)          { return 0, nil }
func (*probeTestConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (*probeTestConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (*probeTestConn) SetDeadline(_ time.Time) error      { return nil }
func (*probeTestConn) SetReadDeadline(_ time.Time) error  { return nil }
func (*probeTestConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *probeTestConn) Close() error                     { return c.closeErr }

func TestProbeIPv6EgressWith(t *testing.T) {
	wantConn := &probeTestConn{}
	if err := probeIPv6EgressWith(context.Background(), func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp6" || address != ipv6ProbeAddress {
			t.Fatalf("IPv6 probe dial = %q %q", network, address)
		}
		return wantConn, nil
	}); err != nil {
		t.Fatalf("probeIPv6EgressWith() error = %v", err)
	}
	if err := probeIPv6EgressWith(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") }); err == nil {
		t.Fatal("IPv6 dial error was ignored")
	}
	if err := probeIPv6EgressWith(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, nil }); err == nil {
		t.Fatal("nil IPv6 connection was accepted")
	}
	wantCloseErr := errors.New("close failed")
	if err := probeIPv6EgressWith(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return &probeTestConn{closeErr: wantCloseErr}, nil
	}); !errors.Is(err, wantCloseErr) {
		t.Fatalf("IPv6 probe close error = %v", err)
	}
}

func TestProbeRealityTargetWithResolvesAndPinsTLSAddress(t *testing.T) {
	lookups := 0
	dials := 0
	err := probeRealityTargetWith(context.Background(), "reality.example:443", "front.example", func(_ context.Context, network, host string) ([]net.IP, error) {
		lookups++
		if network != "ip" || host != "reality.example" {
			t.Fatalf("DNS lookup = %q %q", network, host)
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	}, func(_ context.Context, address string, config *tls.Config) (net.Conn, error) {
		dials++
		if address != "203.0.113.10:443" || config.ServerName != "front.example" || config.MinVersion != tls.VersionTLS12 {
			t.Fatalf("TLS dial = %q %+v", address, config)
		}
		return &probeTestConn{}, nil
	})
	if err != nil || lookups != 1 || dials != 1 {
		t.Fatalf("probeRealityTargetWith() = %v, lookups=%d dials=%d", err, lookups, dials)
	}
}

func TestProbeRealityTargetWithValidatesAndUsesLiteralAddress(t *testing.T) {
	for _, target := range []string{"missing-port", "host:0", "host:65536", "host:nope"} {
		err := probeRealityTargetWith(context.Background(), target, "", func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("invalid target performed DNS lookup")
			return nil, nil
		}, func(context.Context, string, *tls.Config) (net.Conn, error) {
			t.Fatal("invalid target attempted TLS")
			return nil, nil
		})
		if !errors.Is(err, errInvalidProbeTarget) {
			t.Fatalf("target %q error = %v, want invalid target", target, err)
		}
	}
	dials := 0
	if err := probeRealityTargetWith(context.Background(), "203.0.113.20:443", "", func(context.Context, string, string) ([]net.IP, error) {
		t.Fatal("literal IP performed DNS lookup")
		return nil, nil
	}, func(_ context.Context, address string, config *tls.Config) (net.Conn, error) {
		dials++
		if address != "203.0.113.20:443" || config.ServerName != "203.0.113.20" {
			t.Fatalf("literal TLS dial = %q with SNI %q", address, config.ServerName)
		}
		return &probeTestConn{}, nil
	}); err != nil || dials != 1 {
		t.Fatalf("literal target probe = %v, dials=%d", err, dials)
	}
}

func TestProbeRealityTargetWithHandlesResolutionAndAddressFailures(t *testing.T) {
	lookupError := errors.New("DNS unavailable")
	if err := probeRealityTargetWith(context.Background(), "front.example:443", "", func(context.Context, string, string) ([]net.IP, error) { return nil, lookupError }, nil); !errors.Is(err, lookupError) {
		t.Fatalf("DNS error = %v", err)
	}
	if err := probeRealityTargetWith(context.Background(), "front.example:443", "", func(context.Context, string, string) ([]net.IP, error) { return nil, nil }, nil); err == nil || !strings.Contains(err.Error(), "no addresses") {
		t.Fatalf("empty DNS result error = %v", err)
	}
	for _, unsafe := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"} {
		err := probeRealityTargetWith(context.Background(), "front.example:443", "", func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP(unsafe)}, nil }, func(context.Context, string, *tls.Config) (net.Conn, error) {
			t.Fatal("unsafe address attempted TLS")
			return nil, nil
		})
		if !errors.Is(err, errInvalidProbeTarget) {
			t.Fatalf("unsafe address %s error = %v", unsafe, err)
		}
	}
}

func TestProbeRealityTargetWithRetriesAddressesAndRejectsEmptyConn(t *testing.T) {
	addresses := []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.11")}
	var attempted []string
	if err := probeRealityTargetWith(context.Background(), "front.example:8443", "front.example", func(context.Context, string, string) ([]net.IP, error) { return addresses, nil }, func(_ context.Context, address string, _ *tls.Config) (net.Conn, error) {
		attempted = append(attempted, address)
		if len(attempted) == 1 {
			return nil, errors.New("first IP failed")
		}
		return &probeTestConn{}, nil
	}); err != nil || len(attempted) != 2 {
		t.Fatalf("multiple address probe = %v, attempts=%v", err, attempted)
	}
	if err := probeRealityTargetWith(context.Background(), "203.0.113.12:443", "", nil, func(context.Context, string, *tls.Config) (net.Conn, error) { return nil, nil }); err == nil || !strings.Contains(err.Error(), "no connection") {
		t.Fatalf("nil TLS connection error = %v", err)
	}
	wantErr := errors.New("TLS failed")
	if err := probeRealityTargetWith(context.Background(), "203.0.113.13:443", "", nil, func(context.Context, string, *tls.Config) (net.Conn, error) { return nil, wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("TLS failure = %v", err)
	}
}

func TestDefaultProbeFunctionsHonorEarlyCancellationAndValidation(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeIPv6Egress(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled IPv6 probe error = %v", err)
	}
	if err := probeRealityTarget(context.Background(), "missing-port", ""); !errors.Is(err, errInvalidProbeTarget) {
		t.Fatalf("invalid default target error = %v", err)
	}
}
