package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

const ipv6ProbeAddress = "[2606:4700:4700::1111]:443"

var errInvalidProbeTarget = errors.New("invalid probe target")

func probeIPv6(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return probeIPv6With(ctx, dialer.DialContext)
}

func probeIPv6With(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	conn, err := dial(ctx, "tcp6", ipv6ProbeAddress)
	if err != nil {
		return fmt.Errorf("connect to IPv6 probe endpoint: %w", err)
	}
	if conn == nil {
		return errors.New("IPv6 probe dialer returned no connection")
	}
	return conn.Close()
}

func probeTarget(target, sni string) error {
	return probeTargetContext(context.Background(), target, sni)
}

func probeTargetContext(parent context.Context, target, sni string) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return probeTargetContextWith(parent, target, sni, net.DefaultResolver.LookupIP, func(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", address)
	})
}

func probeTargetWith(target, sni string, lookupIP func(context.Context, string, string) ([]net.IP, error), dialTLS func(string, *tls.Config) (net.Conn, error)) error {
	return probeTargetContextWith(context.Background(), target, sni, lookupIP, func(_ context.Context, address string, config *tls.Config) (net.Conn, error) {
		return dialTLS(address, config)
	})
}

func probeTargetContextWith(parent context.Context, target, sni string, lookupIP func(context.Context, string, string) ([]net.IP, error), dialTLS func(context.Context, string, *tls.Config) (net.Conn, error)) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%w: target must be host:port", errInvalidProbeTarget)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%w: target port must be between 1 and 65535", errInvalidProbeTarget)
	}
	if sni == "" {
		sni = host
	}
	addresses := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		addresses = append(addresses, ip)
	} else {
		addresses, err = lookupIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("resolve target: %w", err)
		}
	}
	if len(addresses) == 0 {
		return errors.New("target has no addresses")
	}
	for _, address := range addresses {
		if forbiddenProbeIP(address) {
			return fmt.Errorf("%w: target resolves to a private or local address", errInvalidProbeTarget)
		}
	}
	// Dial the address returned by the same DNS lookup that passed the SSRF
	// checks. Using the hostname here would allow a DNS rebinding between the
	// check and the TLS connection.
	var lastErr error
	for _, address := range addresses {
		conn, dialErr := dialTLS(ctx, net.JoinHostPort(address.String(), port), &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
		if dialErr == nil {
			if conn == nil {
				return errors.New("TLS probe dialer returned no connection")
			}
			_ = conn.Close()
			return nil
		}
		lastErr = dialErr
	}
	return fmt.Errorf("TLS probe failed: %w", lastErr)
}

func forbiddenProbeIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()
}
