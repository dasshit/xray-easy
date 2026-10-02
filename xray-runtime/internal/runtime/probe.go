package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ipv6ProbeAddress is an internal package constant.
const ipv6ProbeAddress = "[2606:4700:4700::1111]:443"

// errInvalidProbeTarget is an internal package variable.
var errInvalidProbeTarget = errors.New("invalid REALITY target")

// probeIPv6Egress performs the operation represented by its name.
func probeIPv6Egress(ctx context.Context) error {
	probeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return probeIPv6EgressWith(probeContext, dialer.DialContext)
}

// probeIPv6EgressWith performs the operation represented by its name.
func probeIPv6EgressWith(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	connection, err := dial(ctx, "tcp6", ipv6ProbeAddress)
	if err != nil {
		return fmt.Errorf("connect to IPv6 probe endpoint: %w", err)
	}
	if connection == nil {
		return errors.New("IPv6 probe dialer returned no connection")
	}
	return connection.Close()
}

// probeRealityTarget performs the operation represented by its name.
func probeRealityTarget(ctx context.Context, target, serverName string) error {
	probeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return probeRealityTargetWith(probeContext, target, serverName, net.DefaultResolver.LookupIP, func(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
		return (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", address)
	})
}

// probeRealityTargetWith performs the operation represented by its name.
func probeRealityTargetWith(ctx context.Context, target, serverName string, lookupIP func(context.Context, string, string) ([]net.IP, error), dialTLS func(context.Context, string, *tls.Config) (net.Conn, error)) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%w: target must be host:port", errInvalidProbeTarget)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%w: target port is invalid", errInvalidProbeTarget)
	}
	if serverName == "" {
		serverName = host
	}
	addresses := []net.IP{}
	if address := net.ParseIP(host); address != nil {
		addresses = append(addresses, address)
	} else {
		addresses, err = lookupIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("resolve REALITY target: %w", err)
		}
	}
	if len(addresses) == 0 {
		return errors.New("REALITY target has no addresses")
	}
	for _, address := range addresses {
		if forbiddenProbeIP(address) {
			return fmt.Errorf("%w: target resolves to a private or local address", errInvalidProbeTarget)
		}
	}
	var lastError error
	for _, address := range addresses {
		connection, dialError := dialTLS(ctx, net.JoinHostPort(address.String(), port), &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		if dialError == nil {
			if connection == nil {
				return errors.New("REALITY target TLS dialer returned no connection")
			}
			_ = connection.Close()
			return nil
		}
		lastError = dialError
	}
	return fmt.Errorf("REALITY target TLS probe failed: %w", lastError)
}

// forbiddenProbeIP performs the operation represented by its name.
func forbiddenProbeIP(address net.IP) bool {
	return address == nil || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast()
}
