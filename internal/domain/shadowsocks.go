package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	ShadowsocksMethodChaCha20Poly1305 = "chacha20-poly1305"
	ShadowsocksMethodAES256GCM        = "aes-256-gcm"
	ShadowsocksMethodAES128GCM        = "aes-128-gcm"
	ShadowsocksNetworkTCP             = "tcp"
	ShadowsocksNetworkUDP             = "udp"
	ShadowsocksNetworkTCPUDP          = "tcp,udp"
)

// ShadowsocksSettings is the node-wide classic Shadowsocks inbound setup.
// The 2022 cipher family is deliberately excluded until Xray exposes a
// reliable live per-user management API for it.
type ShadowsocksSettings struct {
	Enabled    bool
	PublicPort int
	Method     string
	Network    string
}

func (s ShadowsocksSettings) Validate() error {
	if !s.Enabled {
		return nil
	}
	if s.PublicPort < 1 || s.PublicPort > 65535 {
		return errors.New("Shadowsocks public port must be between 1 and 65535")
	}
	if !SupportsShadowsocksMethod(s.Method) {
		return fmt.Errorf("unsupported Shadowsocks method %q", s.Method)
	}
	if !SupportsShadowsocksNetwork(s.Network) {
		return fmt.Errorf("unsupported Shadowsocks network %q", s.Network)
	}
	return nil
}

func SupportsShadowsocksMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case ShadowsocksMethodChaCha20Poly1305, ShadowsocksMethodAES256GCM, ShadowsocksMethodAES128GCM:
		return true
	default:
		return false
	}
}

func SupportsShadowsocksNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case ShadowsocksNetworkTCP, ShadowsocksNetworkUDP, ShadowsocksNetworkTCPUDP:
		return true
	default:
		return false
	}
}

func (s ShadowsocksSettings) String() string {
	return strings.Join([]string{strconv.Itoa(s.PublicPort), s.Method, s.Network}, "/")
}
