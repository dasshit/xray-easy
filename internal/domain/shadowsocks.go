package domain

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// ShadowsocksMethodChaCha20Poly1305 identifies a supported package value.
	ShadowsocksMethodChaCha20Poly1305 = "chacha20-poly1305"
	// ShadowsocksMethodAES256GCM identifies a supported package value.
	ShadowsocksMethodAES256GCM = "aes-256-gcm"
	// ShadowsocksMethodAES128GCM identifies a supported package value.
	ShadowsocksMethodAES128GCM = "aes-128-gcm"
	// ShadowsocksNetworkTCP identifies a supported package value.
	ShadowsocksNetworkTCP = "tcp"
	// ShadowsocksNetworkUDP identifies a supported package value.
	ShadowsocksNetworkUDP = "udp"
	// ShadowsocksNetworkTCPUDP identifies a supported package value.
	ShadowsocksNetworkTCPUDP = "tcp,udp"
)

// ShadowsocksSettings is the node-wide classic Shadowsocks inbound setup.
// The 2022 cipher family is deliberately excluded until Xray exposes a
// reliable live per-user management API for it.
type ShadowsocksSettings struct {
	// Enabled is whether the object is enabled.
	Enabled bool
	// PublicPort is the public listener port advertised to clients.
	PublicPort int
	// Method contains the Method value for this object.
	Method string
	// Network contains the Network value for this object.
	Network string
}

// Validate validates the supplied value.
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

// SupportsShadowsocksMethod reports whether the supplied option is supported.
func SupportsShadowsocksMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case ShadowsocksMethodChaCha20Poly1305, ShadowsocksMethodAES256GCM, ShadowsocksMethodAES128GCM:
		return true
	default:
		return false
	}
}

// SupportsShadowsocksNetwork reports whether the supplied option is supported.
func SupportsShadowsocksNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case ShadowsocksNetworkTCP, ShadowsocksNetworkUDP, ShadowsocksNetworkTCPUDP:
		return true
	default:
		return false
	}
}

// String returns the string representation of the value.
func (s ShadowsocksSettings) String() string {
	return strings.Join([]string{strconv.Itoa(s.PublicPort), s.Method, s.Network}, "/")
}
