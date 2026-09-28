package domain

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var realityTargetPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// Settings is the persisted configuration for one Xray node. The encrypted
// private key remains opaque to the domain; encryption and storage belong to
// infrastructure, while the public key and connection parameters are domain
// configuration.
type Settings struct {
	PublicHost           string
	PublicPort           int
	XrayAPIListen        string
	InternalInboundPort  int
	RealityTarget        string
	RealitySNI           string
	RealityPrivateKeyEnc string
	RealityPublicKey     string
	ClientFingerprint    string
}

func ValidateRealityTarget(target, sni string) error {
	target = strings.TrimSpace(target)
	sni = strings.TrimSpace(sni)
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" || !realityTargetPattern.MatchString(target) {
		return errors.New("REALITY target must be a host:port value")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("REALITY target port must be between 1 and 65535")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast()) {
		return errors.New("REALITY target cannot be a private or local address")
	}
	if sni == "" || strings.ContainsAny(sni, "/?#\t\r\n") {
		return errors.New("REALITY SNI must be a hostname")
	}
	return nil
}

// NormalizePublicHost validates and canonicalizes a DNS hostname or IP literal
// used as the public endpoint in generated device profiles.
func NormalizePublicHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("public host must be a DNS name, IPv4, or global IPv6 address")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4In6() {
			return "", errors.New("public host must use a native IPv4 or IPv6 address")
		}
		if address.Is6() && (address.Zone() != "" || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast()) {
			return "", errors.New("IPv6 public host must be a global unicast address without a zone identifier")
		}
		return address.String(), nil
	}
	if len(host) > 253 || strings.ContainsAny(host, "/?#\t\r\n :%[]") {
		return "", errors.New("public host must be a DNS name, IPv4, or global IPv6 address")
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return "", errors.New("public host must be a DNS name, IPv4, or global IPv6 address")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("public host must be a DNS name, IPv4, or global IPv6 address")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
				return "", errors.New("public host must be a DNS name, IPv4, or global IPv6 address")
			}
		}
	}
	return host, nil
}

// ValidatePublicHost accepts a DNS hostname, IPv4 address, or global IPv6
// address for a public device-profile endpoint.
func ValidatePublicHost(host string) error {
	_, err := NormalizePublicHost(host)
	return err
}

func (s Settings) ValidateConnection() error {
	if err := ValidatePublicHost(s.PublicHost); err != nil {
		return err
	}
	if s.PublicPort < 1 || s.PublicPort > 65535 {
		return errors.New("public port must be between 1 and 65535")
	}
	if err := ValidateRealityTarget(s.RealityTarget, s.RealitySNI); err != nil {
		return err
	}
	if !SupportsFingerprint(s.ClientFingerprint) {
		return errors.New("unsupported client fingerprint")
	}
	return nil
}
