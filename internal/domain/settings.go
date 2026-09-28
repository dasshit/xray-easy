package domain

import (
	"errors"
	"net"
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

// ValidatePublicHost accepts a DNS hostname or IPv4 address for MVP profile
// endpoints. IPv6 remains a deployment-level future feature.
func ValidatePublicHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/?#\t\r\n :") {
		return errors.New("public host must be a DNS name or IPv4 address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return errors.New("public host must be a DNS name or IPv4 address")
		}
		return nil
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return errors.New("public host must be a DNS name or IPv4 address")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("public host must be a DNS name or IPv4 address")
		}
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
				return errors.New("public host must be a DNS name or IPv4 address")
			}
		}
	}
	return nil
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
