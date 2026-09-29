package domain

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

var hysteriaCertificateIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

const (
	HysteriaTLSCustom      = "custom"
	HysteriaTLSSelfSigned  = "self-signed"
	HysteriaTLSLegacy      = "legacy"
	HysteriaMasqueradeOff  = "off"
	HysteriaMasqueradeText = "string"
)

// HysteriaSettings is the persisted, node-wide Hysteria 2 inbound setup.
// Certificate bytes are held in a dedicated volume, not in SQLite.
type HysteriaSettings struct {
	Enabled          bool
	Host             string
	TLSMode          string
	TLSCertIP        string
	TLSServerName    string
	CertificateID    string
	UDPIdleTimeout   int
	MasqueradeType   string
	MasqueradeString string
}

// Validate checks settings that affect the shared Hysteria 2 inbound.
func (s HysteriaSettings) Validate() error {
	if s.TLSMode != HysteriaTLSCustom && s.TLSMode != HysteriaTLSSelfSigned && s.TLSMode != HysteriaTLSLegacy {
		return errors.New("Hysteria 2 TLS mode must be custom, self-signed, or legacy")
	}
	if s.TLSMode == HysteriaTLSSelfSigned {
		ip, err := netip.ParseAddr(s.TLSCertIP)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("self-signed Hysteria 2 TLS requires a public IPv4 certificate address")
		}
		if s.TLSServerName != "" && s.TLSServerName != ip.String() {
			return errors.New("self-signed Hysteria 2 TLS server name must match its IPv4 certificate address")
		}
	}
	if s.TLSServerName != "" {
		if _, err := NormalizePublicHost(s.TLSServerName); err != nil {
			return errors.New("Hysteria 2 TLS server name must be a DNS name or public IP")
		}
	}
	if s.Host != "" {
		if _, err := NormalizePublicHost(s.Host); err != nil {
			return errors.New("Hysteria 2 host must be a DNS name or public IP")
		}
	}
	if s.UDPIdleTimeout < 10 || s.UDPIdleTimeout > 600 {
		return errors.New("Hysteria 2 UDP idle timeout must be between 10 and 600 seconds")
	}
	if s.MasqueradeType != HysteriaMasqueradeOff && s.MasqueradeType != HysteriaMasqueradeText {
		return errors.New("Hysteria 2 masquerade must be off or a static text response")
	}
	if s.MasqueradeType == HysteriaMasqueradeText && strings.TrimSpace(s.MasqueradeString) == "" {
		return errors.New("Hysteria 2 static response must not be empty")
	}
	if len(s.MasqueradeString) > 4096 {
		return errors.New("Hysteria 2 static response must be at most 4096 bytes")
	}
	if s.CertificateID != "" && !hysteriaCertificateIDPattern.MatchString(s.CertificateID) {
		return errors.New("invalid Hysteria 2 certificate version")
	}
	return nil
}
