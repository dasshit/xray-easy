package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var (
	deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	fingerprints      = map[string]struct{}{
		"chrome": {}, "firefox": {}, "safari": {}, "edge": {},
		"ios": {}, "android": {}, "random": {},
	}
)

var ErrClientRevoked = errors.New("revoked client cannot be enabled")

type ClientAction string

// ClientProtocol identifies the inbound credentials attached to a device profile.
type ClientProtocol string

const (
	ProtocolLegacyDual ClientProtocol = "legacy_dual"
	ProtocolVLESS      ClientProtocol = "vless"
	ProtocolHysteria2  ClientProtocol = "hysteria2"
)

const (
	ActionEnable  ClientAction = "enable"
	ActionDisable ClientAction = "disable"
	ActionRevoke  ClientAction = "revoke"
)

// Client is an Xray device profile and its credentials. It contains secrets
// used by the control plane, so transport responses must map it explicitly.
type Client struct {
	ID                string
	Name              string
	Protocol          ClientProtocol
	UUID              string
	Email             string
	ShortID           string
	HysteriaAuth      string
	ClientFingerprint string
	Enabled           bool
	Revoked           bool
	VLESSEnabled      bool
	VLESSRevoked      bool
	HysteriaEnabled   bool
	HysteriaRevoked   bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// HasVLESS reports whether this profile contains VLESS credentials.
func (c Client) HasVLESS() bool {
	return c.Protocol == ProtocolVLESS || c.Protocol == ProtocolLegacyDual
}

// HasHysteria2 reports whether this profile contains Hysteria 2 credentials.
func (c Client) HasHysteria2() bool {
	return c.Protocol == ProtocolHysteria2 || c.Protocol == ProtocolLegacyDual
}

// VLESSCanConnect reports whether the VLESS access for this profile is active.
func (c Client) VLESSCanConnect() bool {
	return c.HasVLESS() && c.VLESSEnabled && !c.VLESSRevoked
}

// Hysteria2CanConnect reports whether the Hysteria 2 access for this profile is active.
func (c Client) Hysteria2CanConnect() bool {
	return c.HasHysteria2() && c.HysteriaEnabled && !c.HysteriaRevoked
}

// HysteriaCredential returns the stored password or the legacy UUID fallback.
func (c Client) HysteriaCredential() string {
	if c.HysteriaAuth != "" {
		return c.HysteriaAuth
	}
	return c.UUID
}

type ClientState struct {
	Enabled bool
	Revoked bool
}

// AccessState returns the independent lifecycle state of one protocol access.
func (c Client) AccessState(protocol ClientProtocol) (ClientState, error) {
	switch protocol {
	case ProtocolVLESS:
		if !c.HasVLESS() {
			return ClientState{}, errors.New("profile has no VLESS access")
		}
		return ClientState{Enabled: c.VLESSEnabled, Revoked: c.VLESSRevoked}, nil
	case ProtocolHysteria2:
		if !c.HasHysteria2() {
			return ClientState{}, errors.New("profile has no Hysteria 2 access")
		}
		return ClientState{Enabled: c.HysteriaEnabled, Revoked: c.HysteriaRevoked}, nil
	default:
		return ClientState{}, errors.New("unsupported protocol access")
	}
}

func NewClient(id, name, fingerprint string) (Client, error) {
	name = strings.TrimSpace(name)
	fingerprint = strings.TrimSpace(fingerprint)
	if id == "" {
		return Client{}, errors.New("client id is required")
	}
	if !deviceNamePattern.MatchString(name) {
		return Client{}, errors.New("name must contain ASCII letters, digits or '-' and be 1-64 characters")
	}
	if fingerprint != "" && !SupportsFingerprint(fingerprint) {
		return Client{}, errors.New("unsupported client fingerprint")
	}
	return Client{
		ID: id, Name: name, Protocol: ProtocolLegacyDual, ClientFingerprint: fingerprint,
		Enabled: true, VLESSEnabled: true, HysteriaEnabled: true,
	}, nil
}

// NewProtocolClient creates a profile for exactly one supported protocol.
func NewProtocolClient(id, name string, protocol ClientProtocol, fingerprint, hysteriaAuth string) (Client, error) {
	name = strings.TrimSpace(name)
	if id == "" {
		return Client{}, errors.New("client id is required")
	}
	if !deviceNamePattern.MatchString(name) {
		return Client{}, errors.New("name must contain ASCII letters, digits or '-' and be 1-64 characters")
	}
	switch protocol {
	case ProtocolVLESS:
		fingerprint = strings.TrimSpace(fingerprint)
		if fingerprint != "" && !SupportsFingerprint(fingerprint) {
			return Client{}, errors.New("unsupported client fingerprint")
		}
		return Client{ID: id, Name: name, Protocol: protocol, ClientFingerprint: fingerprint, Enabled: true, VLESSEnabled: true}, nil
	case ProtocolHysteria2:
		hysteriaAuth = strings.TrimSpace(hysteriaAuth)
		if hysteriaAuth == "" || len(hysteriaAuth) > 256 || strings.IndexFunc(hysteriaAuth, unicode.IsControl) >= 0 {
			return Client{}, errors.New("Hysteria 2 auth must contain 1-256 bytes without control characters")
		}
		return Client{ID: id, Name: name, Protocol: protocol, HysteriaAuth: hysteriaAuth, Enabled: true, HysteriaEnabled: true}, nil
	default:
		return Client{}, errors.New("new profiles must use VLESS or Hysteria 2")
	}
}

func SupportsFingerprint(value string) bool {
	_, ok := fingerprints[value]
	return ok
}

func (c Client) CanConnect() bool { return c.Enabled && !c.Revoked }

func (c Client) Enable() (Client, error) {
	if c.Revoked {
		return Client{}, ErrClientRevoked
	}
	c.Enabled = true
	return c, nil
}

func (c Client) Disable() Client {
	c.Enabled = false
	return c
}

func (c Client) Revoke() Client {
	c.Enabled = false
	c.Revoked = true
	return c
}

func (c Client) Transition(action ClientAction) (Client, error) {
	switch action {
	case ActionEnable:
		return c.Enable()
	case ActionDisable:
		return c.Disable(), nil
	case ActionRevoke:
		return c.Revoke(), nil
	default:
		return Client{}, errors.New("unsupported client action")
	}
}
