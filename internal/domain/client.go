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

// ErrClientRevoked indicates that a revoked profile cannot be enabled again.
var ErrClientRevoked = errors.New("revoked client cannot be enabled")

// ClientAction identifies a lifecycle transition for a device profile.
type ClientAction string

// ClientProtocol identifies the inbound credentials attached to a device profile.
type ClientProtocol string

const (
	// ProtocolLegacyDual identifies a legacy profile that contains VLESS and Hysteria 2 access.
	ProtocolLegacyDual ClientProtocol = "legacy_dual"
	// ProtocolVLESS identifies a VLESS + REALITY profile.
	ProtocolVLESS ClientProtocol = "vless"
	// ProtocolHysteria2 identifies a Hysteria 2 profile.
	ProtocolHysteria2 ClientProtocol = "hysteria2"
	// ProtocolVMess identifies a VMess + TLS profile.
	ProtocolVMess ClientProtocol = "vmess"
	// ProtocolShadowsocks identifies a Shadowsocks profile.
	ProtocolShadowsocks ClientProtocol = "shadowsocks"
	// ProtocolTrojan identifies a Trojan + TLS profile.
	ProtocolTrojan ClientProtocol = "trojan"
	// ProtocolAmneziaWG identifies an AmneziaWG profile.
	ProtocolAmneziaWG ClientProtocol = "amneziawg"
)

const (
	// ActionEnable enables a profile or protocol access.
	ActionEnable ClientAction = "enable"
	// ActionDisable disables a profile or protocol access.
	ActionDisable ClientAction = "disable"
	// ActionRevoke permanently revokes a profile or protocol access.
	ActionRevoke ClientAction = "revoke"
)

// Client is an Xray device profile and its credentials. It contains secrets
// used by the control plane, so transport responses must map it explicitly.
type Client struct {
	// ID is the unique identifier for the object.
	ID string
	// Name is the human-readable name of the object.
	Name string
	// Protocol is the protocol associated with the object.
	Protocol ClientProtocol
	// UUID is the UUID credential assigned to the profile.
	UUID string
	// Email is the Xray statistics identity for the profile.
	Email string
	// ShortID is the REALITY short identifier assigned to the profile.
	ShortID string
	// HysteriaAuth is the Hysteria 2 authentication credential.
	HysteriaAuth string
	// ClientFingerprint is the TLS client fingerprint used in generated profiles.
	ClientFingerprint string
	// Enabled is whether the object is enabled.
	Enabled bool
	// Revoked is whether access to the object has been revoked.
	Revoked bool
	// VLESSEnabled is whether VLESS access is enabled.
	VLESSEnabled bool
	// VLESSRevoked is whether VLESS access is revoked.
	VLESSRevoked bool
	// HysteriaEnabled is whether Hysteria 2 access is enabled.
	HysteriaEnabled bool
	// HysteriaRevoked is whether Hysteria 2 access is revoked.
	HysteriaRevoked bool
	// VMessEnabled is whether VMess access is enabled.
	VMessEnabled bool
	// VMessRevoked is whether VMess access is revoked.
	VMessRevoked bool
	// ShadowsocksPasswordEnc is the encrypted Shadowsocks password credential.
	ShadowsocksPasswordEnc string
	// ShadowsocksEnabled is whether Shadowsocks access is enabled.
	ShadowsocksEnabled bool
	// ShadowsocksRevoked is whether Shadowsocks access is revoked.
	ShadowsocksRevoked bool
	// TrojanPasswordEnc is the encrypted Trojan password credential.
	TrojanPasswordEnc string
	// TrojanEnabled is whether Trojan access is enabled.
	TrojanEnabled bool
	// TrojanRevoked is whether Trojan access is revoked.
	TrojanRevoked bool
	// CreatedAt is the time the object was created.
	CreatedAt time.Time
	// UpdatedAt is the time the object was last updated.
	UpdatedAt time.Time
}

// HasVLESS reports whether this profile contains VLESS credentials.
func (c Client) HasVLESS() bool {
	return c.Protocol == ProtocolVLESS || c.Protocol == ProtocolLegacyDual
}

// HasHysteria2 reports whether this profile contains Hysteria 2 credentials.
func (c Client) HasHysteria2() bool {
	return c.Protocol == ProtocolHysteria2 || c.Protocol == ProtocolLegacyDual
}

// HasVMess reports whether this profile has VMess credentials.
func (c Client) HasVMess() bool { return c.Protocol == ProtocolVMess }

// HasShadowsocks reports whether this profile contains Shadowsocks credentials.
func (c Client) HasShadowsocks() bool { return c.Protocol == ProtocolShadowsocks }

// HasTrojan reports whether this profile contains Trojan credentials.
func (c Client) HasTrojan() bool { return c.Protocol == ProtocolTrojan }

// VLESSCanConnect reports whether the VLESS access for this profile is active.
func (c Client) VLESSCanConnect() bool {
	return c.HasVLESS() && c.VLESSEnabled && !c.VLESSRevoked
}

// Hysteria2CanConnect reports whether the Hysteria 2 access for this profile is active.
func (c Client) Hysteria2CanConnect() bool {
	return c.HasHysteria2() && c.HysteriaEnabled && !c.HysteriaRevoked
}

// VMessCanConnect reports whether the VMess access for this profile is active.
func (c Client) VMessCanConnect() bool { return c.HasVMess() && c.Enabled && !c.Revoked }

// ShadowsocksCanConnect reports whether the Shadowsocks access is active.
func (c Client) ShadowsocksCanConnect() bool {
	return c.HasShadowsocks() && c.ShadowsocksEnabled && !c.ShadowsocksRevoked
}

// TrojanCanConnect reports whether the Trojan access is active.
func (c Client) TrojanCanConnect() bool { return c.HasTrojan() && c.TrojanEnabled && !c.TrojanRevoked }

// HysteriaCredential returns the stored password or the legacy UUID fallback.
func (c Client) HysteriaCredential() string {
	if c.HysteriaAuth != "" {
		return c.HysteriaAuth
	}
	return c.UUID
}

// ClientState contains the enabled and revoked flags for one protocol access.
type ClientState struct {
	// Enabled is whether the object is enabled.
	Enabled bool
	// Revoked is whether access to the object has been revoked.
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
	case ProtocolVMess:
		if !c.HasVMess() {
			return ClientState{}, errors.New("profile has no VMess access")
		}
		return ClientState{Enabled: c.Enabled, Revoked: c.Revoked}, nil
	case ProtocolShadowsocks:
		if !c.HasShadowsocks() {
			return ClientState{}, errors.New("profile has no Shadowsocks access")
		}
		return ClientState{Enabled: c.ShadowsocksEnabled, Revoked: c.ShadowsocksRevoked}, nil
	case ProtocolTrojan:
		if !c.HasTrojan() {
			return ClientState{}, errors.New("profile has no Trojan access")
		}
		return ClientState{Enabled: c.TrojanEnabled, Revoked: c.TrojanRevoked}, nil
	default:
		return ClientState{}, errors.New("unsupported protocol access")
	}
}

// NewShadowsocksClient creates a profile for the classic Shadowsocks inbound.
// The encrypted password is generated and persisted by the application layer.
func NewShadowsocksClient(id, name string) (Client, error) {
	name = strings.TrimSpace(name)
	if id == "" {
		return Client{}, errors.New("client id is required")
	}
	if !deviceNamePattern.MatchString(name) {
		return Client{}, errors.New("name must contain ASCII letters, digits or '-' and be 1-64 characters")
	}
	return Client{ID: id, Name: name, Protocol: ProtocolShadowsocks, Enabled: true, ShadowsocksEnabled: true}, nil
}

// NewClient constructs and returns the requested value.
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
	case ProtocolVMess:
		return Client{ID: id, Name: name, Protocol: protocol, Enabled: true, VMessEnabled: true}, nil
	case ProtocolShadowsocks:
		return Client{ID: id, Name: name, Protocol: protocol, Enabled: true, ShadowsocksEnabled: true}, nil
	case ProtocolTrojan:
		return Client{ID: id, Name: name, Protocol: protocol, Enabled: true, TrojanEnabled: true}, nil
	default:
		return Client{}, errors.New("new profiles must use VLESS, VMess, Hysteria 2, Shadowsocks, or Trojan")
	}
}

// SupportsFingerprint reports whether the supplied option is supported.
func SupportsFingerprint(value string) bool {
	_, ok := fingerprints[value]
	return ok
}

// CanConnect reports whether the requested operation is allowed.
func (c Client) CanConnect() bool { return c.Enabled && !c.Revoked }

// Enable performs the operation represented by its name.
func (c Client) Enable() (Client, error) {
	if c.Revoked {
		return Client{}, ErrClientRevoked
	}
	c.Enabled = true
	return c, nil
}

// Disable performs the operation represented by its name.
func (c Client) Disable() Client {
	c.Enabled = false
	return c
}

// Revoke performs the operation represented by its name.
func (c Client) Revoke() Client {
	c.Enabled = false
	c.Revoked = true
	return c
}

// Transition transitions the value to the requested state.
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
