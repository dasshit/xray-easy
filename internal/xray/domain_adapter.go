// Package xray adapts domain profiles and settings to Xray configuration and connection artifacts.
package xray

import (
	"encoding/hex"
	"path/filepath"
	"strings"

	"xray-easy/internal/domain"
)

// SettingsFromDomain translates persisted configuration into the renderer's
// transport model. Keeping this at the adapter boundary prevents handlers and
// CLI flows from duplicating field-by-field conversions.
func SettingsFromDomain(value domain.Settings, privateKey string) Settings {
	return Settings{
		PublicHost: value.PublicHost, PublicPort: value.PublicPort,
		XrayAPIListen: value.XrayAPIListen, InternalInboundPort: value.InternalInboundPort,
		RealityTarget: value.RealityTarget, RealitySNI: value.RealitySNI,
		RealityPrivateKey: privateKey, RealityPublicKey: value.RealityPublicKey,
		ClientFingerprint: value.ClientFingerprint, LogLevel: value.LogLevel,
	}
}

// ApplyHysteriaSettings translates persisted node-level Hysteria settings into
// renderer fields without mixing them into the VLESS node settings model.
func ApplyHysteriaSettings(settings *Settings, value domain.HysteriaSettings) {
	settings.Hysteria2Enabled = value.Enabled
	settings.HysteriaTLSMode = value.TLSMode
	settings.HysteriaTLSCertIP = value.TLSCertIP
	settings.HysteriaTLSServerName = value.TLSServerName
	settings.HysteriaHost = value.Host
	settings.HysteriaUDPIdleTimeout = value.UDPIdleTimeout
	settings.HysteriaMasqueradeType = value.MasqueradeType
	settings.HysteriaMasqueradeString = value.MasqueradeString
	if !validCertificateID(value.CertificateID) {
		settings.HysteriaTLSCertPath, settings.HysteriaTLSKeyPath = HysteriaTLSCertPath, HysteriaTLSKeyPath
		return
	}
	certificateDir := filepath.Join("/etc/xray/hysteria-tls", filepath.Clean(value.CertificateID))
	settings.HysteriaTLSCertPath = filepath.Join(certificateDir, "fullchain.pem")
	settings.HysteriaTLSKeyPath = filepath.Join(certificateDir, "privkey.pem")
}

// ApplyShadowsocksSettings translates node-level Shadowsocks configuration
// into renderer fields without coupling persistence to Xray JSON types.
func ApplyShadowsocksSettings(settings *Settings, value domain.ShadowsocksSettings) {
	settings.ShadowsocksEnabled = value.Enabled
	settings.ShadowsocksPublicPort = value.PublicPort
	settings.ShadowsocksMethod = value.Method
	settings.ShadowsocksNetwork = value.Network
}

// validCertificateID performs the operation represented by its name.
func validCertificateID(value string) bool {
	if len(value) != 32 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ClientFromDomain performs the operation represented by its name.
func ClientFromDomain(value domain.Client) Client {
	return Client{
		ID: value.ID, Name: value.Name, Protocol: value.Protocol, UUID: value.UUID, Email: value.Email,
		ShortID: value.ShortID, HysteriaAuth: value.HysteriaAuth, ClientFingerprint: value.ClientFingerprint,
		Enabled: value.Enabled, Revoked: value.Revoked,
		VLESSEnabled: value.VLESSEnabled, VLESSRevoked: value.VLESSRevoked,
		HysteriaEnabled: value.HysteriaEnabled, HysteriaRevoked: value.HysteriaRevoked,
		VMessEnabled: value.VMessEnabled, VMessRevoked: value.VMessRevoked,
		ShadowsocksEnabled: value.ShadowsocksEnabled, ShadowsocksRevoked: value.ShadowsocksRevoked,
		TrojanEnabled: value.TrojanEnabled, TrojanRevoked: value.TrojanRevoked,
		ExpiresAt: value.ExpiresAt,
	}
}

// ClientsFromDomain performs the operation represented by its name.
func ClientsFromDomain(values []domain.Client) []Client {
	result := make([]Client, 0, len(values))
	for _, value := range values {
		result = append(result, ClientFromDomain(value))
	}
	return result
}
