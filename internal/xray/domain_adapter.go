package xray

import "xray-easy/internal/domain"

// SettingsFromDomain translates persisted configuration into the renderer's
// transport model. Keeping this at the adapter boundary prevents handlers and
// CLI flows from duplicating field-by-field conversions.
func SettingsFromDomain(value domain.Settings, privateKey string) Settings {
	return Settings{
		PublicHost: value.PublicHost, PublicPort: value.PublicPort,
		XrayAPIListen: value.XrayAPIListen, InternalInboundPort: value.InternalInboundPort,
		RealityTarget: value.RealityTarget, RealitySNI: value.RealitySNI,
		RealityPrivateKey: privateKey, RealityPublicKey: value.RealityPublicKey,
		ClientFingerprint: value.ClientFingerprint,
	}
}

func ClientFromDomain(value domain.Client) Client {
	return Client{ID: value.ID, Name: value.Name, UUID: value.UUID, Email: value.Email, ShortID: value.ShortID,
		ClientFingerprint: value.ClientFingerprint, Enabled: value.Enabled, Revoked: value.Revoked}
}

func ClientsFromDomain(values []domain.Client) []Client {
	result := make([]Client, 0, len(values))
	for _, value := range values {
		result = append(result, ClientFromDomain(value))
	}
	return result
}
