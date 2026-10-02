package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"xray-easy/internal/domain"
)

const (
	// Protocol is the VLESS protocol name used in rendered Xray settings.
	Protocol = "vless"
	// Network is the TCP transport used by the VLESS inbound.
	Network = "tcp"
	// Security is the REALITY transport security name.
	Security = "reality"
	// Flow is the XTLS Vision flow used by VLESS clients.
	Flow = "xtls-rprx-vision"
	// Xray 26.7.11 and newer apply an implicit minClientVer of 26.3.27
	// when the field is omitted. Third-party clients such as V2RAGE may
	// report an older REALITY client version, so keep the compatibility
	// floor explicit until clients can be verified against the newer gate.
	realityMinClientVersion = "1.0.0"
	// Xray requires at least one REALITY short ID even when there are no
	// enabled clients. This reserved value has no matching UUID and therefore
	// cannot authenticate a device.
	emptyShortID = "0000000000000000"
	// ReservedShortIDCount is the number of short IDs kept for live user additions.
	ReservedShortIDCount = 5
	// VerifiedCoreVersion is the Xray version validated by the runtime compatibility checks.
	VerifiedCoreVersion = "26.7.28"
	// HysteriaInboundTag is the stable Xray tag for the Hysteria 2 inbound.
	HysteriaInboundTag = "hysteria2"
	// VMessInboundTag is the stable Xray tag for the VMess inbound.
	VMessInboundTag = "vmess-tls"
	// ShadowsocksInboundTag is the stable Xray tag for the Shadowsocks inbound.
	ShadowsocksInboundTag = "shadowsocks"
	// TrojanInboundTag is the stable Xray tag for the Trojan inbound.
	TrojanInboundTag = "trojan-tls"
	// VMessInternalPort is the VMess listener port inside the Xray container.
	VMessInternalPort = 8444
	// ShadowsocksInternalPort is the Shadowsocks listener port inside the Xray container.
	ShadowsocksInternalPort = 8388
	// TrojanInternalPort is the Trojan listener port inside the Xray container.
	TrojanInternalPort = 8445
	// HysteriaTLSCertPath is the mounted Hysteria 2 certificate path.
	HysteriaTLSCertPath = "/etc/xray/hysteria-tls/fullchain.pem"
	// HysteriaTLSKeyPath is the mounted Hysteria 2 private key path.
	HysteriaTLSKeyPath = "/etc/xray/hysteria-tls/privkey.pem"
	// HysteriaTLSSelfSigned selects the generated self-signed Hysteria 2 certificate.
	HysteriaTLSSelfSigned = "self-signed"
	// HysteriaTLSCustom selects a user-provided Hysteria 2 certificate.
	HysteriaTLSCustom = "custom"
	// HysteriaTLSLegacy selects the legacy certificate compatibility mode.
	HysteriaTLSLegacy = "legacy"
)

// Settings contains the values needed to render the active Xray configuration and client profiles.
type Settings struct {
	// PublicHost is the public DNS name or IP address advertised to clients.
	PublicHost string
	// PublicPort is the public listener port advertised to clients.
	PublicPort int
	// XrayAPIListen is the private Xray API listen address.
	XrayAPIListen string
	// RealityTarget is the REALITY target host and port.
	RealityTarget string
	// RealitySNI is the REALITY server name indication.
	RealitySNI string
	// RealityPrivateKey is the X25519 REALITY private key.
	RealityPrivateKey string
	// RealityPublicKey is the X25519 REALITY public key.
	RealityPublicKey string
	// ClientFingerprint is the TLS client fingerprint used in generated profiles.
	ClientFingerprint string
	// LogLevel is the active Xray log level.
	LogLevel string
	// InternalInboundPort is the internal VLESS inbound port.
	InternalInboundPort int
	// ReservedShortIDs is the pool of reserved REALITY short identifiers.
	ReservedShortIDs []string
	// Hysteria2Enabled is whether the Hysteria 2 inbound is enabled.
	Hysteria2Enabled bool
	// HysteriaTLSMode is the Hysteria 2 TLS certificate mode.
	HysteriaTLSMode string
	// HysteriaTLSCertIP is the IPv4 address included in a self-signed certificate.
	HysteriaTLSCertIP string
	// HysteriaTLSServerName is the TLS server name used by Hysteria 2.
	HysteriaTLSServerName string
	// HysteriaTLSFingerprint is the Hysteria 2 TLS fingerprint.
	HysteriaTLSFingerprint string
	// HysteriaHost is the Hysteria 2 host used for generated profiles.
	HysteriaHost string
	// HysteriaTLSCertPath is the path to the Hysteria 2 certificate.
	HysteriaTLSCertPath string
	// HysteriaTLSKeyPath is the path to the Hysteria 2 private key.
	HysteriaTLSKeyPath string
	// HysteriaUDPIdleTimeout is the Hysteria 2 UDP idle timeout in seconds.
	HysteriaUDPIdleTimeout int
	// HysteriaMasqueradeType is the Hysteria 2 masquerade mode.
	HysteriaMasqueradeType string
	// HysteriaMasqueradeString is the static Hysteria 2 masquerade response.
	HysteriaMasqueradeString string
	// VMessPublicPort is the public VMess listener port.
	VMessPublicPort int
	// ShadowsocksEnabled is whether Shadowsocks access is enabled.
	ShadowsocksEnabled bool
	// ShadowsocksPublicPort is the public Shadowsocks listener port.
	ShadowsocksPublicPort int
	// ShadowsocksMethod is the Shadowsocks cipher method.
	ShadowsocksMethod string
	// ShadowsocksNetwork is the Shadowsocks transport network.
	ShadowsocksNetwork string
	// TrojanEnabled is whether Trojan access is enabled.
	TrojanEnabled bool
	// TrojanPublicPort is the public Trojan listener port.
	TrojanPublicPort int
}

// Client contains the credentials and protocol state needed to render one client profile.
type Client struct {
	// ID is the unique identifier for the object.
	ID string
	// Name is the human-readable name of the object.
	Name string
	// Protocol is the protocol associated with the object.
	Protocol domain.ClientProtocol
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
	// ShadowsocksPassword is the Shadowsocks password credential.
	ShadowsocksPassword string
	// ShadowsocksEnabled is whether Shadowsocks access is enabled.
	ShadowsocksEnabled bool
	// ShadowsocksRevoked is whether Shadowsocks access is revoked.
	ShadowsocksRevoked bool
	// TrojanPassword is the Trojan password credential.
	TrojanPassword string
	// TrojanEnabled is whether Trojan access is enabled.
	TrojanEnabled bool
	// TrojanRevoked is whether Trojan access is revoked.
	TrojanRevoked bool
}

// Profile contains the generated connection artifacts shown or downloaded for a client.
type Profile struct {
	// Protocol is the protocol associated with the object.
	Protocol domain.ClientProtocol
	// URI is the generated connection URI.
	URI string
	// HysteriaURI is the generated Hysteria 2 connection URI.
	HysteriaURI string
	// VMessURI is the generated VMess connection URI.
	VMessURI string
	// ShadowsocksURI is the generated Shadowsocks connection URI.
	ShadowsocksURI string
	// ShadowsocksJSON is the generated Shadowsocks client JSON.
	ShadowsocksJSON []byte
	// TrojanURI is the generated Trojan connection URI.
	TrojanURI string
	// TrojanJSON is the generated Trojan client JSON.
	TrojanJSON []byte
	// JSON is the generated client JSON document.
	JSON []byte
	// Name is the human-readable name of the object.
	Name string
	// UUID is the UUID credential assigned to the profile.
	UUID string
	// ShortID is the REALITY short identifier assigned to the profile.
	ShortID string
}

// serverConfig is an internal type used by the package.
type serverConfig struct {
	// Log stores the value associated with the enclosing object.
	Log logConfig `json:"log"`
	// API stores the value associated with the enclosing object.
	API apiConfig `json:"api"`
	// Stats stores the value associated with the enclosing object.
	Stats map[string]any `json:"stats"`
	// Policy stores the value associated with the enclosing object.
	Policy policyConfig `json:"policy"`
	// Inbounds stores the value associated with the enclosing object.
	Inbounds []any `json:"inbounds"`
	// Outbounds stores the value associated with the enclosing object.
	Outbounds []outbound `json:"outbounds"`
}

// logConfig is an internal type used by the package.
type logConfig struct {
	// LogLevel stores the value associated with the enclosing object.
	LogLevel string `json:"loglevel"`
}

// apiConfig is an internal type used by the package.
type apiConfig struct {
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Services stores the value associated with the enclosing object.
	Services []string `json:"services"`
}

// policyConfig is an internal type used by the package.
type policyConfig struct {
	// Levels stores the value associated with the enclosing object.
	Levels map[string]policyLevel `json:"levels"`
}

// policyLevel is an internal type used by the package.
type policyLevel struct {
	// StatsUserUplink stores the value associated with the enclosing object.
	StatsUserUplink bool `json:"statsUserUplink"`
	// StatsUserDownlink stores the value associated with the enclosing object.
	StatsUserDownlink bool `json:"statsUserDownlink"`
	// StatsUserOnline stores the value associated with the enclosing object.
	StatsUserOnline bool `json:"statsUserOnline"`
}

// inbound is an internal type used by the package.
type inbound struct {
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Port stores the value associated with the enclosing object.
	Port int `json:"port"`
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Settings stores the value associated with the enclosing object.
	Settings inboundSettings `json:"settings"`
	// StreamSettings stores the value associated with the enclosing object.
	StreamSettings streamSettings `json:"streamSettings"`
	// Sniffing stores the value associated with the enclosing object.
	Sniffing sniffing `json:"sniffing"`
}

// inboundSettings is an internal type used by the package.
type inboundSettings struct {
	// Clients stores the value associated with the enclosing object.
	Clients []serverClient `json:"clients"`
	// Decryption stores the value associated with the enclosing object.
	Decryption string `json:"decryption"`
}

// serverClient is an internal type used by the package.
type serverClient struct {
	// ID stores the value associated with the enclosing object.
	ID string `json:"id"`
	// Flow stores the value associated with the enclosing object.
	Flow string `json:"flow,omitempty"`
	// Email stores the value associated with the enclosing object.
	Email string `json:"email"`
}

// streamSettings is an internal type used by the package.
type streamSettings struct {
	// Network stores the value associated with the enclosing object.
	Network string `json:"network"`
	// Security stores the value associated with the enclosing object.
	Security string `json:"security"`
	// RealitySettings stores the value associated with the enclosing object.
	RealitySettings realityServer `json:"realitySettings"`
}

// realityServer is an internal type used by the package.
type realityServer struct {
	// Show stores the value associated with the enclosing object.
	Show bool `json:"show"`
	// Target stores the value associated with the enclosing object.
	Target string `json:"target"`
	// XVer stores the value associated with the enclosing object.
	XVer int `json:"xver"`
	// ServerNames stores the value associated with the enclosing object.
	ServerNames []string `json:"serverNames"`
	// PrivateKey stores the value associated with the enclosing object.
	PrivateKey string `json:"privateKey"`
	// MinClientVer stores the value associated with the enclosing object.
	MinClientVer string `json:"minClientVer"`
	// ShortIDs stores the value associated with the enclosing object.
	ShortIDs []string `json:"shortIds"`
}

// sniffing is an internal type used by the package.
type sniffing struct {
	// Enabled stores the value associated with the enclosing object.
	Enabled bool `json:"enabled"`
	// DestOverride stores the value associated with the enclosing object.
	DestOverride []string `json:"destOverride"`
}

// outbound is an internal type used by the package.
type outbound struct {
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
}

// hysteriaInbound is an internal type used by the package.
type hysteriaInbound struct {
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Port stores the value associated with the enclosing object.
	Port int `json:"port"`
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Settings stores the value associated with the enclosing object.
	Settings hysteriaInboundSettings `json:"settings"`
	// StreamSettings stores the value associated with the enclosing object.
	StreamSettings hysteriaStreamSettings `json:"streamSettings"`
}

// hysteriaInboundSettings is an internal type used by the package.
type hysteriaInboundSettings struct {
	// Version stores the value associated with the enclosing object.
	Version int `json:"version"`
	// Users stores the value associated with the enclosing object.
	Users []hysteriaUser `json:"users"`
}

// hysteriaUser is an internal type used by the package.
type hysteriaUser struct {
	// Auth stores the value associated with the enclosing object.
	Auth string `json:"auth"`
	// Level stores the value associated with the enclosing object.
	Level int `json:"level"`
	// Email stores the value associated with the enclosing object.
	Email string `json:"email"`
}

// hysteriaStreamSettings is an internal type used by the package.
type hysteriaStreamSettings struct {
	// Network stores the value associated with the enclosing object.
	Network string `json:"network"`
	// Security stores the value associated with the enclosing object.
	Security string `json:"security"`
	// TLSSettings stores the value associated with the enclosing object.
	TLSSettings hysteriaTLSSettings `json:"tlsSettings"`
	// HysteriaSettings stores the value associated with the enclosing object.
	HysteriaSettings hysteriaTransportSettings `json:"hysteriaSettings"`
}

// hysteriaTLSSettings is an internal type used by the package.
type hysteriaTLSSettings struct {
	// Certificates stores the value associated with the enclosing object.
	Certificates []hysteriaCertificate `json:"certificates"`
}

// hysteriaCertificate is an internal type used by the package.
type hysteriaCertificate struct {
	// CertificateFile stores the value associated with the enclosing object.
	CertificateFile string `json:"certificateFile"`
	// KeyFile stores the value associated with the enclosing object.
	KeyFile string `json:"keyFile"`
}

// hysteriaTransportSettings is an internal type used by the package.
type hysteriaTransportSettings struct {
	// Version stores the value associated with the enclosing object.
	Version int `json:"version"`
	// UDPIdleTimeout stores the value associated with the enclosing object.
	UDPIdleTimeout int `json:"udpIdleTimeout,omitempty"`
	// Masquerade stores the value associated with the enclosing object.
	Masquerade *hysteriaMasquerade `json:"masquerade,omitempty"`
}

// hysteriaMasquerade is an internal type used by the package.
type hysteriaMasquerade struct {
	// Type stores the value associated with the enclosing object.
	Type string `json:"type"`
	// Content stores the value associated with the enclosing object.
	Content string `json:"content,omitempty"`
	// StatusCode stores the value associated with the enclosing object.
	StatusCode int `json:"statusCode,omitempty"`
}

// vmessInbound is an internal type used by the package.
type vmessInbound struct {
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Port stores the value associated with the enclosing object.
	Port int `json:"port"`
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Settings stores the value associated with the enclosing object.
	Settings vmessInboundSettings `json:"settings"`
	// StreamSettings stores the value associated with the enclosing object.
	StreamSettings vmessStreamSettings `json:"streamSettings"`
}

// vmessInboundSettings is an internal type used by the package.
type vmessInboundSettings struct {
	// Clients stores the value associated with the enclosing object.
	Clients []vmessServerClient `json:"clients"`
}

// vmessServerClient is an internal type used by the package.
type vmessServerClient struct {
	// ID stores the value associated with the enclosing object.
	ID string `json:"id"`
	// AlterID stores the value associated with the enclosing object.
	AlterID int `json:"alterId"`
	// Email stores the value associated with the enclosing object.
	Email string `json:"email"`
}

// vmessStreamSettings is an internal type used by the package.
type vmessStreamSettings struct {
	// Network stores the value associated with the enclosing object.
	Network string `json:"network"`
	// Security stores the value associated with the enclosing object.
	Security string `json:"security"`
	// TLSSettings stores the value associated with the enclosing object.
	TLSSettings hysteriaTLSSettings `json:"tlsSettings"`
}

// shadowsocksInbound is an internal type used by the package.
type shadowsocksInbound struct {
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Port stores the value associated with the enclosing object.
	Port int `json:"port"`
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Settings stores the value associated with the enclosing object.
	Settings shadowsocksInboundSettings `json:"settings"`
}

// shadowsocksInboundSettings is an internal type used by the package.
type shadowsocksInboundSettings struct {
	// Network stores the value associated with the enclosing object.
	Network string `json:"network"`
	// Clients stores the value associated with the enclosing object.
	Clients []shadowsocksServerClient `json:"clients"`
}

// shadowsocksServerClient is an internal type used by the package.
type shadowsocksServerClient struct {
	// Method stores the value associated with the enclosing object.
	Method string `json:"method"`
	// Password stores the value associated with the enclosing object.
	Password string `json:"password"`
	// Email stores the value associated with the enclosing object.
	Email string `json:"email"`
}

// trojanInbound is an internal type used by the package.
type trojanInbound struct {
	// Listen stores the value associated with the enclosing object.
	Listen string `json:"listen"`
	// Port stores the value associated with the enclosing object.
	Port int `json:"port"`
	// Protocol stores the value associated with the enclosing object.
	Protocol string `json:"protocol"`
	// Tag stores the value associated with the enclosing object.
	Tag string `json:"tag"`
	// Settings stores the value associated with the enclosing object.
	Settings trojanInboundSettings `json:"settings"`
	// StreamSettings stores the value associated with the enclosing object.
	StreamSettings vmessStreamSettings `json:"streamSettings"`
}

// trojanInboundSettings is an internal type used by the package.
type trojanInboundSettings struct {
	// Clients stores the value associated with the enclosing object.
	Clients []trojanServerClient `json:"clients"`
}

// trojanServerClient is an internal type used by the package.
type trojanServerClient struct {
	// Password stores the value associated with the enclosing object.
	Password string `json:"password"`
	// Email stores the value associated with the enclosing object.
	Email string `json:"email"`
}

// RenderServerConfig renders the requested representation.
func RenderServerConfig(settings Settings, clients []Client) ([]byte, error) {
	if settings.LogLevel == "" {
		settings.LogLevel = "warning"
	}
	if err := validateSettings(settings); err != nil {
		return nil, err
	}
	activeVLESS := make([]Client, 0, len(clients))
	activeHysteria := make([]Client, 0, len(clients))
	activeVMess := make([]Client, 0, len(clients))
	activeShadowsocks := make([]Client, 0, len(clients))
	activeTrojan := make([]Client, 0, len(clients))
	hasVMessProfile := false
	for _, client := range clients {
		if client.VLESSCanConnect() {
			activeVLESS = append(activeVLESS, client)
		}
		if client.Hysteria2CanConnect() {
			activeHysteria = append(activeHysteria, client)
		}
		if client.HasVMess() && !client.VMessIsRevoked() {
			hasVMessProfile = true
			if client.VMessCanConnect() {
				activeVMess = append(activeVMess, client)
			}
		}
		if client.HasShadowsocks() && !client.ShadowsocksIsRevoked() && client.ShadowsocksCanConnect() {
			activeShadowsocks = append(activeShadowsocks, client)
		}
		if client.HasTrojan() && !client.TrojanIsRevoked() && client.TrojanCanConnect() {
			activeTrojan = append(activeTrojan, client)
		}
	}
	sort.Slice(activeVLESS, func(i, j int) bool { return activeVLESS[i].ID < activeVLESS[j].ID })
	sort.Slice(activeHysteria, func(i, j int) bool { return activeHysteria[i].ID < activeHysteria[j].ID })
	sort.Slice(activeVMess, func(i, j int) bool { return activeVMess[i].ID < activeVMess[j].ID })
	sort.Slice(activeShadowsocks, func(i, j int) bool { return activeShadowsocks[i].ID < activeShadowsocks[j].ID })
	sort.Slice(activeTrojan, func(i, j int) bool { return activeTrojan[i].ID < activeTrojan[j].ID })
	serverClients := make([]serverClient, 0, len(activeVLESS))
	shortIDs := make([]string, 0, len(clients)+len(settings.ReservedShortIDs))
	shortIDSet := make(map[string]struct{}, cap(shortIDs))
	for _, client := range activeVLESS {
		if client.UUID == "" || client.ShortID == "" || client.Email == "" {
			return nil, fmt.Errorf("client %s is missing generated fields", client.ID)
		}
		serverClients = append(serverClients, serverClient{ID: client.UUID, Flow: Flow, Email: client.Email})
	}
	// Keep IDs for disabled profiles in REALITY so they can be enabled with
	for _, client := range clients {
		if !client.HasVLESS() || client.VLESSIsRevoked() || client.ShortID == "" {
			continue
		}
		if _, exists := shortIDSet[client.ShortID]; !exists {
			shortIDSet[client.ShortID] = struct{}{}
			shortIDs = append(shortIDs, client.ShortID)
		}
	}
	for _, shortID := range settings.ReservedShortIDs {
		if shortID == "" || shortID == emptyShortID {
			return nil, errors.New("reserved REALITY short ID is invalid")
		}
		if _, exists := shortIDSet[shortID]; exists {
			return nil, errors.New("REALITY short IDs must be unique")
		}
		shortIDSet[shortID] = struct{}{}
		shortIDs = append(shortIDs, shortID)
	}
	if len(shortIDs) == 0 {
		shortIDs = []string{emptyShortID}
	}
	sort.Strings(shortIDs)
	inbounds := []any{inbound{
		Listen: "0.0.0.0", Port: settings.InternalInboundPort, Protocol: Protocol, Tag: "vless-reality",
		Settings:       inboundSettings{Clients: serverClients, Decryption: "none"},
		StreamSettings: streamSettings{Network: Network, Security: Security, RealitySettings: realityServer{Show: false, Target: settings.RealityTarget, XVer: 0, ServerNames: []string{settings.RealitySNI}, PrivateKey: settings.RealityPrivateKey, MinClientVer: realityMinClientVersion, ShortIDs: shortIDs}},
		Sniffing:       sniffing{Enabled: true, DestOverride: []string{"http", "tls", "quic"}},
	}}
	if settings.Hysteria2Enabled {
		hysteriaUsers := make([]hysteriaUser, 0, len(activeHysteria))
		for _, client := range activeHysteria {
			auth := client.HysteriaAuth
			if auth == "" {
				auth = client.UUID
			}
			if auth == "" || client.Email == "" {
				return nil, fmt.Errorf("client %s is missing Hysteria 2 credentials", client.ID)
			}
			hysteriaUsers = append(hysteriaUsers, hysteriaUser{Auth: auth, Email: client.Email})
		}
		certPath, keyPath := settings.HysteriaTLSCertPath, settings.HysteriaTLSKeyPath
		if certPath == "" {
			certPath = HysteriaTLSCertPath
		}
		if keyPath == "" {
			keyPath = HysteriaTLSKeyPath
		}
		hysteriaTransport := hysteriaTransportSettings{Version: 2, UDPIdleTimeout: settings.HysteriaUDPIdleTimeout}
		if settings.HysteriaMasqueradeType == "string" {
			hysteriaTransport.Masquerade = &hysteriaMasquerade{Type: "string", Content: settings.HysteriaMasqueradeString, StatusCode: 404}
		}
		inbounds = append(inbounds, hysteriaInbound{
			Listen: "0.0.0.0", Port: settings.InternalInboundPort, Protocol: "hysteria", Tag: HysteriaInboundTag,
			Settings: hysteriaInboundSettings{Version: 2, Users: hysteriaUsers},
			StreamSettings: hysteriaStreamSettings{
				Network: "hysteria", Security: "tls",
				TLSSettings:      hysteriaTLSSettings{Certificates: []hysteriaCertificate{{CertificateFile: certPath, KeyFile: keyPath}}},
				HysteriaSettings: hysteriaTransport,
			},
		})
	}
	if hasVMessProfile {
		if settings.VMessPublicPort < 1 || settings.VMessPublicPort > 65535 {
			return nil, errors.New("VMess public port is not configured")
		}
		vmessUsers := make([]vmessServerClient, 0, len(activeVMess))
		for _, client := range activeVMess {
			if client.UUID == "" || client.Email == "" {
				return nil, fmt.Errorf("client %s is missing VMess credentials", client.ID)
			}
			vmessUsers = append(vmessUsers, vmessServerClient{ID: client.UUID, AlterID: 0, Email: client.Email})
		}
		certPath, keyPath := settings.HysteriaTLSCertPath, settings.HysteriaTLSKeyPath
		if certPath == "" {
			certPath = HysteriaTLSCertPath
		}
		if keyPath == "" {
			keyPath = HysteriaTLSKeyPath
		}
		inbounds = append(inbounds, vmessInbound{
			Listen: "0.0.0.0", Port: VMessInternalPort, Protocol: "vmess", Tag: VMessInboundTag,
			Settings: vmessInboundSettings{Clients: vmessUsers},
			StreamSettings: vmessStreamSettings{
				Network: "tcp", Security: "tls",
				TLSSettings: hysteriaTLSSettings{Certificates: []hysteriaCertificate{{CertificateFile: certPath, KeyFile: keyPath}}},
			},
		})
	}
	if settings.ShadowsocksEnabled {
		if settings.ShadowsocksPublicPort < 1 || settings.ShadowsocksPublicPort > 65535 {
			return nil, errors.New("Shadowsocks public port is not configured")
		}
		if !domain.SupportsShadowsocksMethod(settings.ShadowsocksMethod) {
			return nil, errors.New("unsupported Shadowsocks method")
		}
		if !domain.SupportsShadowsocksNetwork(settings.ShadowsocksNetwork) {
			return nil, errors.New("unsupported Shadowsocks network")
		}
		ssUsers := make([]shadowsocksServerClient, 0, len(activeShadowsocks))
		for _, client := range activeShadowsocks {
			if client.ShadowsocksPassword == "" || client.Email == "" {
				return nil, fmt.Errorf("client %s is missing Shadowsocks credentials", client.ID)
			}
			ssUsers = append(ssUsers, shadowsocksServerClient{Method: settings.ShadowsocksMethod, Password: client.ShadowsocksPassword, Email: client.Email})
		}
		inbounds = append(inbounds, shadowsocksInbound{
			Listen: "0.0.0.0", Port: ShadowsocksInternalPort, Protocol: "shadowsocks", Tag: ShadowsocksInboundTag,
			Settings: shadowsocksInboundSettings{Network: settings.ShadowsocksNetwork, Clients: ssUsers},
		})
	}
	if settings.TrojanEnabled {
		if settings.TrojanPublicPort < 1 || settings.TrojanPublicPort > 65535 {
			return nil, errors.New("Trojan public port is not configured")
		}
		trojanUsers := make([]trojanServerClient, 0, len(activeTrojan))
		for _, client := range activeTrojan {
			if client.TrojanPassword == "" || client.Email == "" {
				return nil, fmt.Errorf("client %s is missing Trojan credentials", client.ID)
			}
			trojanUsers = append(trojanUsers, trojanServerClient{Password: client.TrojanPassword, Email: client.Email})
		}
		certPath, keyPath := settings.HysteriaTLSCertPath, settings.HysteriaTLSKeyPath
		if certPath == "" {
			certPath = HysteriaTLSCertPath
		}
		if keyPath == "" {
			keyPath = HysteriaTLSKeyPath
		}
		inbounds = append(inbounds, trojanInbound{
			Listen: "0.0.0.0", Port: TrojanInternalPort, Protocol: "trojan", Tag: TrojanInboundTag,
			Settings:       trojanInboundSettings{Clients: trojanUsers},
			StreamSettings: vmessStreamSettings{Network: "tcp", Security: "tls", TLSSettings: hysteriaTLSSettings{Certificates: []hysteriaCertificate{{CertificateFile: certPath, KeyFile: keyPath}}}},
		})
	}
	config := serverConfig{
		Log:       logConfig{LogLevel: settings.LogLevel},
		API:       apiConfig{Tag: "api", Listen: settings.XrayAPIListen, Services: []string{"HandlerService", "LoggerService"}},
		Stats:     map[string]any{},
		Policy:    policyConfig{Levels: map[string]policyLevel{"0": {StatsUserUplink: true, StatsUserDownlink: true, StatsUserOnline: true}}},
		Inbounds:  inbounds,
		Outbounds: []outbound{{Protocol: "freedom", Tag: "direct"}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// BuildProfile builds the requested representation.
func BuildProfile(settings Settings, client Client) (Profile, error) {
	profile := Profile{Protocol: client.Protocol, Name: client.Name, UUID: client.UUID, ShortID: client.ShortID}
	if client.HasVLESS() && !client.VLESSIsRevoked() {
		if err := validateSettings(settings); err != nil {
			return Profile{}, err
		}
		publicHost, err := domain.NormalizePublicHost(settings.PublicHost)
		if err != nil {
			return Profile{}, err
		}
		settings.PublicHost = publicHost
		if client.UUID == "" || client.ShortID == "" {
			return Profile{}, errors.New("VLESS profile is unavailable")
		}
		fingerprint := client.ClientFingerprint
		if fingerprint == "" {
			fingerprint = settings.ClientFingerprint
		}
		if fingerprint == "" {
			return Profile{}, errors.New("client fingerprint is required")
		}
		profile.URI = BuildVLESSURI(settings, client, fingerprint)
		profile.JSON, err = buildClientJSON(settings, client, fingerprint)
		if err != nil {
			return Profile{}, err
		}
	}
	if client.HasHysteria2() && !client.HysteriaIsRevoked() {
		if client.HysteriaCredential() == "" {
			return Profile{}, errors.New("Hysteria 2 profile is unavailable")
		}
		if settings.Hysteria2Enabled {
			if err := validateHysteriaProfileSettings(settings); err != nil {
				return Profile{}, err
			}
			profile.HysteriaURI = BuildHysteriaURI(settings, client)
		}
	}
	if client.HasVMess() && !client.VMessIsRevoked() {
		if client.UUID == "" {
			return Profile{}, errors.New("VMess profile is unavailable")
		}
		if err := validateVMessProfileSettings(settings); err != nil {
			return Profile{}, err
		}
		var err error
		profile.VMessURI, err = BuildVMessURI(settings, client)
		if err != nil {
			return Profile{}, err
		}
		profile.JSON, err = buildVMessClientJSON(settings, client)
		if err != nil {
			return Profile{}, err
		}
	}
	if client.HasShadowsocks() && !client.ShadowsocksIsRevoked() {
		if err := validateShadowsocksProfileSettings(settings); err != nil {
			return Profile{}, err
		}
		if client.ShadowsocksPassword == "" {
			return Profile{}, errors.New("Shadowsocks profile is unavailable")
		}
		profile.ShadowsocksURI = BuildShadowsocksURI(settings, client)
		var err error
		profile.ShadowsocksJSON, err = buildShadowsocksClientJSON(settings, client)
		if err != nil {
			return Profile{}, err
		}
	}
	if client.HasTrojan() && !client.TrojanIsRevoked() {
		if err := validateTrojanProfileSettings(settings); err != nil {
			return Profile{}, err
		}
		if client.TrojanPassword == "" {
			return Profile{}, errors.New("Trojan profile is unavailable")
		}
		profile.TrojanURI = BuildTrojanURI(settings, client)
		var err error
		profile.TrojanJSON, err = buildTrojanClientJSON(settings, client)
		if err != nil {
			return Profile{}, err
		}
	}
	if profile.URI == "" && profile.HysteriaURI == "" && profile.VMessURI == "" && profile.ShadowsocksURI == "" && profile.TrojanURI == "" {
		return Profile{}, errors.New("client profile is unavailable")
	}
	return profile, nil
}

// validateTrojanProfileSettings validates the supplied value.
func validateTrojanProfileSettings(settings Settings) error {
	if !settings.TrojanEnabled {
		return errors.New("Trojan is not enabled")
	}
	if settings.TrojanPublicPort < 1 || settings.TrojanPublicPort > 65535 {
		return errors.New("Trojan public port is not configured")
	}
	if _, err := domain.NormalizePublicHost(settings.PublicHost); err != nil {
		return fmt.Errorf("Trojan public host: %w", err)
	}
	return nil
}

// validateShadowsocksProfileSettings validates the supplied value.
func validateShadowsocksProfileSettings(settings Settings) error {
	if !settings.ShadowsocksEnabled {
		return errors.New("Shadowsocks is not enabled")
	}
	if settings.ShadowsocksPublicPort < 1 || settings.ShadowsocksPublicPort > 65535 {
		return errors.New("Shadowsocks public port is not configured")
	}
	if _, err := domain.NormalizePublicHost(settings.PublicHost); err != nil {
		return fmt.Errorf("Shadowsocks public host: %w", err)
	}
	if !domain.SupportsShadowsocksMethod(settings.ShadowsocksMethod) {
		return errors.New("unsupported Shadowsocks method")
	}
	if !domain.SupportsShadowsocksNetwork(settings.ShadowsocksNetwork) {
		return errors.New("unsupported Shadowsocks network")
	}
	return nil
}

// validateVMessProfileSettings validates the supplied value.
func validateVMessProfileSettings(settings Settings) error {
	if settings.VMessPublicPort < 1 || settings.VMessPublicPort > 65535 {
		return errors.New("VMess public port is not configured")
	}
	if _, err := domain.NormalizePublicHost(settings.PublicHost); err != nil {
		return fmt.Errorf("VMess public host: %w", err)
	}
	if _, err := domain.NormalizePublicHost(vmessServerName(settings)); err != nil {
		return fmt.Errorf("VMess TLS server name: %w", err)
	}
	if settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy {
		if _, err := normalizeTLSFingerprint(settings.HysteriaTLSFingerprint); err != nil {
			return fmt.Errorf("VMess TLS certificate fingerprint: %w", err)
		}
	}
	return nil
}

// normalizeTLSFingerprint performs the operation represented by its name.
func normalizeTLSFingerprint(value string) (string, error) {
	value = strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(value))
	if len(value) != 64 {
		return "", errors.New("must be a SHA-256 fingerprint")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("must be a hexadecimal SHA-256 fingerprint")
	}
	return strings.ToUpper(value), nil
}

// vmessServerName performs the operation represented by its name.
func vmessServerName(settings Settings) string {
	return domain.HysteriaSettings{
		TLSMode:       settings.HysteriaTLSMode,
		TLSCertIP:     settings.HysteriaTLSCertIP,
		TLSServerName: settings.HysteriaTLSServerName,
		Host:          settings.HysteriaHost,
	}.EffectiveTLSServerName(settings.PublicHost)
}

// validateHysteriaProfileSettings validates the supplied value.
func validateHysteriaProfileSettings(settings Settings) error {
	if !settings.Hysteria2Enabled {
		return errors.New("Hysteria 2 is not enabled")
	}
	if settings.PublicPort < 1 || settings.PublicPort > 65535 {
		return errors.New("Hysteria 2 public port is not configured")
	}
	host := settings.HysteriaHost
	if host == "" {
		host = settings.PublicHost
	}
	if _, err := domain.NormalizePublicHost(host); err != nil {
		return fmt.Errorf("Hysteria 2 public host: %w", err)
	}
	serverName := settings.HysteriaTLSServerName
	if serverName != "" {
		if _, err := domain.NormalizePublicHost(serverName); err != nil {
			return fmt.Errorf("Hysteria 2 TLS server name: %w", err)
		}
	}
	return nil
}

// protocol performs the operation represented by its name.
func (c Client) protocol() domain.ClientProtocol {
	if c.Protocol == "" {
		return domain.ProtocolLegacyDual
	}
	return c.Protocol
}

// HasVLESS reports whether the value contains the requested capability.
func (c Client) HasVLESS() bool {
	protocol := c.protocol()
	return protocol == domain.ProtocolVLESS || protocol == domain.ProtocolLegacyDual
}

// HasHysteria2 reports whether the value contains the requested capability.
func (c Client) HasHysteria2() bool {
	protocol := c.protocol()
	return protocol == domain.ProtocolHysteria2 || protocol == domain.ProtocolLegacyDual
}

// HasVMess reports whether the value contains the requested capability.
func (c Client) HasVMess() bool { return c.protocol() == domain.ProtocolVMess }

// HasShadowsocks reports whether the value contains the requested capability.
func (c Client) HasShadowsocks() bool { return c.protocol() == domain.ProtocolShadowsocks }

// HasTrojan reports whether the value contains the requested capability.
func (c Client) HasTrojan() bool { return c.protocol() == domain.ProtocolTrojan }

// VLESSCanConnect performs the operation represented by its name.
func (c Client) VLESSCanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasVLESS() && c.VLESSEnabled && !c.VLESSRevoked
}

// Hysteria2CanConnect performs the operation represented by its name.
func (c Client) Hysteria2CanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasHysteria2() && c.HysteriaEnabled && !c.HysteriaRevoked
}

// VMessCanConnect performs the operation represented by its name.
func (c Client) VMessCanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasVMess() && c.VMESSEnabled() && !c.VMessIsRevoked()
}

// ShadowsocksCanConnect performs the operation represented by its name.
func (c Client) ShadowsocksCanConnect() bool {
	if c.Protocol == "" {
		return false
	}
	return c.HasShadowsocks() && c.ShadowsocksEnabled && !c.ShadowsocksRevoked
}

// TrojanCanConnect performs the operation represented by its name.
func (c Client) TrojanCanConnect() bool {
	if c.Protocol == "" {
		return false
	}
	return c.HasTrojan() && c.TrojanEnabled && !c.TrojanRevoked
}

// VMESSEnabled performs the operation represented by its name.
func (c Client) VMESSEnabled() bool {
	if c.Protocol == "" {
		return c.Enabled
	}
	return c.VMessEnabled
}

// VLESSIsRevoked performs the operation represented by its name.
func (c Client) VLESSIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.VLESSRevoked
}

// HysteriaIsRevoked performs the operation represented by its name.
func (c Client) HysteriaIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.HysteriaRevoked
}

// VMessIsRevoked performs the operation represented by its name.
func (c Client) VMessIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.VMessRevoked
}

// ShadowsocksIsRevoked performs the operation represented by its name.
func (c Client) ShadowsocksIsRevoked() bool {
	if c.Protocol == "" {
		return false
	}
	return c.ShadowsocksRevoked
}

// TrojanIsRevoked performs the operation represented by its name.
func (c Client) TrojanIsRevoked() bool {
	if c.Protocol == "" {
		return false
	}
	return c.TrojanRevoked
}

// HysteriaCredential performs the operation represented by its name.
func (c Client) HysteriaCredential() string {
	if c.HysteriaAuth != "" {
		return c.HysteriaAuth
	}
	return c.UUID
}

// BuildHysteriaURI creates the V2RAGE-compatible Hysteria 2 URI for one device.
func BuildHysteriaURI(settings Settings, client Client) string {
	query := url.Values{}
	if settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy {
		query.Set("insecure", "1")
	}
	serverName := settings.HysteriaTLSServerName
	if serverName == "" {
		serverName = settings.PublicHost
	}
	query.Set("sni", serverName)
	host := settings.HysteriaHost
	if host == "" {
		host = settings.PublicHost
	}
	u := &url.URL{Scheme: "hysteria2", User: url.User(client.HysteriaCredential()), Host: net.JoinHostPort(host, strconv.Itoa(settings.PublicPort)), RawQuery: query.Encode(), Fragment: client.Name}
	return u.String()
}

// BuildVMessURI creates a standard VMess v2 share link for one device.
func BuildVMessURI(settings Settings, client Client) (string, error) {
	serverName := vmessServerName(settings)
	value := map[string]any{
		"v": "2", "ps": client.Name, "add": settings.PublicHost,
		"port": strconv.Itoa(settings.VMessPublicPort), "id": client.UUID,
		"aid": "0", "scy": "auto", "net": "tcp", "type": "none",
		"host": "", "path": "", "tls": "tls", "sni": serverName, "insecure": "0",
	}
	if settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy {
		fingerprint, err := normalizeTLSFingerprint(settings.HysteriaTLSFingerprint)
		if err != nil {
			return "", fmt.Errorf("VMess TLS certificate fingerprint: %w", err)
		}
		value["pcs"] = fingerprint
	}
	data, _ := json.Marshal(value)
	return "vmess://" + base64.StdEncoding.EncodeToString(data), nil
}

// BuildShadowsocksURI creates a SIP-002 Shadowsocks share link.
func BuildShadowsocksURI(settings Settings, client Client) string {
	credentials := base64.RawURLEncoding.EncodeToString([]byte(settings.ShadowsocksMethod + ":" + client.ShadowsocksPassword))
	u := &url.URL{Scheme: "ss", Host: net.JoinHostPort(settings.PublicHost, strconv.Itoa(settings.ShadowsocksPublicPort)), Fragment: client.Name}
	return "ss://" + credentials + "@" + u.Host + "#" + url.PathEscape(client.Name)
}

// BuildTrojanURI creates a Trojan TCP/TLS share link.
func BuildTrojanURI(settings Settings, client Client) string {
	query := url.Values{"security": []string{"tls"}, "type": []string{"tcp"}}
	serverName := vmessServerName(settings)
	if serverName != "" {
		query.Set("sni", serverName)
	}
	if settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy {
		query.Set("allowInsecure", "1")
	}
	u := &url.URL{Scheme: "trojan", User: url.User(client.TrojanPassword), Host: net.JoinHostPort(settings.PublicHost, strconv.Itoa(settings.TrojanPublicPort)), RawQuery: query.Encode(), Fragment: client.Name}
	return u.String()
}

// buildTrojanClientJSON performs the operation represented by its name.
func buildTrojanClientJSON(settings Settings, client Client) ([]byte, error) {
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{map[string]any{
			"protocol":       "trojan",
			"settings":       map[string]any{"servers": []any{map[string]any{"address": settings.PublicHost, "port": settings.TrojanPublicPort, "password": client.TrojanPassword}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": vmessServerName(settings), "allowInsecure": settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy}},
		}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// buildShadowsocksClientJSON performs the operation represented by its name.
func buildShadowsocksClientJSON(settings Settings, client Client) ([]byte, error) {
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": settings.PublicHost, "port": settings.ShadowsocksPublicPort,
				"method": settings.ShadowsocksMethod, "password": client.ShadowsocksPassword,
			}}},
		}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// buildVMessClientJSON performs the operation represented by its name.
func buildVMessClientJSON(settings Settings, client Client) ([]byte, error) {
	serverName := vmessServerName(settings)
	tls := map[string]any{"serverName": serverName}
	if settings.HysteriaTLSMode == HysteriaTLSSelfSigned || settings.HysteriaTLSMode == HysteriaTLSLegacy {
		fingerprint, err := normalizeTLSFingerprint(settings.HysteriaTLSFingerprint)
		if err != nil {
			return nil, fmt.Errorf("VMess TLS certificate fingerprint: %w", err)
		}
		tls["pinnedPeerCertSha256"] = fingerprint
	}
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{map[string]any{
			"protocol":       "vmess",
			"settings":       map[string]any{"vnext": []any{map[string]any{"address": settings.PublicHost, "port": settings.VMessPublicPort, "users": []any{map[string]any{"id": client.UUID, "alterId": 0, "security": "auto"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": tls},
		}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// BuildVLESSURI builds the requested representation.
func BuildVLESSURI(settings Settings, client Client, fingerprint string) string {
	query := url.Values{}
	query.Set("encryption", "none")
	query.Set("flow", Flow)
	query.Set("fp", fingerprint)
	query.Set("pbk", settings.RealityPublicKey)
	query.Set("security", Security)
	query.Set("sid", client.ShortID)
	query.Set("sni", settings.RealitySNI)
	query.Set("type", Network)
	u := &url.URL{Scheme: Protocol, User: url.User(client.UUID), Host: net.JoinHostPort(settings.PublicHost, strconv.Itoa(settings.PublicPort)), RawQuery: query.Encode(), Fragment: client.Name}
	return u.String()
}

// buildClientJSON performs the operation represented by its name.
func buildClientJSON(settings Settings, client Client, fingerprint string) ([]byte, error) {
	value := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": map[string]any{"udp": true}}},
		"outbounds": []any{map[string]any{
			"protocol": Protocol,
			"settings": map[string]any{"vnext": []any{map[string]any{"address": settings.PublicHost, "port": settings.PublicPort, "users": []any{map[string]any{"id": client.UUID, "encryption": "none", "flow": Flow}}}}},
			"streamSettings": map[string]any{"network": Network, "security": Security, "realitySettings": map[string]any{
				"serverName":  settings.RealitySNI,
				"fingerprint": fingerprint,
				// password is the current Xray field; publicKey keeps the
				// exported profile importable by clients that still use the
				// historical name (including V2Rage builds).
				"password":  settings.RealityPublicKey,
				"publicKey": settings.RealityPublicKey,
				"shortId":   client.ShortID,
				"spiderX":   "/",
			}},
		}},
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// validateSettings validates the supplied value.
func validateSettings(settings Settings) error {
	if settings.LogLevel != "" && !domain.SupportsXrayLogLevel(settings.LogLevel) {
		return errors.New("unsupported Xray log level")
	}
	if err := ValidatePublicHost(settings.PublicHost); err != nil {
		return err
	}
	if settings.PublicPort < 1 || settings.PublicPort > 65535 {
		return errors.New("public host and port are required")
	}
	if settings.XrayAPIListen == "" || settings.InternalInboundPort < 1 || settings.InternalInboundPort > 65535 {
		return errors.New("Xray API and internal inbound port are required")
	}
	if err := ValidateTarget(settings.RealityTarget, settings.RealitySNI); err != nil {
		return err
	}
	if settings.RealityPrivateKey == "" || settings.RealityPublicKey == "" {
		return errors.New("REALITY key pair is not configured")
	}
	if settings.Hysteria2Enabled {
		switch settings.HysteriaTLSMode {
		case "", HysteriaTLSCustom, HysteriaTLSLegacy:
			if settings.HysteriaTLSServerName != "" {
				if _, err := domain.NormalizePublicHost(settings.HysteriaTLSServerName); err != nil {
					return fmt.Errorf("Hysteria 2 TLS server name: %w", err)
				}
			}
		case HysteriaTLSSelfSigned:
			ip, err := netip.ParseAddr(settings.HysteriaTLSCertIP)
			if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
				return errors.New("Hysteria 2 self-signed certificate requires a public IPv4 address")
			}
			if settings.PublicHost != ip.String() {
				return errors.New("Hysteria 2 public host must match the self-signed certificate IPv4 address")
			}
			if settings.HysteriaTLSServerName != "" && settings.HysteriaTLSServerName != ip.String() {
				return errors.New("Hysteria 2 self-signed TLS server name must match the certificate IPv4 address")
			}
		default:
			return errors.New("unsupported Hysteria 2 TLS mode")
		}
	}
	return nil
}
