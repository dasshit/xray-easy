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
	Protocol = "vless"
	Network  = "tcp"
	Security = "reality"
	Flow     = "xtls-rprx-vision"
	// Xray 26.7.11 and newer apply an implicit minClientVer of 26.3.27
	// when the field is omitted. Third-party clients such as V2RAGE may
	// report an older REALITY client version, so keep the compatibility
	// floor explicit until clients can be verified against the newer gate.
	realityMinClientVersion = "1.0.0"
	// Xray requires at least one REALITY short ID even when there are no
	// enabled clients. This reserved value has no matching UUID and therefore
	// cannot authenticate a device.
	emptyShortID            = "0000000000000000"
	ReservedShortIDCount    = 5
	VerifiedCoreVersion     = "26.7.28"
	HysteriaInboundTag      = "hysteria2"
	VMessInboundTag         = "vmess-tls"
	ShadowsocksInboundTag   = "shadowsocks"
	TrojanInboundTag        = "trojan-tls"
	VMessInternalPort       = 8444
	ShadowsocksInternalPort = 8388
	TrojanInternalPort      = 8445
	HysteriaTLSCertPath     = "/etc/xray/hysteria-tls/fullchain.pem"
	HysteriaTLSKeyPath      = "/etc/xray/hysteria-tls/privkey.pem"
	HysteriaTLSSelfSigned   = "self-signed"
	HysteriaTLSCustom       = "custom"
	HysteriaTLSLegacy       = "legacy"
)

type Settings struct {
	PublicHost               string
	PublicPort               int
	XrayAPIListen            string
	RealityTarget            string
	RealitySNI               string
	RealityPrivateKey        string
	RealityPublicKey         string
	ClientFingerprint        string
	LogLevel                 string
	InternalInboundPort      int
	ReservedShortIDs         []string
	Hysteria2Enabled         bool
	HysteriaTLSMode          string
	HysteriaTLSCertIP        string
	HysteriaTLSServerName    string
	HysteriaTLSFingerprint   string
	HysteriaHost             string
	HysteriaTLSCertPath      string
	HysteriaTLSKeyPath       string
	HysteriaUDPIdleTimeout   int
	HysteriaMasqueradeType   string
	HysteriaMasqueradeString string
	VMessPublicPort          int
	ShadowsocksEnabled       bool
	ShadowsocksPublicPort    int
	ShadowsocksMethod        string
	ShadowsocksNetwork       string
	TrojanEnabled            bool
	TrojanPublicPort         int
}

type Client struct {
	ID                  string
	Name                string
	Protocol            domain.ClientProtocol
	UUID                string
	Email               string
	ShortID             string
	HysteriaAuth        string
	ClientFingerprint   string
	Enabled             bool
	Revoked             bool
	VLESSEnabled        bool
	VLESSRevoked        bool
	HysteriaEnabled     bool
	HysteriaRevoked     bool
	VMessEnabled        bool
	VMessRevoked        bool
	ShadowsocksPassword string
	ShadowsocksEnabled  bool
	ShadowsocksRevoked  bool
	TrojanPassword      string
	TrojanEnabled       bool
	TrojanRevoked       bool
}

type Profile struct {
	Protocol        domain.ClientProtocol
	URI             string
	HysteriaURI     string
	VMessURI        string
	ShadowsocksURI  string
	ShadowsocksJSON []byte
	TrojanURI       string
	TrojanJSON      []byte
	JSON            []byte
	Name            string
	UUID            string
	ShortID         string
}

type serverConfig struct {
	Log       logConfig      `json:"log"`
	API       apiConfig      `json:"api"`
	Stats     map[string]any `json:"stats"`
	Policy    policyConfig   `json:"policy"`
	Inbounds  []any          `json:"inbounds"`
	Outbounds []outbound     `json:"outbounds"`
}

type logConfig struct {
	LogLevel string `json:"loglevel"`
}
type apiConfig struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Services []string `json:"services"`
}
type policyConfig struct {
	Levels map[string]policyLevel `json:"levels"`
}
type policyLevel struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
	StatsUserOnline   bool `json:"statsUserOnline"`
}
type inbound struct {
	Listen         string          `json:"listen"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       inboundSettings `json:"settings"`
	StreamSettings streamSettings  `json:"streamSettings"`
	Sniffing       sniffing        `json:"sniffing"`
}
type inboundSettings struct {
	Clients    []serverClient `json:"clients"`
	Decryption string         `json:"decryption"`
}
type serverClient struct {
	ID    string `json:"id"`
	Flow  string `json:"flow,omitempty"`
	Email string `json:"email"`
}
type streamSettings struct {
	Network         string        `json:"network"`
	Security        string        `json:"security"`
	RealitySettings realityServer `json:"realitySettings"`
}
type realityServer struct {
	Show         bool     `json:"show"`
	Target       string   `json:"target"`
	XVer         int      `json:"xver"`
	ServerNames  []string `json:"serverNames"`
	PrivateKey   string   `json:"privateKey"`
	MinClientVer string   `json:"minClientVer"`
	ShortIDs     []string `json:"shortIds"`
}
type sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}
type outbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}
type hysteriaInbound struct {
	Listen         string                  `json:"listen"`
	Port           int                     `json:"port"`
	Protocol       string                  `json:"protocol"`
	Tag            string                  `json:"tag"`
	Settings       hysteriaInboundSettings `json:"settings"`
	StreamSettings hysteriaStreamSettings  `json:"streamSettings"`
}
type hysteriaInboundSettings struct {
	Version int            `json:"version"`
	Users   []hysteriaUser `json:"users"`
}
type hysteriaUser struct {
	Auth  string `json:"auth"`
	Level int    `json:"level"`
	Email string `json:"email"`
}
type hysteriaStreamSettings struct {
	Network          string                    `json:"network"`
	Security         string                    `json:"security"`
	TLSSettings      hysteriaTLSSettings       `json:"tlsSettings"`
	HysteriaSettings hysteriaTransportSettings `json:"hysteriaSettings"`
}
type hysteriaTLSSettings struct {
	Certificates []hysteriaCertificate `json:"certificates"`
}
type hysteriaCertificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}
type hysteriaTransportSettings struct {
	Version        int                 `json:"version"`
	UDPIdleTimeout int                 `json:"udpIdleTimeout,omitempty"`
	Masquerade     *hysteriaMasquerade `json:"masquerade,omitempty"`
}

type hysteriaMasquerade struct {
	Type       string `json:"type"`
	Content    string `json:"content,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
}

type vmessInbound struct {
	Listen         string               `json:"listen"`
	Port           int                  `json:"port"`
	Protocol       string               `json:"protocol"`
	Tag            string               `json:"tag"`
	Settings       vmessInboundSettings `json:"settings"`
	StreamSettings vmessStreamSettings  `json:"streamSettings"`
}

type vmessInboundSettings struct {
	Clients []vmessServerClient `json:"clients"`
}

type vmessServerClient struct {
	ID      string `json:"id"`
	AlterID int    `json:"alterId"`
	Email   string `json:"email"`
}

type vmessStreamSettings struct {
	Network     string              `json:"network"`
	Security    string              `json:"security"`
	TLSSettings hysteriaTLSSettings `json:"tlsSettings"`
}

type shadowsocksInbound struct {
	Listen   string                     `json:"listen"`
	Port     int                        `json:"port"`
	Protocol string                     `json:"protocol"`
	Tag      string                     `json:"tag"`
	Settings shadowsocksInboundSettings `json:"settings"`
}

type shadowsocksInboundSettings struct {
	Network string                    `json:"network"`
	Clients []shadowsocksServerClient `json:"clients"`
}

type shadowsocksServerClient struct {
	Method   string `json:"method"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type trojanInbound struct {
	Listen         string                `json:"listen"`
	Port           int                   `json:"port"`
	Protocol       string                `json:"protocol"`
	Tag            string                `json:"tag"`
	Settings       trojanInboundSettings `json:"settings"`
	StreamSettings vmessStreamSettings   `json:"streamSettings"`
}

type trojanInboundSettings struct {
	Clients []trojanServerClient `json:"clients"`
}

type trojanServerClient struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

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

func vmessServerName(settings Settings) string {
	return domain.HysteriaSettings{
		TLSMode:       settings.HysteriaTLSMode,
		TLSCertIP:     settings.HysteriaTLSCertIP,
		TLSServerName: settings.HysteriaTLSServerName,
		Host:          settings.HysteriaHost,
	}.EffectiveTLSServerName(settings.PublicHost)
}

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

func (c Client) protocol() domain.ClientProtocol {
	if c.Protocol == "" {
		return domain.ProtocolLegacyDual
	}
	return c.Protocol
}

func (c Client) HasVLESS() bool {
	protocol := c.protocol()
	return protocol == domain.ProtocolVLESS || protocol == domain.ProtocolLegacyDual
}

func (c Client) HasHysteria2() bool {
	protocol := c.protocol()
	return protocol == domain.ProtocolHysteria2 || protocol == domain.ProtocolLegacyDual
}

func (c Client) HasVMess() bool { return c.protocol() == domain.ProtocolVMess }

func (c Client) HasShadowsocks() bool { return c.protocol() == domain.ProtocolShadowsocks }

func (c Client) HasTrojan() bool { return c.protocol() == domain.ProtocolTrojan }

func (c Client) VLESSCanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasVLESS() && c.VLESSEnabled && !c.VLESSRevoked
}

func (c Client) Hysteria2CanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasHysteria2() && c.HysteriaEnabled && !c.HysteriaRevoked
}

func (c Client) VMessCanConnect() bool {
	if c.Protocol == "" {
		return c.Enabled && !c.Revoked
	}
	return c.HasVMess() && c.VMESSEnabled() && !c.VMessIsRevoked()
}

func (c Client) ShadowsocksCanConnect() bool {
	if c.Protocol == "" {
		return false
	}
	return c.HasShadowsocks() && c.ShadowsocksEnabled && !c.ShadowsocksRevoked
}

func (c Client) TrojanCanConnect() bool {
	if c.Protocol == "" {
		return false
	}
	return c.HasTrojan() && c.TrojanEnabled && !c.TrojanRevoked
}

func (c Client) VMESSEnabled() bool {
	if c.Protocol == "" {
		return c.Enabled
	}
	return c.VMessEnabled
}

func (c Client) VLESSIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.VLESSRevoked
}

func (c Client) HysteriaIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.HysteriaRevoked
}

func (c Client) VMessIsRevoked() bool {
	if c.Protocol == "" {
		return c.Revoked
	}
	return c.VMessRevoked
}

func (c Client) ShadowsocksIsRevoked() bool {
	if c.Protocol == "" {
		return false
	}
	return c.ShadowsocksRevoked
}

func (c Client) TrojanIsRevoked() bool {
	if c.Protocol == "" {
		return false
	}
	return c.TrojanRevoked
}

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
