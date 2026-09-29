package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"

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
	emptyShortID         = "0000000000000000"
	ReservedShortIDCount = 5
	VerifiedCoreVersion  = "26.7.28"
)

type Settings struct {
	PublicHost          string
	PublicPort          int
	XrayAPIListen       string
	RealityTarget       string
	RealitySNI          string
	RealityPrivateKey   string
	RealityPublicKey    string
	ClientFingerprint   string
	LogLevel            string
	InternalInboundPort int
	ReservedShortIDs    []string
}

type Client struct {
	ID                string
	Name              string
	UUID              string
	Email             string
	ShortID           string
	ClientFingerprint string
	Enabled           bool
	Revoked           bool
}

type Profile struct {
	URI     string
	JSON    []byte
	Name    string
	UUID    string
	ShortID string
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

func RenderServerConfig(settings Settings, clients []Client) ([]byte, error) {
	if settings.LogLevel == "" {
		settings.LogLevel = "warning"
	}
	if err := validateSettings(settings); err != nil {
		return nil, err
	}
	active := make([]Client, 0, len(clients))
	for _, client := range clients {
		if client.Enabled && !client.Revoked {
			active = append(active, client)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	serverClients := make([]serverClient, 0, len(active))
	shortIDs := make([]string, 0, len(clients)+len(settings.ReservedShortIDs))
	shortIDSet := make(map[string]struct{}, cap(shortIDs))
	for _, client := range active {
		if client.UUID == "" || client.ShortID == "" || client.Email == "" {
			return nil, fmt.Errorf("client %s is missing generated fields", client.ID)
		}
		serverClients = append(serverClients, serverClient{ID: client.UUID, Flow: Flow, Email: client.Email})
	}
	// Keep IDs for disabled profiles in REALITY so they can be enabled with
	for _, client := range clients {
		if client.Revoked || client.ShortID == "" {
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
	config := serverConfig{
		Log:       logConfig{LogLevel: settings.LogLevel},
		API:       apiConfig{Tag: "api", Listen: settings.XrayAPIListen, Services: []string{"HandlerService", "StatsService", "LoggerService"}},
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
	if err := validateSettings(settings); err != nil {
		return Profile{}, err
	}
	publicHost, err := domain.NormalizePublicHost(settings.PublicHost)
	if err != nil {
		return Profile{}, err
	}
	settings.PublicHost = publicHost
	if client.UUID == "" || client.ShortID == "" || client.Revoked {
		return Profile{}, errors.New("client profile is unavailable")
	}
	fingerprint := client.ClientFingerprint
	if fingerprint == "" {
		fingerprint = settings.ClientFingerprint
	}
	if fingerprint == "" {
		return Profile{}, errors.New("client fingerprint is required")
	}
	uri := BuildVLESSURI(settings, client, fingerprint)
	clientJSON, err := buildClientJSON(settings, client, fingerprint)
	if err != nil {
		return Profile{}, err
	}
	return Profile{URI: uri, JSON: clientJSON, Name: client.Name, UUID: client.UUID, ShortID: client.ShortID}, nil
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
	return nil
}
