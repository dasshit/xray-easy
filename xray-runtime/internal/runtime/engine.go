// Package runtime embeds Xray core and exposes its managed runtime operations.
package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	coreinbound "github.com/xtls/xray-core/features/inbound"
	corestats "github.com/xtls/xray-core/features/stats"
	xrayserial "github.com/xtls/xray-core/infra/conf/serial"
	"github.com/xtls/xray-core/proxy"
	hysteriaaccount "github.com/xtls/xray-core/proxy/hysteria/account"
	shadowsocks2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	trojan "github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
	"xray-easy/internal/domain"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
	_ "xray-easy/xray-runtime/internal/xrayregistration"
)

// capturedXrayLog is an internal type used by the package.
type capturedXrayLog struct {
	write func(level, component, message string)
	allow func(level string) bool
}

// Handle handles the supplied event.
func (h capturedXrayLog) Handle(message corelog.Message) {
	if h.write == nil {
		return
	}
	level := ""
	text := ""
	switch typed := message.(type) {
	case *corelog.AccessMessage:
		// Xray emits accepted and rejected inbound connections as access
		// messages, which do not carry GeneralMessage severity. Keep the
		// normal logging filter while mapping rejected access to warning.
		level = "info"
		if typed.Status == corelog.AccessRejected {
			level = "warn"
		}
		text = typed.String()
	case *corelog.GeneralMessage:
		switch typed.Severity {
		case corelog.Severity_Error:
			level = "error"
		case corelog.Severity_Warning:
			level = "warn"
		case corelog.Severity_Info:
			level = "info"
		case corelog.Severity_Debug:
			level = "debug"
		default:
			return
		}
		text = fmt.Sprint(typed.Content)
	default:
		return
	}
	if h.allow != nil && !h.allow(level) {
		return
	}
	h.write(level, "xray", redactXrayLog(text))
}

var (
	// ipv4EndpointPattern is an internal package variable.
	ipv4EndpointPattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b`)
	// bracketedIPv6Pattern is an internal package variable.
	bracketedIPv6Pattern = regexp.MustCompile(`\[[0-9a-fA-F:]+\](?::[0-9]{1,5})?`)
	// canonicalUUIDPattern is an internal package variable.
	canonicalUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// runtimeExecutable is an internal package variable.
	runtimeExecutable = os.Executable
)

// isolatedValidationTimeout is an internal package constant.
const isolatedValidationTimeout = 20 * time.Second

// maxTelemetrySourceIPs is an internal package constant.
const maxTelemetrySourceIPs = 32

// redactXrayLog performs the operation represented by its name.
func redactXrayLog(message string) string {
	message = ipv4EndpointPattern.ReplaceAllString(message, "[REDACTED-IP]")
	message = bracketedIPv6Pattern.ReplaceAllString(message, "[REDACTED-IP]")
	return strings.TrimSpace(message)
}

// Engine owns the one Xray instance active in this process.
type Engine struct {
	instance      *core.Instance
	leases        *leaseConnectionRegistry
	leaseTracking bool
}

// ErrInboundRollbackFailed marks a replacement failure whose previous handler
// could not be restored, requiring the runtime process to restart.
var ErrInboundRollbackFailed = errors.New("inbound rollback failed")

// LoadEngine parses and constructs an Xray instance without starting listeners.
func LoadEngine(configuration []byte) (*Engine, error) {
	config, err := parseConfig(configuration)
	if err != nil {
		return nil, err
	}
	instance, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("construct Xray instance: %w", err)
	}
	leases := newLeaseConnectionRegistry()
	leaseTracking, err := installLeaseTracking(instance, leases)
	if err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("install Xray lease tracking: %w", err)
	}
	return &Engine{instance: instance, leases: leases, leaseTracking: leaseTracking}, nil
}

// ValidateConfig runs Xray's config builder without constructing a core
// instance. core.New mutates Xray process-global logging and dialer state, so
// candidate validation must not call it while the active instance is running.
func ValidateConfig(configuration []byte) error {
	_, err := parseConfig(configuration)
	return err
}

// ValidateConfigIsolated performs full core construction in a short-lived
// process so Xray's process-global settings cannot affect the active instance.
func ValidateConfigIsolated(configuration []byte) error {
	return ValidateConfigIsolatedContext(context.Background(), configuration)
}

// ValidateConfigIsolatedContext performs full Xray construction in a child
// process and honors the caller's deadline or cancellation.
func ValidateConfigIsolatedContext(parent context.Context, configuration []byte) error {
	if parent == nil {
		parent = context.Background()
	}
	if err := ValidateConfig(configuration); err != nil {
		return err
	}
	executable, err := runtimeExecutable()
	if err != nil {
		return errors.New("locate runtime executable")
	}
	ctx, cancel := context.WithTimeout(parent, isolatedValidationTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "validate-candidate")
	command.Stdin = bytes.NewReader(configuration)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return context.Canceled
		}
		return errors.New("isolated Xray runtime validation failed")
	}
	return nil
}

// parseConfig parses the supplied value.
func parseConfig(configuration []byte) (*core.Config, error) {
	if len(configuration) == 0 {
		return nil, errors.New("Xray configuration is empty")
	}
	configuration, err := stripExternalAPIServer(configuration)
	if err != nil {
		return nil, fmt.Errorf("remove external Xray API server: %w", err)
	}
	// Keep the complete Xray diagnostic stream available to the embedded
	// handler. Service-level filtering can then change the administrator's
	// selected level without restarting listeners.
	var document map[string]json.RawMessage
	if json.Unmarshal(configuration, &document) == nil && document != nil {
		var logConfig map[string]any
		if raw, ok := document["log"]; ok && json.Unmarshal(raw, &logConfig) == nil {
			logConfig["loglevel"] = "debug"
			document["log"], _ = json.Marshal(logConfig)
			configuration, _ = json.Marshal(document)
		}
	}
	config, err := xrayserial.LoadJSONConfig(bytes.NewReader(configuration))
	if err != nil {
		return nil, fmt.Errorf("parse Xray configuration: %w", err)
	}
	return config, nil
}

// stripExternalAPIServer removes the top-level Xray API app from configs
// rendered for the Controller. The embedded runtime owns the Xray instance
// directly and uses its in-process features, so starting this legacy listener
// is unnecessary and can fail when its configured address belongs to the
// runtime container's network namespace.
func stripExternalAPIServer(configuration []byte) ([]byte, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(configuration, &document); err != nil || document == nil {
		// Let Xray's config loader report malformed or non-object input using its
		// regular validation path.
		return configuration, nil
	}
	if _, exists := document["api"]; !exists {
		return configuration, nil
	}
	delete(document, "api")
	stripped, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return stripped, nil
}

// Start starts the Xray listeners and runtime features.
func (e *Engine) Start() error {
	if e == nil || e.instance == nil {
		return errors.New("Xray instance is not initialized")
	}
	if err := e.instance.Start(); err != nil {
		return fmt.Errorf("start Xray instance: %w", err)
	}
	return nil
}

// Close shuts down the instance and releases its features.
func (e *Engine) Close() error {
	if e == nil || e.instance == nil {
		return nil
	}
	return e.instance.Close()
}

// InboundConfiguration returns the active inbound with the requested tag.
func InboundConfiguration(configuration []byte, tag string) (*core.InboundHandlerConfig, error) {
	config, err := parseConfig(configuration)
	if err != nil {
		return nil, err
	}
	for _, inbound := range config.GetInbound() {
		if inbound.GetTag() == tag {
			return inbound, nil
		}
	}
	return nil, nil
}

// ReplaceInbound updates one live inbound and reports whether it already
// matched the requested configuration. Failed candidate adds restore the
// handler settings observed before removal.
func (e *Engine) ReplaceInbound(ctx context.Context, tag string, configuration []byte) (bool, error) {
	if e == nil || e.instance == nil {
		return false, errors.New("Xray instance is not initialized")
	}
	manager, ok := e.instance.GetFeature(coreinbound.ManagerType()).(coreinbound.Manager)
	if !ok || manager == nil {
		return false, errors.New("Xray inbound manager is unavailable")
	}
	var desired *core.InboundHandlerConfig
	if len(configuration) != 0 {
		var err error
		desired, err = InboundConfiguration(configuration, tag)
		if err != nil {
			return false, err
		}
	}
	var current coreinbound.Handler
	for _, handler := range manager.ListHandlers(ctx) {
		if handler.Tag() == tag {
			current = handler
			break
		}
	}
	if current != nil && desired != nil && proto.Equal(current.ProxySettings(), desired.GetProxySettings()) && proto.Equal(current.ReceiverSettings(), desired.GetReceiverSettings()) {
		return true, nil
	}
	var previous *core.InboundHandlerConfig
	if current != nil {
		previous = &core.InboundHandlerConfig{Tag: current.Tag(), ProxySettings: current.ProxySettings(), ReceiverSettings: current.ReceiverSettings()}
		if err := manager.RemoveHandler(ctx, tag); err != nil {
			return false, fmt.Errorf("remove current inbound: %w", err)
		}
	} else if desired == nil {
		return true, nil
	}
	if desired == nil {
		return false, nil
	}
	if err := core.AddInboundHandler(e.instance, desired); err != nil {
		if previous != nil {
			if restoreErr := core.AddInboundHandler(e.instance, previous); restoreErr != nil {
				return false, fmt.Errorf("%w: %v", ErrInboundRollbackFailed, restoreErr)
			}
		}
		return false, fmt.Errorf("add candidate inbound: %w", err)
	}
	return false, nil
}

// AddUser inserts a protocol user or reports that the matching user already
// exists. A conflicting credential for the same email is rejected.
func (e *Engine) AddUser(ctx context.Context, protocolType xrayruntimev1.Protocol, tag, email, credential, flow string) (bool, error) {
	return e.AddUserWithMethod(ctx, protocolType, tag, email, credential, flow, "")
}

// AddUserWithMethod inserts a user and supplies the Shadowsocks 2022 cipher
// when that protocol is selected. Other protocols ignore method.
func (e *Engine) AddUserWithMethod(ctx context.Context, protocolType xrayruntimev1.Protocol, tag, email, credential, flow, method string) (bool, error) {
	if strings.EqualFold(strings.TrimSpace(email), domain.ShadowsocksBootstrapUserEmail) {
		return false, errors.New("reserved Shadowsocks 2022 bootstrap identity")
	}
	manager, err := e.userManager(ctx, tag)
	if err != nil {
		return false, err
	}
	account, err := accountForWithMethod(protocolType, credential, flow, method)
	if err != nil {
		return false, err
	}
	for _, existing := range manager.GetUsers(ctx) {
		if existing.Email != email {
			continue
		}
		if sameAccount(existing.Account, account) {
			if e.leases != nil {
				e.leases.allowProfile(leaseProfileKey{protocol: protocolType, email: email})
			}
			return true, nil
		}
		return false, errors.New("Xray user email already exists with a different credential")
	}
	if err := manager.AddUser(ctx, &protocol.MemoryUser{Email: email, Account: account}); err != nil {
		return false, err
	}
	if e.leases != nil {
		e.leases.allowProfile(leaseProfileKey{protocol: protocolType, email: email})
	}
	return false, nil
}

// sameAccount performs the operation represented by its name.
func sameAccount(current, desired protocol.Account) bool {
	if current == nil || desired == nil || !current.Equals(desired) {
		return false
	}
	currentVLESS, currentIsVLESS := current.(*vless.MemoryAccount)
	desiredVLESS, desiredIsVLESS := desired.(*vless.MemoryAccount)
	if currentIsVLESS || desiredIsVLESS {
		return currentIsVLESS && desiredIsVLESS && currentVLESS.Flow == desiredVLESS.Flow
	}
	return true
}

// RemoveUser removes a user, treating an already absent user as success.
func (e *Engine) RemoveUser(ctx context.Context, tag, email string) (bool, error) {
	if strings.EqualFold(strings.TrimSpace(email), domain.ShadowsocksBootstrapUserEmail) {
		return false, errors.New("reserved Shadowsocks 2022 bootstrap identity")
	}
	manager, err := e.userManager(ctx, tag)
	if err != nil {
		return false, err
	}
	for _, existing := range manager.GetUsers(ctx) {
		if existing.Email == email {
			if err := manager.RemoveUser(ctx, email); err != nil {
				return false, err
			}
			return false, nil
		}
	}
	return true, nil
}

// ListUsers returns sorted user email labels for one configured inbound.
func (e *Engine) ListUsers(ctx context.Context, tag string) ([]string, error) {
	manager, err := e.userManager(ctx, tag)
	if err != nil {
		return nil, err
	}
	users := manager.GetUsers(ctx)
	emails := make([]string, 0, len(users))
	for _, user := range users {
		if strings.EqualFold(strings.TrimSpace(user.Email), domain.ShadowsocksBootstrapUserEmail) {
			continue
		}
		emails = append(emails, user.Email)
	}
	sort.Strings(emails)
	return emails, nil
}

// userManager performs the operation represented by its name.
func (e *Engine) userManager(ctx context.Context, tag string) (proxy.UserManager, error) {
	if e == nil || e.instance == nil {
		return nil, errors.New("Xray instance is not initialized")
	}
	manager, ok := e.instance.GetFeature(coreinbound.ManagerType()).(coreinbound.Manager)
	if !ok || manager == nil {
		return nil, errors.New("Xray inbound manager is unavailable")
	}
	handler, err := manager.GetHandler(ctx, tag)
	if err != nil {
		return nil, err
	}
	withInbound, ok := handler.(proxy.GetInbound)
	if !ok || withInbound.GetInbound() == nil {
		return nil, errors.New("configured Xray inbound does not manage users")
	}
	userManager, ok := withInbound.GetInbound().(proxy.UserManager)
	if !ok || userManager == nil {
		return nil, errors.New("configured Xray inbound does not manage users")
	}
	return userManager, nil
}

// accountFor performs the operation represented by its name.
func accountFor(protocolType xrayruntimev1.Protocol, credential, flow string) (protocol.Account, error) {
	return accountForWithMethod(protocolType, credential, flow, "")
}

// accountForWithMethod performs the operation represented by its name.
func accountForWithMethod(protocolType xrayruntimev1.Protocol, credential, flow, method string) (protocol.Account, error) {
	var account protocol.Account
	var err error
	switch protocolType {
	case xrayruntimev1.Protocol_PROTOCOL_VLESS:
		if flow != "" && flow != "xtls-rprx-vision" {
			return nil, errors.New("unsupported VLESS flow")
		}
		if !canonicalUUIDPattern.MatchString(credential) {
			return nil, errors.New("invalid UUID credential")
		}
		account, err = (&vless.Account{Id: credential, Flow: flow}).AsAccount()
	case xrayruntimev1.Protocol_PROTOCOL_VMESS:
		if flow != "" {
			return nil, errors.New("VMess does not accept a flow")
		}
		if !canonicalUUIDPattern.MatchString(credential) {
			return nil, errors.New("invalid UUID credential")
		}
		account, err = (&vmess.Account{Id: credential, SecuritySettings: &protocol.SecurityConfig{Type: protocol.SecurityType_AUTO}}).AsAccount()
	case xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2:
		if flow != "" {
			return nil, errors.New("Hysteria 2 does not accept a flow")
		}
		account, err = (&hysteriaaccount.Account{Auth: credential}).AsAccount()
	case xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS:
		if flow != "" {
			return nil, errors.New("Shadowsocks does not accept a flow")
		}
		if method != "2022-blake3-aes-256-gcm" {
			return nil, errors.New("unsupported Shadowsocks method")
		}
		if !validShadowsocks2022UserKey(credential) {
			return nil, errors.New("Shadowsocks 2022 user key must be standard base64 for exactly 32 bytes")
		}
		account, err = (&shadowsocks2022.Account{Key: credential}).AsAccount()
	case xrayruntimev1.Protocol_PROTOCOL_TROJAN:
		if flow != "" {
			return nil, errors.New("Trojan does not accept a flow")
		}
		if strings.TrimSpace(credential) == "" || strings.ContainsAny(credential, "\r\n") {
			return nil, errors.New("invalid Trojan password")
		}
		account, err = (&trojan.Account{Password: credential}).AsAccount()
	default:
		return nil, errors.New("unsupported Xray protocol")
	}
	if err != nil {
		return nil, errors.New("invalid Xray user credential")
	}
	return account, nil
}

// validShadowsocks2022UserKey reports whether credential is a padded
// standard-base64 encoding of the 32-byte per-user PSK used by AES-256-GCM.
func validShadowsocks2022UserKey(credential string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(credential)
	return err == nil && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == credential
}

// Version reports the embedded Xray-core version.
func (e *Engine) Version() string { return core.Version() }

// StatsAvailable reports whether this instance has an in-process stats manager.
func (e *Engine) StatsAvailable() bool {
	if e == nil || e.instance == nil {
		return false
	}
	manager, ok := e.instance.GetFeature(corestats.ManagerType()).(corestats.Manager)
	if !ok || manager == nil {
		return false
	}
	switch manager.(type) {
	case corestats.NoopManager, *corestats.NoopManager:
		return false
	default:
		return true
	}
}

// GetTelemetry collects configured users, cumulative counters, Xray online-map
// addresses, and active source addresses from the lease connection registry.
func (e *Engine) GetTelemetry(ctx context.Context, inboundTags map[xrayruntimev1.Protocol]string) ([]RuntimeUserTelemetry, error) {
	if e == nil || e.instance == nil {
		return nil, errors.New("Xray instance is not initialized")
	}
	statsManager, ok := e.instance.GetFeature(corestats.ManagerType()).(corestats.Manager)
	if !ok || statsManager == nil {
		return nil, errors.New("Xray stats manager is unavailable")
	}
	if !e.StatsAvailable() {
		return nil, errors.New("Xray stats manager is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	usersByEmail := make(map[string]xrayruntimev1.Protocol)
	for protocol, tag := range inboundTags {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		manager, err := e.userManager(ctx, tag)
		if err != nil {
			return nil, fmt.Errorf("read configured inbound users: %w", err)
		}
		for _, user := range manager.GetUsers(ctx) {
			if user != nil && strings.TrimSpace(user.Email) != "" && !strings.EqualFold(strings.TrimSpace(user.Email), domain.ShadowsocksBootstrapUserEmail) {
				current, exists := usersByEmail[user.Email]
				if !exists || telemetryProtocolPriority(protocol) < telemetryProtocolPriority(current) {
					usersByEmail[user.Email] = protocol
				}
			}
		}
	}
	emails := make([]string, 0, len(usersByEmail))
	for email := range usersByEmail {
		emails = append(emails, email)
	}
	sort.Strings(emails)
	result := make([]RuntimeUserTelemetry, 0, len(emails))
	for _, email := range emails {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		user := RuntimeUserTelemetry{Email: email, Protocol: usersByEmail[email], SourceIPs: make([]RuntimeIPObservation, 0)}
		observedByAddress := make(map[string]RuntimeIPObservation)
		for _, observation := range e.leases.observations(user.Protocol, email) {
			observedByAddress[observation.Address] = observation
		}
		if counter := statsManager.GetCounter("user>>>" + email + ">>>traffic>>>uplink"); counter != nil {
			user.UploadBytes = clampNonNegative(counter.Value())
		}
		if counter := statsManager.GetCounter("user>>>" + email + ">>>traffic>>>downlink"); counter != nil {
			user.DownloadBytes = clampNonNegative(counter.Value())
		}
		if onlineMap := statsManager.GetOnlineMap("user>>>" + email + ">>>online"); onlineMap != nil {
			user.Online = onlineMap.Count() > 0
			observed := make([]RuntimeIPObservation, 0, onlineMap.Count())
			onlineMap.ForEach(func(rawAddress string, unixLastSeen int64) bool {
				address, err := netip.ParseAddr(rawAddress)
				if err != nil || unixLastSeen <= 0 {
					return true
				}
				canonical := address.WithZone("").Unmap().String()
				lastSeen := time.Unix(unixLastSeen, 0).UTC()
				observation, exists := observedByAddress[canonical]
				if !exists {
					observation = RuntimeIPObservation{Address: canonical, LastSeen: lastSeen}
				}
				observed = append(observed, observation)
				delete(observedByAddress, canonical)
				if lastSeen.After(user.LastSeen) {
					user.LastSeen = lastSeen
				}
				return true
			})
			for _, observation := range observedByAddress {
				observed = append(observed, observation)
			}
			sort.Slice(observed, func(i, j int) bool { return observed[i].Address < observed[j].Address })
			if len(observed) > maxTelemetrySourceIPs {
				observed = observed[:maxTelemetrySourceIPs]
			}
			user.SourceIPs = observed
		} else {
			for _, observation := range observedByAddress {
				user.SourceIPs = append(user.SourceIPs, observation)
			}
			sort.Slice(user.SourceIPs, func(i, j int) bool { return user.SourceIPs[i].Address < user.SourceIPs[j].Address })
		}
		result = append(result, user)
	}
	return result, nil
}

// telemetryProtocolPriority selects a stable owner when one statistics email
// is configured in multiple inbound protocols. Lease-capable protocols win so
// their connection observations remain visible to source-IP enforcement.
func telemetryProtocolPriority(protocol xrayruntimev1.Protocol) int {
	switch protocol {
	case xrayruntimev1.Protocol_PROTOCOL_VLESS:
		return 0
	case xrayruntimev1.Protocol_PROTOCOL_VMESS:
		return 1
	case xrayruntimev1.Protocol_PROTOCOL_TROJAN:
		return 2
	case xrayruntimev1.Protocol_PROTOCOL_HYSTERIA2:
		return 3
	case xrayruntimev1.Protocol_PROTOCOL_SHADOWSOCKS:
		return 4
	default:
		return 5
	}
}

// ConfiguredProtocols extracts supported protocol names from a validated
// snapshot without retaining or exposing secret-bearing configuration fields.
func ConfiguredProtocols(configuration []byte) ([]string, error) {
	var document struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configuration, &document); err != nil {
		return nil, fmt.Errorf("read Xray inbound protocols: %w", err)
	}
	seen := make(map[string]struct{})
	var result []string
	for _, inbound := range document.Inbounds {
		protocol := inbound.Protocol
		if protocol != "vless" && protocol != "vmess" && protocol != "hysteria" && protocol != "shadowsocks" && protocol != "trojan" {
			continue
		}
		if protocol == "hysteria" {
			protocol = "hysteria2"
		}
		if _, exists := seen[protocol]; exists {
			continue
		}
		seen[protocol] = struct{}{}
		result = append(result, protocol)
	}
	return result, nil
}
