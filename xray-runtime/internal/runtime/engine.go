package runtime

import (
	"bytes"
	"context"
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
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/protobuf/proto"
	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
	_ "xray-easy/xray-runtime/internal/xrayregistration"
)

type capturedXrayLog struct {
	write func(level, component, message string)
}

func (h capturedXrayLog) Handle(message corelog.Message) {
	general, ok := message.(*corelog.GeneralMessage)
	if !ok || h.write == nil {
		return
	}
	level := ""
	switch general.Severity {
	case corelog.Severity_Error:
		level = "error"
	case corelog.Severity_Warning:
		level = "warn"
	default:
		return
	}
	h.write(level, "xray", redactXrayLog(fmt.Sprint(general.Content)))
}

var (
	ipv4EndpointPattern  = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b`)
	bracketedIPv6Pattern = regexp.MustCompile(`\[[0-9a-fA-F:]+\](?::[0-9]{1,5})?`)
	canonicalUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	runtimeExecutable    = os.Executable
)

const isolatedValidationTimeout = 20 * time.Second

const maxTelemetrySourceIPs = 32

func redactXrayLog(message string) string {
	message = ipv4EndpointPattern.ReplaceAllString(message, "[REDACTED-IP]")
	message = bracketedIPv6Pattern.ReplaceAllString(message, "[REDACTED-IP]")
	return strings.TrimSpace(message)
}

// Engine owns the one Xray instance active in this process.
type Engine struct {
	instance *core.Instance
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
	return &Engine{instance: instance}, nil
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

func parseConfig(configuration []byte) (*core.Config, error) {
	if len(configuration) == 0 {
		return nil, errors.New("Xray configuration is empty")
	}
	configuration, err := stripExternalAPIServer(configuration)
	if err != nil {
		return nil, fmt.Errorf("remove external Xray API server: %w", err)
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
	manager, err := e.userManager(ctx, tag)
	if err != nil {
		return false, err
	}
	account, err := accountFor(protocolType, credential, flow)
	if err != nil {
		return false, err
	}
	for _, existing := range manager.GetUsers(ctx) {
		if existing.Email != email {
			continue
		}
		if sameAccount(existing.Account, account) {
			return true, nil
		}
		return false, errors.New("Xray user email already exists with a different credential")
	}
	if err := manager.AddUser(ctx, &protocol.MemoryUser{Email: email, Account: account}); err != nil {
		return false, err
	}
	return false, nil
}

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
		emails = append(emails, user.Email)
	}
	sort.Strings(emails)
	return emails, nil
}

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

func accountFor(protocolType xrayruntimev1.Protocol, credential, flow string) (protocol.Account, error) {
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
	default:
		return nil, errors.New("unsupported Xray protocol")
	}
	if err != nil {
		return nil, errors.New("invalid Xray user credential")
	}
	return account, nil
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

// GetTelemetry collects configured user roster, cumulative counters, and
// currently tracked source addresses through Xray's in-process stats feature.
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
	usersByEmail := make(map[string]struct{})
	for _, tag := range inboundTags {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		manager, err := e.userManager(ctx, tag)
		if err != nil {
			return nil, fmt.Errorf("read configured inbound users: %w", err)
		}
		for _, user := range manager.GetUsers(ctx) {
			if user != nil && strings.TrimSpace(user.Email) != "" {
				usersByEmail[user.Email] = struct{}{}
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
		user := RuntimeUserTelemetry{Email: email, SourceIPs: make([]RuntimeIPObservation, 0)}
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
				observed = append(observed, RuntimeIPObservation{Address: canonical, LastSeen: lastSeen})
				if lastSeen.After(user.LastSeen) {
					user.LastSeen = lastSeen
				}
				return true
			})
			sort.Slice(observed, func(i, j int) bool { return observed[i].Address < observed[j].Address })
			if len(observed) > maxTelemetrySourceIPs {
				observed = observed[:maxTelemetrySourceIPs]
			}
			user.SourceIPs = observed
		}
		result = append(result, user)
	}
	return result, nil
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
		if protocol != "vless" && protocol != "vmess" && protocol != "hysteria" {
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
