package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	corelog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	xrayserial "github.com/xtls/xray-core/infra/conf/serial"
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
)

func redactXrayLog(message string) string {
	message = ipv4EndpointPattern.ReplaceAllString(message, "[REDACTED-IP]")
	message = bracketedIPv6Pattern.ReplaceAllString(message, "[REDACTED-IP]")
	return strings.TrimSpace(message)
}

// Engine owns the one Xray instance active in this process.
type Engine struct {
	instance *core.Instance
}

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

func parseConfig(configuration []byte) (*core.Config, error) {
	if len(configuration) == 0 {
		return nil, errors.New("Xray configuration is empty")
	}
	config, err := xrayserial.LoadJSONConfig(bytes.NewReader(configuration))
	if err != nil {
		return nil, fmt.Errorf("parse Xray configuration: %w", err)
	}
	return config, nil
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

// Version reports the embedded Xray-core version.
func (e *Engine) Version() string { return core.Version() }

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
