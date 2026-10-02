package runtime

import (
	"encoding/json"
	"time"

	xrayruntimev1 "xray-easy/internal/xrayruntime/api/v1"
)

// RuntimeIPObservation describes a currently tracked client address. The Xray
// online map drops the address when its last connection closes, so callers
// must not treat this as historical source-IP data.
type RuntimeIPObservation struct {
	// Address is the endpoint address observed by the runtime.
	Address string
	// LastSeen is the last time the runtime observed traffic.
	LastSeen time.Time
}

// RuntimeUserTelemetry combines a configured-user roster entry with whatever
// live counters and online observations Xray currently exposes for it.
type RuntimeUserTelemetry struct {
	// Email is the Xray statistics identity for the profile.
	Email string
	// Protocol is the protocol associated with the object.
	Protocol xrayruntimev1.Protocol
	// UploadBytes is the observed upload byte count.
	UploadBytes int64
	// DownloadBytes is the observed download byte count.
	DownloadBytes int64
	// Online is whether the client is currently online.
	Online bool
	// LastSeen is the last time the runtime observed traffic.
	LastSeen time.Time
	// SourceIPs is the source IP observations associated with the client.
	SourceIPs []RuntimeIPObservation
}

type telemetryCapabilities struct {
	trafficCounters bool
	onlineStatus    bool
	sourceIP        bool
}

func clampNonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

// telemetryCapabilitiesFor reads only the Xray stats and level-0 user policy
// flags used by Xray-easy. Every generated user currently runs at level 0.
func telemetryCapabilitiesFor(configuration []byte, statsAvailable bool) telemetryCapabilities {
	if !statsAvailable {
		return telemetryCapabilities{}
	}
	var document struct {
		Stats  json.RawMessage `json:"stats"`
		Policy struct {
			Levels map[string]json.RawMessage `json:"levels"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(configuration, &document); err != nil || !isJSONStatsObject(document.Stats) {
		return telemetryCapabilities{}
	}
	level := document.Policy.Levels["0"]
	if len(level) == 0 {
		return telemetryCapabilities{}
	}
	var flags struct {
		Uplink   bool `json:"statsUserUplink"`
		Downlink bool `json:"statsUserDownlink"`
		Online   bool `json:"statsUserOnline"`
	}
	if err := json.Unmarshal(level, &flags); err != nil {
		return telemetryCapabilities{}
	}
	return telemetryCapabilities{
		trafficCounters: flags.Uplink && flags.Downlink,
		onlineStatus:    flags.Online,
		sourceIP:        flags.Online,
	}
}

func isJSONStatsObject(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) == nil && object != nil
}
