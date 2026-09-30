package domain

import "time"

// XrayRuntimeStatus is the embedded Xray core's health and applied config state.
type XrayRuntimeStatus struct {
	Protocol       string
	XrayVersion    string
	State          string
	LastError      string
	StartedAt      time.Time
	ActiveRevision int64
	InboundTags    []string
	StatsAvailable bool
}
