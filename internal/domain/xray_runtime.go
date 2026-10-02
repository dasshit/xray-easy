package domain

import "time"

// XrayRuntimeStatus is the embedded Xray core's health and applied config state.
type XrayRuntimeStatus struct {
	// Protocol is the protocol associated with the object.
	Protocol string
	// XrayVersion contains the XrayVersion value for this object.
	XrayVersion string
	// State is the current operation state.
	State string
	// LastError contains the LastError value for this object.
	LastError string
	// StartedAt contains the StartedAt value for this object.
	StartedAt time.Time
	// ActiveRevision contains the ActiveRevision value for this object.
	ActiveRevision int64
	// InboundTags contains the InboundTags value for this object.
	InboundTags []string
	// StatsAvailable contains the StatsAvailable value for this object.
	StatsAvailable bool
}
