package xrayapi

import "time"

// UserStats is the control plane representation of a protocol user's traffic
// and connection telemetry, independent of the Xray protobuf wire format.
type UserStats struct {
	// Email is the Xray statistics identity for the profile.
	Email string
	// Protocol is the protocol associated with the object.
	Protocol string
	// UploadBytes is the observed upload byte count.
	UploadBytes int64
	// DownloadBytes is the observed download byte count.
	DownloadBytes int64
	// LastSeen is the last time the runtime observed traffic.
	LastSeen time.Time
	// SourceIPs is the source IP observations associated with the client.
	SourceIPs []IPObservation
}

// IPObservation records a client source address and its latest observed time.
type IPObservation struct {
	// Address is the endpoint address observed by the runtime.
	Address string
	// LastSeen is the last time the runtime observed traffic.
	LastSeen time.Time
}
