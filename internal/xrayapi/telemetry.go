package xrayapi

import "time"

// UserStats is the control plane representation of a protocol user's traffic
// and connection telemetry, independent of the Xray protobuf wire format.
type UserStats struct {
	Email         string
	Protocol      string
	UploadBytes   int64
	DownloadBytes int64
	LastSeen      time.Time
	SourceIPs     []IPObservation
}

// IPObservation records a client source address and its latest observed time.
type IPObservation struct {
	Address  string
	LastSeen time.Time
}
