package domain

import (
	"errors"
	"regexp"
	"time"
)

var amneziaWGPeerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,32}$`)

// AmneziaWGStatus describes the configured server endpoint without exposing
// key material other than the public server key.
type AmneziaWGStatus struct {
	Running        bool
	PublicKey      string
	ListenPort     int
	PublicHost     string
	PublicPort     int
	PeerCount      int
	IPv4Network    string
	IPv6Network    string
	ServiceVersion string
}

// AmneziaWGPeer is a single device's public identity and assigned addresses.
type AmneziaWGPeer struct {
	Name      string
	PublicKey string
	IPv4      string
	IPv6      string
	CreatedAt time.Time
}

// AmneziaWGPeerStats is the runtime telemetry observable for one peer.
type AmneziaWGPeerStats struct {
	Name          string
	SourceIP      string
	LastSeen      time.Time
	UploadBytes   int64
	DownloadBytes int64
}

// ValidateAmneziaWGPeerName checks the restricted name used in profile paths
// and AmneziaWG UAPI state.
func ValidateAmneziaWGPeerName(name string) error {
	if !amneziaWGPeerNamePattern.MatchString(name) {
		return errors.New("name must contain ASCII letters, digits or '-' and be 1-32 characters")
	}
	return nil
}
