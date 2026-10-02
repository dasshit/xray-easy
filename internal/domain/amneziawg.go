// Package domain defines protocol-independent entities and validation rules for Xray-easy.
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
	// Running contains the Running value for this object.
	Running bool
	// PublicKey is the public key associated with the object.
	PublicKey string
	// ListenPort is the AmneziaWG listen port.
	ListenPort int
	// PublicHost is the public DNS name or IP address advertised to clients.
	PublicHost string
	// PublicPort is the public listener port advertised to clients.
	PublicPort int
	// PeerCount contains the PeerCount value for this object.
	PeerCount int
	// IPv4Network contains the IPv4Network value for this object.
	IPv4Network string
	// IPv6Network contains the IPv6Network value for this object.
	IPv6Network string
	// ServiceVersion contains the ServiceVersion value for this object.
	ServiceVersion string
}

// AmneziaWGPeer is a single device's public identity and assigned addresses.
type AmneziaWGPeer struct {
	// Name is the human-readable name of the object.
	Name string
	// PublicKey is the public key associated with the object.
	PublicKey string
	// IPv4 is the assigned IPv4 address.
	IPv4 string
	// IPv6 is the assigned IPv6 address.
	IPv6 string
	// CreatedAt is the time the object was created.
	CreatedAt time.Time
}

// AmneziaWGPeerStats is the runtime telemetry observable for one peer.
type AmneziaWGPeerStats struct {
	// Name is the human-readable name of the object.
	Name string
	// SourceIP is the source IP address observed for the client.
	SourceIP string
	// LastSeen is the last time the runtime observed traffic.
	LastSeen time.Time
	// UploadBytes is the observed upload byte count.
	UploadBytes int64
	// DownloadBytes is the observed download byte count.
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
