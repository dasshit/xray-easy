package control

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PeerTelemetry is a non-secret runtime view of one AmneziaWG peer.
type PeerTelemetry struct {
	// Name is the human-readable name of the object.
	Name string
	// PublicKey is the public key associated with the object.
	PublicKey string
	// SourceIP is the source IP address observed for the client.
	SourceIP string
	// LastHandshake is the last observed WireGuard handshake time.
	LastHandshake time.Time
	// UploadBytes is the observed upload byte count.
	UploadBytes int64
	// DownloadBytes is the observed download byte count.
	DownloadBytes int64
}

// ParsePeerTelemetry parses the public per-peer records returned by the
// AmneziaWG engine's UAPI snapshot. Private keys and unrelated device fields
// are deliberately ignored.
func ParsePeerTelemetry(snapshot string) ([]PeerTelemetry, error) {
	var result []PeerTelemetry
	var current *PeerTelemetry
	var handshakeSeconds, handshakeNanos int64
	flush := func() {
		if current == nil {
			return
		}
		if handshakeSeconds > 0 && handshakeNanos >= 0 && handshakeNanos < int64(time.Second) {
			current.LastHandshake = time.Unix(handshakeSeconds, handshakeNanos).UTC()
		}
		result = append(result, *current)
		current = nil
		handshakeSeconds, handshakeNanos = 0, 0
	}
	for _, line := range strings.Split(snapshot, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			flush()
			if value == "" {
				return nil, fmt.Errorf("AWG UAPI peer has an empty public key")
			}
			publicKey, err := hex.DecodeString(value)
			if err != nil || len(publicKey) != 32 {
				return nil, fmt.Errorf("invalid AWG UAPI peer public key %q", value)
			}
			// The engine's UAPI serializes keys as lowercase hex, while the
			// persisted peer model and service API use standard base64. Normalize
			// here so PeerTelemetry can join live records to managed peers.
			current = &PeerTelemetry{PublicKey: base64.StdEncoding.EncodeToString(publicKey)}
			continue
		}
		if current == nil {
			continue
		}
		switch key {
		case "endpoint":
			current.SourceIP = endpointIP(value)
		case "last_handshake_time_sec":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 {
				return nil, fmt.Errorf("invalid AWG peer handshake seconds %q", value)
			}
			handshakeSeconds = number
		case "last_handshake_time_nsec":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 || number >= int64(time.Second) {
				return nil, fmt.Errorf("invalid AWG peer handshake nanoseconds %q", value)
			}
			handshakeNanos = number
		case "rx_bytes":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 {
				return nil, fmt.Errorf("invalid AWG peer rx_bytes %q", value)
			}
			current.UploadBytes = number
		case "tx_bytes":
			number, err := strconv.ParseInt(value, 10, 64)
			if err != nil || number < 0 {
				return nil, fmt.Errorf("invalid AWG peer tx_bytes %q", value)
			}
			current.DownloadBytes = number
		}
	}
	flush()
	return result, nil
}

// endpointIP performs the operation represented by its name.
func endpointIP(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return ""
	}
	return address.WithZone("").String()
}
