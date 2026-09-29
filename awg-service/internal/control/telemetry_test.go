package control

import (
	"testing"
	"time"
)

func TestParsePeerTelemetryMapsUAPIFields(t *testing.T) {
	rows, err := ParsePeerTelemetry("private_key=ignored\n\npublic_key=peer-one\nendpoint=[2001:db8::5]:51820\nlast_handshake_time_sec=1790798400\nlast_handshake_time_nsec=123000000\nrx_bytes=345\ntx_bytes=678\n\npublic_key=peer-two\nendpoint=192.0.2.10:12345\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=0\ntx_bytes=0\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("parsed peers = %+v", rows)
	}
	first := rows[0]
	if first.PublicKey != "peer-one" || first.SourceIP != "2001:db8::5" || first.UploadBytes != 345 || first.DownloadBytes != 678 || first.LastHandshake.IsZero() {
		t.Fatalf("first telemetry = %+v", first)
	}
	if got := first.LastHandshake.Location(); got != time.UTC {
		t.Fatalf("handshake timezone = %v, want UTC", got)
	}
	second := rows[1]
	if second.PublicKey != "peer-two" || second.SourceIP != "192.0.2.10" || !second.LastHandshake.IsZero() {
		t.Fatalf("second telemetry = %+v", second)
	}
}

func TestParsePeerTelemetryRejectsInvalidCounters(t *testing.T) {
	for _, snapshot := range []string{
		"public_key=peer\nrx_bytes=-1\n",
		"public_key=peer\nlast_handshake_time_nsec=1000000000\n",
		"public_key=\n",
	} {
		if _, err := ParsePeerTelemetry(snapshot); err == nil {
			t.Errorf("ParsePeerTelemetry(%q) succeeded", snapshot)
		}
	}
}
