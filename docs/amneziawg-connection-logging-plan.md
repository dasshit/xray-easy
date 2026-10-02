# AmneziaWG connection event logging plan

## Current behavior

`amneziawg-service` logs gRPC calls and peer lifecycle mutations such as
`peer_added` and `peer_removed`. `WatchPeerStats` polls the live UAPI snapshot
while Controller has an open telemetry stream and derives online status from
counter growth and a 15-second activity window.

Connection logging is now independent of that stream: a cancellable background
monitor starts with the gRPC service, samples peer telemetry once per second,
and logs transitions. The Web UI telemetry stream continues to serve live
status independently.

## Implementation

1. Run a background telemetry monitor from the service lifecycle. Emit one
   structured `slog` event per online/offline transition. Include peer name,
   transition, source address when available, and reason. Never log keys,
   profiles, or byte counters.
2. Keep the existing 15-second online semantics. Clear cached state when a peer
   disappears from the live snapshot, without reporting administrative removal
   as a client disconnect. Preserve the telemetry stream payload and Controller
   behavior.
3. Test that transitions are logged without an open telemetry stream, repeated
   polling does not duplicate events, and the monitor stops on cancellation.
4. Run AWG module tests, race tests, vet, and the repository test suite.

## Log fields

Records use the message `AWG connection event`, `component=connection`,
`event=peer_online` or `peer_offline`, and `peer_name=<name>`. `source_ip` is
included when the peer endpoint is known. The background monitor remains
active until the service shuts down.
