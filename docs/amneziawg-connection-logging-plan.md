# AmneziaWG connection event logging plan

## Current state

- `awg-service` logs gRPC calls and peer lifecycle mutations (`peer_added` and
  `peer_removed`).
- `WatchPeerStats` polls the live UAPI snapshot while Controller has an open
  telemetry stream. It derives `online` from counter growth and a 15-second
  activity window, but does not log state transitions.
- Consequently, a successful client handshake is visible only through the
  telemetry response consumed by Controller, not in the `amneziawg-service`
  container log. No connection transition can be observed when the telemetry
  stream is not connected.

## Implementation steps

1. Add a service-level peer state cache used by telemetry watchers to emit one
   structured `slog` event per online/offline transition. Include the peer
   name, transition, source address when available, and the reason. Do not log
   keys, profiles, or byte counters.
2. Keep the existing 15-second semantics and clear cached state when a peer is
   removed from the live snapshot. Preserve the existing stream payload and
   Controller behavior.
3. Add unit coverage for online and offline transitions, duplicate suppression,
   source address handling, and stream cancellation. Capture JSON logs in the
   test instead of relying on container output.
4. Run the AWG module tests, race tests, vet, and the repository test suite.

## Operational result

The service will emit structured records such as `AWG connection event` with
`component=connection`, `event=peer_online` or `peer_offline`, and
`peer_name=<name>`. These records appear only while `WatchPeerStats` is active;
the stream is opened by Controller when the Web UI SSE pipeline is active.
