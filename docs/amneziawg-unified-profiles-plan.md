# Unified AmneziaWG profiles and connection telemetry

## Goal

Make AmneziaWG a first-class option in the existing profile workflow, while
keeping its tunnel engine and private client configurations inside the AWG
service container. Show connection state, last seen, cumulative traffic, source
IP when observable, and sampled current upload/download rates for all supported
profile types.

## Architecture decisions

- AmneziaWG peers remain owned by the AWG service and are not copied into the
  Xray client table. The control plane composes both sources into one profile
  list using namespaced IDs (`awg:<peer-name>`); Xray IDs remain unchanged.
- The shared create/profile/revoke UI and API dispatch by protocol. AWG still
  uses its authenticated private gRPC API for peer lifecycle and profile
  delivery. Existing transport-specific endpoints remain available for
  compatibility and settings/diagnostics.
- AWG private client configurations and private keys never enter the control
  plane database, shared profile DTO, logs, or SSE payloads.
- Xray telemetry comes from StatsService user statistics. AWG telemetry comes
  from the engine's UAPI peer snapshot (`endpoint`, handshake timestamp, rx/tx
  counters). A source IP is shown only when the corresponding protocol reports
  a recent endpoint/IP.
- Current rates are sampled average bytes per second between successful polls,
  not configured throughput limits. Rates are zero when offline, when counters
  reset, or when the polling gap is too large to describe current use reliably.
- Cumulative AWG counters are checkpointed in a dedicated SQLite table and
  survive app/AWG process restarts. Xray keeps using its existing durable
  snapshots. Revoking an AWG peer removes its traffic checkpoint.
- The AWG enabled/disabled distinction is not added in this change: the AWG
  service currently supports create and revoke, but not reversible disable.
  The unified card therefore offers profile display and revoke, without an
  enable/disable control that would misrepresent behavior.

## Phases

### 1. Contracts and profile identity

- Add `amneziawg` to the backend and frontend protocol enums and API validators.
- Define the namespaced ID format and ensure it cannot collide with Xray IDs.
- Compose Xray clients and available AWG peers in authenticated `GET /api/clients`.
- Dispatch `POST /api/clients` by protocol; validate AWG's stricter 1–32
  character peer name and service availability before creating a peer.
- Route shared profile delivery and revoke actions to the existing AWG service
  methods. Preserve authenticated, no-store handling for profile/QR output and
  existing automatic backup/audit behavior on revoke.
- Remove the separate AmneziaWG tab and panel. Keep API compatibility for
  existing profile URLs and transport status operations.

### 2. AmneziaWG runtime telemetry

- Parse per-peer UAPI snapshots without exposing key material. Map `rx_bytes` to
  client upload and `tx_bytes` to client download; map the endpoint host to the
  source IP and convert the last handshake timestamp to UTC.
- Treat a peer as online when its handshake is within the same five-minute
  freshness window used for Xray users.
- Extend the authenticated AWG gRPC peer-list response and Go gateway parser
  with telemetry fields; keep fields optional for compatibility with older
  responses and fakes.
- Add an AWG traffic checkpoint table keyed by peer name, counter-reset-safe
  cumulative totals, last handshake, last source IP, and last poll timestamp.
- Remove checkpoints when a peer is revoked; preserve them through process
  restart and normal peer updates.

### 3. Unified statistics and source IPs

- Keep Xray's current StatsService polling and extract each user's fresh IP
  observations instead of discarding them in the adapter.
- Poll AWG peers alongside Xray without making Xray stats fail when AWG is
  disabled or temporarily unavailable.
- Publish one keyed snapshot for the common UI with online, last seen, source IP
  list, cumulative upload/download bytes, and sampled upload/download bytes per
  second.
- Use bounded polling gaps and counter-reset detection; do not report stale
  rates as live usage.
- Include both transports in the existing authenticated SSE stats event.

### 4. Unified profile UI and AmneziaWG settings

- Add AmneziaWG to the common create-profile modal, gated by AWG availability.
- Reuse the common profile list, status, last-seen, traffic, profile-delivery,
  and confirmation patterns. For AWG show QR/config download, source IP, and
  revoke; do not offer unsupported enable/disable actions.
- Add live upload/download rate and observed source IP(s) to every card. Keep
  cumulative totals and last-seen visible.
- Remove the separate AmneziaWG section and panel from navigation.
- Add a read-only AmneziaWG Settings card showing availability, public host and
  UDP port, listen port, tunnel networks, peer count, public server key, and
  service version. Do not expose obfuscation secrets or private keys.
- Add Russian and English strings and accessible empty/loading/unavailable
  states.

### 5. Verification and documentation

- Add unit tests for Xray IP extraction, AWG UAPI parsing, counter accumulation,
  online freshness, rate calculation, profile list composition, protocol
  dispatch, AWG delivery/revoke, and optional AWG failure behavior.
- Add frontend tests for protocol selection, unified device presentation,
  AmneziaWG QR/download/revoke, rate/source rendering, and read-only settings.
- Run backend unit tests and coverage, AWG service tests, frontend tests,
  TypeScript, ESLint, and production build. Compare coverage with the starting
  revision because the repository's configured gates may already be unmet; do
  not count an existing deficit as a regression from this work. Build the Docker
  Compose images when the local Docker daemon is available; no VDS runtime check
  is part of this change.
- Update README and AWG service documentation to describe the unified profile
  workflow, the metric meanings and sampling interval, source-IP limitations,
  and which runtime checks still require the user's VDS.

## Acceptance criteria

- All four protocols are selectable from one profile creation modal and appear
  in the same profile list.
- AmneziaWG creation, QR/config delivery, and revocation work through the shared
  profile workflow; private client material stays in the AWG service.
- AmneziaWG shows online/offline, last seen, cumulative upload/download, and
  sampled current upload/download use.
- VLESS, VMess, and Hysteria 2 show available current source IPs; AmneziaWG
  shows the latest observed endpoint IP. Missing/unsupported IP telemetry is
  rendered as unavailable, not guessed.
- Current speeds update through SSE and are not presented as configured link
  capacity.
- Settings shows the active AmneziaWG listener/network state without mutating
  it; no separate AmneziaWG navigation section remains.
- Backend and AWG unit tests, frontend tests, TypeScript, ESLint, and production
  build pass. Coverage is compared with the starting revision and any
  pre-existing gate failures are documented. Changes are committed and pushed.
  VDS verification remains a separate manual step after deployment.

## Implementation verification

- Root and AWG service Go unit tests pass; `go vet` passes for both modules.
- Web typecheck, ESLint, all 118 tests, and the production build pass.
- Handwritten Go statement coverage remains 82.4%, equal to the starting
  revision. The configured 90% overall gate and 80% package gate already failed
  at the starting revision (`internal/hysteria` 34.7%, `internal/store` 73.9%).
  This change adds coverage for the new AWG persistence and raises
  `internal/store` to 74.6%; the new `internal/stats` code is at 93.1%.
- Compose configuration validates with a non-secret placeholder master key.
  Local image build and container runtime checks could not run because the
  sandbox cannot access the Docker daemon socket. No VDS test has been run as
  part of this implementation.
