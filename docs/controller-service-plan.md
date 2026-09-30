# Controller service and gradual runtime migration plan

## Goal

Introduce a private gRPC Controller between the HTTP control plane and the
protocol runtime services. The Controller provides one protocol-neutral runtime
boundary for Xray-based protocols and AmneziaWG, while migrations happen one
operation group at a time without changing the Web UI or public HTTP API.

```text
Web UI --HTTP--> xray-easy control plane --gRPC--> Controller
                                                   |--gRPC--> xray-supervisor / Xray
                                                   `--gRPC--> awg-service / AmneziaWG
```

The control plane remains the source of truth for administrator accounts,
desired device/profile state, settings, audit history, backups, and product
validation. The Controller owns protocol-neutral runtime orchestration,
capability discovery, runtime reconciliation coordination, and normalized
runtime observations. `xray-supervisor` continues to own the Xray child
process and Xray-specific process/config operations. `awg-service` continues
to own the AmneziaWG device, peers, and private client profiles. Neither
runtime adapter accesses the control plane database.

## Architecture decisions

- Controller is an orchestrator and anti-corruption layer, not a generic RPC
  tunnel. It exposes stable operations such as apply desired devices, revoke a
  device, read capabilities/status, and collect telemetry. Engine-specific
  details stay inside protocol adapters.
- The control plane remains authoritative for desired state. It passes stable
  operation IDs to Controller and includes the persisted config revision in
  typed config requests and tracing metadata. The Controller forwards the same
  revision to the Xray supervisor, which rejects stale revisions and
  changed-payload replays.
  Automatic RPC retries remain disabled. No second copy of product state or
  SQLite database is added to Controller.
- During migration, the backend may keep an adapter call for an operation only
  until its Controller route has passed parity tests. A given operation must
  have one active write path at a time; do not dual-write runtime state.
- Xray remains one engine adapter for VLESS, VMess, and Hysteria 2. AmneziaWG
  remains a separate engine adapter. Adding more Xray inbounds does not imply
  adding more containers.
- Use versioned, typed Protobuf messages for every Controller RPC. Generated Go
  sources come from the pinned Buf plugins using
  `scripts/generate-protobuf.sh`; generation tooling is not included in
  runtime images. Keep the internal Xray-supervisor and AWG service contracts
  separately versioned; they are not the Controller API.
- All gRPC listeners stay on private internal Compose networks and are
  unpublished on the host. Each hop authenticates independently using its own
  mounted secret; request correlation metadata is not an authentication
  credential. Do not log request or response bodies.
- Preserve the current backend HTTP routes, SSE event shapes, UI, data files,
  and install flow except for new internal Controller settings/healthchecks.

## Interaction logging and request correlation

Logging is part of the Controller rollout, not an afterthought. Every request
that crosses a service boundary must be diagnosable from logs at the backend,
Controller, and the relevant runtime adapter.

- The backend creates cryptographically random `request_id` and default
  `controller_operation_id` values for each HTTP request that invokes runtime
  behavior. It puts them in request context, returns the request ID in
  `X-Request-ID`, and sends both as gRPC metadata. Durable config mutations
  replace the default operation ID with their persisted `apply_operations.id`
  and attach the associated revision.
- Controller and the runtime adapters validate or replace malformed IDs and
  forward the trace metadata. No automatic RPC retries are enabled. Calls use
  attempt `1`; any future retry must retain the operation ID and increment the
  attempt. The Xray supervisor also enforces the revision fence for config
  mutations; revision values remain correlation metadata on other RPCs.
- Xray supervisor and AWG service include the same correlation fields in their
  structured operation logs. Existing authentication metadata remains
  independent and is never copied into logs.
- Each log record uses JSON to stderr/container logs and includes timestamp,
  service, component, request ID, operation ID when applicable, gRPC method,
  protocol, result, gRPC status code, duration, and retry attempt. Error details
  are bounded and sanitized.
- Never record passwords, TOTP/recovery codes, UUIDs, AWG keys/configs,
  REALITY private keys, TLS private keys, master keys, auth tokens, complete
  profile links/configs, or raw protobuf payloads. Device names/IDs and source
  IPs are omitted by default; a safe opaque device ID may be included only
  after review of the privacy impact.
- Controller logs both its inbound operation and each outbound adapter call,
  so one request ID shows the complete path and identifies the failing layer.
  The backend logs the result returned by Controller, not payloads.
- Add tests that assert correlation propagation and verify representative
  secrets are absent from captured logs. Doctor/support bundles may include
  these logs only after the same redaction review.

## Staged migration

## Implementation status

The current implementation has completed the routing and isolation milestones:

- [x] Backend HTTP request IDs and payload-free Controller client logs.
- [x] Private authenticated Controller service, healthcheck, Docker build, and
  separate `backend` and `control` networks. The backend has no runtime token
  mounts and cannot address Xray/AWG services directly.
- [x] Health, status, logs, probes, Xray Handler/Stats, AmneziaWG status,
  profiles, telemetry, and backup/restore operations route through Controller.
- [x] Xray Handler/Stats calls now pass through `xray-supervisor`, which owns
  those clients and logs the same correlation ID in the Xray container.
- [x] AWG service logs authenticated inbound calls with the same correlation
  ID. No profile or key payloads are recorded.
- [x] Structured logs at the backend, Controller, Xray supervisor, and AWG
  service include request ID, method, protocol, outcome, gRPC status, and
  duration; log bodies and raw errors are excluded.
- [x] Add distinct controller operation IDs, attempt numbers, and config
  revision metadata alongside request ID. Attempt is currently always `1`
  because automatic retries remain disabled.
- [x] Make Xray live user add/remove safe to replay by checking the loaded user
  roster and serializing the roster-check/mutation pair inside the single
  Controller process. Persist AWG create/revoke operation receipts across AWG
  restarts and preserve a pending client key so an interrupted profile write
  can be resumed.
- [x] Attach the persisted apply-operation revision to config validation/apply
  calls and include it in structured logs at each gRPC layer.
- [x] Add durable stale-revision fencing at the Xray supervisor; allocate
  revisions monotonically in SQLite and preserve the high-water mark through
  restore of an older database snapshot. Bind same-operation replay to the
  exact candidate file content.
- [x] Add Controller restart, adapter outage, deadline/cancellation, and
  response-loss integration tests. Automatic RPC retries remain disabled.
- [ ] Validate the full updated stack on a VDS. Local tests, coverage, vet,
  generated-protobuf checks, and Compose validation are handled with the
  implementation; VDS validation remains a manual deployment step.

The checkboxes describe repository state after implementation begins; they do
not replace the full acceptance criteria at the end of this plan.

### Current constraints before automatic RPC retries

- The Controller is deployed as a single service instance. Xray roster-based
  deduplication is serialized within that process; it is not a cross-instance
  durable operation journal.
- AWG operation receipts are retained in `/data/state.json` indefinitely so a
  delayed replay cannot recreate a revoked peer or remove a replacement with
  the same name. The journal grows with create/revoke operations; any future
  compaction policy must preserve the required replay window and be tested
  against backup/restore.
- Config revisions are fenced for Xray config apply and inbound replacement.
  Live user/peer mutations have their own operation replay semantics. Keep
  automatic retries disabled until those semantics are proven for all future
  mutating RPCs.

### 1. Freeze current behavior and define the runtime contract

- Inventory every backend call to `supervisor`, `xrayapi`, and `awgcontrol`,
  including web handlers, background stats/reconciliation, doctor, backup, and
  restore.
- Define versioned protocol-neutral device, desired-state revision,
  capabilities, health, runtime status, telemetry, operation result, and error
  contracts. Specify optional fields and partial-failure behavior explicitly.
- Define idempotency keys and retry rules for create, update, revoke, config
  apply, and reconciliation. Retries must not create duplicate peers/users.
- Add fake-adapter contract tests before adding the network service.

### 2. Add structured interaction logging and correlation IDs

- Add backend HTTP request-ID context/response middleware and gRPC client
  interceptors.
- Add Controller inbound/outbound gRPC logging interceptors and propagate
  correlation metadata.
- Add Xray supervisor and AWG gRPC server interceptors that log method,
  result, duration, and correlation IDs without request content.
- Add redaction tests and ensure authentication failures do not reveal
  credential material.

### 3. Build the Controller service in parallel with existing paths

- Add `cmd/xray-controller`, a private gRPC listener, authenticated backend
  client access, and authenticated clients for the Xray and AWG adapters.
- Implement `Health` and `GetCapabilities`, then runtime status and telemetry
  aggregation. Report an unavailable optional adapter as a partial result;
  do not make Xray-only installations fail because AWG is disabled.
- Add Compose service, healthcheck, control-network address/token setup,
  Docker build, doctor checks, and installer-generated configuration.
- Use fake adapter servers and bufconn for contract, auth, logging, cancellation,
  and partial-failure tests. No public host port is added.

### 4. Migrate read-only operations first

- Route health/readiness, runtime status, version/capabilities, logs, and
  telemetry polling through Controller.
- Keep SQLite persistence, counter accumulation, sampled speed calculation,
  online freshness, and SSE publication in the backend until parity is proven;
  Controller returns normalized observations and capability/availability
  metadata.
- Compare Controller results with current direct adapters in tests and
  temporary shadow diagnostics, without issuing duplicate writes.

### 5. Migrate Xray runtime mutations

- Extend the Xray adapter boundary for Handler API user add/remove/list and
  process/config operations currently called by backend. Prefer exposing these
  through `xray-supervisor`, which already owns the Xray process, rather than
  letting backend call Xray API directly.
- Route VLESS, VMess, and Hysteria 2 profile create/enable/disable/revoke,
  inbound replacement, validation, apply, probes, and reconciliation through
  Controller.
- Controller uses the supervisor API for live add/remove/list-user calls and
  stats polling. The supervisor invokes Xray HandlerService/StatsService from
  inside the Xray container and carries request correlation metadata onward.
- Keep config rendering, short-ID pool bookkeeping, durable device records,
  settings confirmation, audit, and backup creation in backend.
- Preserve rollback behavior and test failure injection at each step.

### 6. Migrate AmneziaWG operations

- Route status, peer list/create/revoke, client profile delivery, peer
  telemetry, and backup export/restore through Controller to `awg-service`.
- Keep AWG private client profiles and keys inside `awg-service`; return a
  profile only for the authenticated delivery call and never retain it in
  Controller logs/state.
- Preserve optional-service semantics and return protocol-specific
  availability/capabilities rather than fabricating missing telemetry.

### 7. Remove direct runtime access from backend

- Remove backend direct gRPC clients to Xray Handler/Stats APIs, supervisor,
  and AWG once every caller has moved.
- Remove obsolete direct-service environment variables, credentials, and
  Compose network permissions. Backend should connect only to Controller for
  runtime operations.
- Attach Controller to both private networks. Attach the backend only to the
  Controller-facing network; do not mount supervisor or AWG credentials in the
  backend container.
- Keep adapter-to-engine access private and least-privileged; Controller does
  not receive host-published ports or data-volume/database mounts.

### 8. Rollout, verification, and documentation

- Update README, architecture docs, `.env.example`, install TUI, doctor,
  troubleshooting, and Compose dependency/health behavior.
- Run root/AWG tests, race tests, per-file coverage gates, web checks, Compose
  validation, and image builds where Docker is available.
- Add failure tests for Controller restart, adapter unavailable, deadline,
  partial telemetry, duplicate operation, retries, and rollback.
- Validate the complete deployment on a VDS after local verification; confirm
  each request ID can be followed in backend, Controller, and Xray/AWG logs.

## Acceptance criteria

- Backend runtime access passes through Controller; no backend direct gRPC
  connection to Xray, supervisor, or AWG remains.
- Controller owns no product database or durable duplicate of desired devices.
- Xray and AmneziaWG operations are idempotent and have explicit partial
  failure semantics; retries do not duplicate users or peers.
- Optional AWG absence does not break Xray-only operation.
- Runtime status and telemetry retain current UI semantics and persistence.
- For a runtime request, the same request ID appears in backend, Controller,
  and the relevant adapter logs, while logs contain no credential/profile
  payloads.
- Public HTTP API, Web UI, SSE contracts, device IDs, and installed user data
  remain compatible throughout migration.
- Final docs and doctor explain Controller health, adapter health, and how to
  trace an operation across all three layers.
