# Xray supervisor gRPC migration plan

> Status: the private Supervisor gRPC migration is complete. Its API now uses
> generated, typed Protobuf messages. The later typed Controller contract is
> separate, and its types do not replace the runtime service contracts.

## Goal

Replace the private HTTP/JSON control channel between `xray-easy` and
`xray-supervisor` with a private gRPC API. Keep the current process ownership,
Xray configuration lifecycle, diagnostics, and user-visible behavior intact.
This is a transport migration; it must not change the control plane's HTTP API
or how the Web UI works.

## Current boundary

`xray-supervisor` owns the Xray child process, validates candidate files, starts
and stops Xray, rolls back failed applies, replaces a single inbound using
Xray's Handler API, probes REALITY targets and outbound IPv6, and retains
redacted process logs. It exposes a typed Protobuf gRPC service on the Docker
`control` network at `172.31.241.2:10086`. The current RPCs are:

| gRPC operation | Existing caller |
| --- | --- |
| `Health` | Compose healthcheck and doctor |
| `GetStatus` | doctor and diagnostics |
| `GetLogs` | diagnostics |
| `ValidateConfig` | configuration preview/apply |
| `ApplyConfig` | configuration apply and restore |
| `ReplaceInbound` | profile reconciliation |
| `ProbeTarget` | initial setup and settings preview |
| `ProbeIPv6` | doctor |

The gRPC client signs the full method name, operation, nonce, and deterministic
Protobuf request hash with HMAC-SHA256. The server compares signatures in
constant time, rejects replayed nonces, enforces message size limits, and masks
secrets in errors and logs. The migration stages below are retained as the
historical implementation plan; the active contract is in
`internal/supervisor/api/v1/supervisor.proto`.

## Target contract and security

- Define `xrayeasy.supervisor.v1.Supervisor` in
  `internal/supervisor/api/v1/supervisor.proto` with explicit messages for all
  requests and responses. Use `int64` for state revisions and traffic
  counters, `Timestamp` for event times, repeated fields for collections,
  and enums for Xray protocols and user actions.
- Generate and check in the Go messages and gRPC client/server with the pinned
  Buf plugins. The Supervisor's generated package is distinct from the
  backend-to-Controller API package.
- Use unary methods `Health`, `GetStatus`, `GetLogs`, `ValidateConfig`,
  `ApplyConfig`, `ReplaceInbound`, `ProbeTarget`, and `ProbeIPv6`.
- Bind the server only to the private Docker control network. Do not publish
  the supervisor port on the host. Use plaintext gRPC inside that isolated
  network, with HMAC-SHA256 metadata authentication; document that HMAC
  authenticates requests but does not encrypt traffic.
- Sign a canonical payload containing the full gRPC method name, operation,
  nonce, and SHA-256 digest of deterministic protobuf request bytes. Send the
  operation, nonce, and hex signature in gRPC metadata. Normal backend calls
  use the `control-plane` operation; the container healthcheck uses
  `healthcheck`. The RPC method allowlist prevents the healthcheck identity
  from invoking state-changing methods.
- Generate a fresh cryptographic nonce for every RPC, reject missing/invalid
  signatures and duplicate nonces, prune expired nonce records, and compare
  signatures in constant time. Load the token from the mounted token file and
  keep the existing restrictive file permissions.
- Apply explicit 24 MiB gRPC receive/send limits to bound large telemetry
  responses while supporting installations with many devices. Propagate RPC cancellation/deadlines into validation, DNS/TLS
  probes, Xray API commands, and process apply where possible.
- Map invalid input, failed preconditions, unavailable Xray, and internal
  failures to stable gRPC status codes. Redact sensitive subprocess output
  before returning status messages or writing logs.

## Implementation stages

### 1. Freeze the behavior and add the contract — complete

- Inventory callers and outputs from the current routes (table above).
- Add the versioned `.proto` contract and generated service registration.
- Specify each typed request and response in the contract and integration
  tests.
- Keep existing `supervisor.Client` methods (`Health`, `Status`, `Logs`,
  `Validate`, `Apply`, `ReplaceInbound`, `ProbeTarget`, `ProbeIPv6`) as the
  control-plane adapter so domain logic does not depend on generated RPC
  details.

### 2. Implement authenticated gRPC on the supervisor — complete

- Convert the HTTP handlers into server RPC methods without changing their
  process operations or safety checks.
- Add a unary server interceptor for HMAC authentication, operation/method
  allowlisting, nonce validation/replay protection, size limits, and safe
  error handling.
- Keep process lifecycle logic independent of transport so tests can exercise
  it directly and through a `bufconn` gRPC connection.
- Add gRPC integration tests for all eight methods, valid/invalid signatures,
  replayed/expired/malformed nonces, cancelled requests, status code mapping,
  redaction, and healthcheck credentials.

### 3. Migrate the backend client — complete

- Replace HTTP request construction/JSON decoding in `internal/supervisor`
  with the versioned gRPC client and signed metadata.
- Preserve the public adapter methods and their existing error behavior where
  callers rely on it; decode status/log payloads strictly.
- Reuse one gRPC connection for the control-plane process lifetime and close
  it in the existing initialization cleanup path. Use `bufconn` for client
  tests; do not open host ports in tests.
- Keep the token file as the only credential source. Do not move the HMAC key
  into environment variables or ordinary application configuration.

### 4. Switch Docker wiring and CLI checks — complete

- Replace `XRAY_SUPERVISOR_URL` with an address setting such as
  `XRAY_SUPERVISOR_ADDR=172.31.241.2:10086` and update install/doctor/docs.
- Change `xray-supervisor healthcheck` from HTTP URL probing to a signed gRPC
  `Health` call using `--addr` and `--token-file`.
- Preserve the private `control` network attachment and keep the port
  unpublished. Update Compose healthcheck and dependencies.
- Remove the HTTP listener, route handlers, and HTTP-only tests after every
  caller has moved to gRPC; avoid retaining two control protocols in the
  shipped service.

### 5. Verify, document, and commit — complete

- Run root Go unit tests, race tests, root coverage gate, AWG coverage gate,
  web lint/typecheck/unit coverage, and Compose config validation.
- Require at least 90% statement coverage for every handwritten Go source file
  in `cmd/xray-supervisor`; maintain the root module gates as well. Add a
  dedicated file-level check so a high package average cannot hide an
  untested supervisor file.
- Add/refresh contract and deployment notes, including the new address
  variable, healthcheck behavior, private-network-only exposure, and migration
  requirements for existing `.env` files.
- Commit the plan before implementation and keep implementation changes in a
  later commit. Do not push unless explicitly requested.

## Protocol-neutral Controller direction (historical)

> Update (2026-09-30): The Controller implementation is now under way and its
> current phases are tracked in [controller-service-plan.md](controller-service-plan.md).
> Xray HandlerService and StatsService calls are being moved into
> `xray-supervisor`, so the Controller uses the supervisor as the Xray runtime
> adapter and correlation IDs are logged inside the Xray container.

The paragraphs below record the original architectural direction and have been
superseded by the Controller plan above.

The proposed end state is:

```text
Web UI -> xray-easy control plane -> Controller gRPC
                                  -> Xray adapter gRPC (xray-supervisor)
                                  -> AmneziaWG adapter gRPC (awg-service)
```

The control plane remains responsible for admin authentication, persistence,
audit, and product-level validation. The Controller becomes responsible for
protocol-neutral runtime orchestration: idempotent apply operations,
reconciliation, rollback sequencing, capability discovery, normalized runtime
status, per-device counters, and active source addresses. Protocol adapters
own engine-specific operations: the supervisor owns the Xray process and its
Handler API; the AWG service owns the AmneziaWG kernel/device lifecycle and
peer operations. Neither adapter should be allowed to write the control
plane's database.

Recommended later Controller stages:

1. Agree on a protocol-neutral device, listener, capability, operation, and
   telemetry contract, including stable opaque device IDs and partial-support
   semantics for source IP/current-speed fields.
2. Extract the current Xray/AWG runtime gateways behind Controller adapters;
   leave UI, REST routes, authentication, and persistence in `xray-easy`.
3. Add a private authenticated Controller gRPC service and integration-test
   it against fake protocol adapters before routing real traffic through it.
4. Migrate one protocol at a time, starting with Xray, then AWG. During each
   migration keep one source of truth for state and avoid dual writes.
5. Remove direct backend-to-engine calls only after parity tests cover apply,
   restore, status, counters, source IP, and failure rollback.

This sequence gives an immediate gRPC supervisor boundary now and a coherent
multi-protocol Controller later, without making the supervisor itself a
protocol-neutral service or creating two competing orchestration owners.

## Реализация этапа supervisor gRPC

Реализация сохраняет прежние операции и использует unary gRPC
`xrayeasy.supervisor.v1.Supervisor` с generated typed Protobuf. Backend
сохраняет адаптерные методы `Health`, `Status`, `Logs`, `Validate`, `Apply`,
`ReplaceInbound`, `ProbeTarget` и `ProbeIPv6`, поэтому control-plane маршруты и
UI не меняются. Счётчики и state revision передаются как `int64`, даты как
`Timestamp`, а протоколы и user actions как enum. Сервер и healthcheck
используют HMAC-контракт над deterministic protobuf bytes; supervisor доступен
только через private Compose network. Из-за изменения wire-формата
`xray-controller` и `xray-supervisor` необходимо обновлять из одного checkout
одновременно.
