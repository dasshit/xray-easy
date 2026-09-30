# Xray supervisor gRPC migration plan

> Scope note: this document tracks the private Xray-supervisor gRPC contract,
> which currently uses validated `google.protobuf.Struct` messages. The
> separate backend ↔ Controller contract is now generated, typed Protobuf;
> Controller typing does not automatically change the supervisor contract.

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
redacted process logs. It currently exposes these private HTTP routes on the
Docker `control` network at `172.31.241.2:10086`:

| HTTP route | Existing caller | gRPC operation |
| --- | --- | --- |
| `GET /health` | Compose healthcheck and doctor | `Health` |
| `GET /status` | doctor and diagnostics | `GetStatus` |
| `GET /logs` | diagnostics | `GetLogs` |
| `POST /validate` | configuration preview/apply | `ValidateConfig` |
| `POST /apply` | configuration apply and restore | `ApplyConfig` |
| `POST /replace-inbound` | profile reconciliation | `ReplaceInbound` |
| `POST /probe-target` | initial setup and settings preview | `ProbeTarget` |
| `GET /probe-ipv6` | doctor | `ProbeIPv6` |

The existing HTTP client signs method, path, operation, nonce, and request-body
hash with HMAC-SHA256. The server compares signatures in constant time, rejects
replayed nonces, accepts a bounded body, and masks secrets in errors/logs. The
new transport must retain those properties.

## Target contract and security

- Define `xrayeasy.supervisor.v1.Supervisor` in
  `internal/supervisor/api/v1/supervisor.proto`.
- For the first migration, use `google.protobuf.Struct` request/response
  messages, following the existing private AWG gRPC convention. Keep Go-side
  request and response conversion helpers strict: required strings, integer
  ranges, timestamp formats, and unexpected fields are validated explicitly.
  This avoids a generated-code toolchain change while keeping the wire format
  protobuf/gRPC interoperable. Promote frequently reused payloads to typed
  messages when the protocol-neutral Controller contract is designed.
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

### 1. Freeze the behavior and add the contract

- Inventory callers and outputs from the current routes (table above).
- Add the versioned `.proto` contract and the manually registered Go service
  descriptor used by this repository's AWG service pattern.
- Specify each Struct field and response field in package documentation/tests.
- Keep existing `supervisor.Client` methods (`Health`, `Status`, `Logs`,
  `Validate`, `Apply`, `ReplaceInbound`, `ProbeTarget`, `ProbeIPv6`) as the
  control-plane adapter so domain logic does not depend on generated RPC
  details.

### 2. Implement authenticated gRPC on the supervisor

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

### 3. Migrate the backend client

- Replace HTTP request construction/JSON decoding in `internal/supervisor`
  with the versioned gRPC client and signed metadata.
- Preserve the public adapter methods and their existing error behavior where
  callers rely on it; decode status/log payloads strictly.
- Reuse one gRPC connection for the control-plane process lifetime and close
  it in the existing initialization cleanup path. Use `bufconn` for client
  tests; do not open host ports in tests.
- Keep the token file as the only credential source. Do not move the HMAC key
  into environment variables or ordinary application configuration.

### 4. Switch Docker wiring and CLI checks

- Replace `XRAY_SUPERVISOR_URL` with an address setting such as
  `XRAY_SUPERVISOR_ADDR=172.31.241.2:10086` and update install/doctor/docs.
- Change `xray-supervisor healthcheck` from HTTP URL probing to a signed gRPC
  `Health` call using `--addr` and `--token-file`.
- Preserve the private `control` network attachment and keep the port
  unpublished. Update Compose healthcheck and dependencies.
- Remove the HTTP listener, route handlers, and HTTP-only tests after every
  caller has moved to gRPC; avoid retaining two control protocols in the
  shipped service.

### 5. Verify, document, and commit

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

Реализация сохраняет прежние операции и переводит transport на unary gRPC
`xrayeasy.supervisor.v1.Supervisor`. Backend сохраняет адаптерные методы
`Health`, `Status`, `Logs`, `Validate`, `Apply`, `ReplaceInbound`, `ProbeTarget`
и `ProbeIPv6`, поэтому control-plane маршруты и UI не меняются. Сервер и
healthcheck используют общий HMAC-контракт; supervisor доступен только через
private Compose network. Документированный Controller остаётся последующим
этапом, пока его протокольно-нейтральный контракт и границы владения runtime
не согласованы.
