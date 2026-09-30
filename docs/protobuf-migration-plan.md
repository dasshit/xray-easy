# Protobuf migration plan: Supervisor and AmneziaWG

> Историческая часть про Supervisor завершена и удалена после VDS-приёмки
> встроенного Xray runtime. Общий Controller/AWG protobuf контракт остаётся;
> текущее состояние runtime описано в [`xray-runtime-service-plan.md`](xray-runtime-service-plan.md).

## Goal

Replace dynamic `google.protobuf.Struct` payloads in the private gRPC links to
`xray-supervisor` and `awg-service` with versioned, typed Protocol Buffers
contracts. Keep the existing process/container boundaries, authentication,
request tracing, revision fencing, and application/domain APIs unchanged.

## Baseline before migration

- The Supervisor `.proto` contract originally existed at
  `internal/supervisor/api/v1/supervisor.proto`, but almost every request and
  response is still `google.protobuf.Struct`. Its gRPC service descriptor is
  hand-written, and clients manually decode field names and types.
- The AWG `.proto` contract originally existed at `awg-service/api/v1/control.proto`, but
  every method uses `Struct`; the service descriptor is also hand-written.
  Both the Controller-side gateway and AWG CLI manually construct and decode
  maps.
- The backend-to-Controller API is already generated and typed. This work does
  not change that public-to-the-project internal contract.

The migration stages below record the implementation status; the AWG contract
now lives in the shared `awg-contract` module and both runtime links use typed
protobuf messages.

## Compatibility and rollout

Typed messages change the protobuf wire shape while retaining the existing
service and method names. Old and new binaries are therefore not wire
compatible. The two images on either side of a migrated link must be rebuilt
and upgraded together:

1. Supervisor migration: `xray-controller` and `xray-supervisor`.
2. AWG migration: `xray-controller` and `awg-service` (when AWG is enabled).

No dual `Struct`/typed fallback will be added. The services communicate only on
the private Compose network, and the project builds its images from one source
revision. Keep the service package/version at `v1`; these are initial typed
contracts, not a change to the established method semantics. Document the
required coordinated rebuild in the repository deployment notes.

## Stages and commits

### Stage 0 — Record migration plan — complete

- Document current dynamic contracts, migration boundaries, rollout
  compatibility, typed data choices, and validation gates.
- Commit: `docs: plan typed protobuf migration for runtime services`.

### Stage 1 — Type the Xray Supervisor API — complete

- Replace `Struct` method payloads in the Supervisor `.proto` with explicit
  messages. Use `int64` for config state revisions and byte counters,
  `Timestamp` for times, repeated strings/messages for collections, and enums
  for Xray protocol and user action values.
- Generate and commit Go protobuf and gRPC bindings. Replace the hand-written
  service descriptor with generated registration and typed server/client
  methods.
- Preserve HMAC authentication over deterministic protobuf serialization;
  update its tests to verify typed request signing and server authorization.
- Move validation to typed request fields and retain existing gRPC status-code
  behavior for missing/unsupported values and runtime failures.
- Convert Xray runtime stats directly to typed messages. Remove string-encoded
  counters, timestamp parsing, and dynamic map conversion from the Supervisor
  client path.
- Add/update transport and adapter tests; run root-module tests, race tests for
  the supervisor/controller path, `go vet`, the root 90% handwritten coverage
  gate, and the per-file Supervisor 90% coverage gate.
- Commit: `refactor: use typed protobuf for xray supervisor`.

### Stage 2 — Type the AmneziaWG service API

- [x] Replace the dynamic AWG schema with typed request/response messages and
  checked-in generated Go stubs in a lightweight shared module.
- [x] Move the backend gateway, AWG service and CLI RPC transport to the
  generated typed contract, retaining auth, trace metadata and safe logging.
- [x] Change backup transport to raw protobuf `bytes` and counters/timestamps
  to `int64`/`Timestamp`; update Docker build and user-facing contract docs.
- [x] Verify both modules, tests, race detector, vet and coverage gates before
  committing this stage independently.
- Commit: `refactor: use typed protobuf for amneziawg service`.

## Acceptance criteria

- No runtime method on either private service accepts or returns
  `google.protobuf.Struct`.
- Generated gRPC clients and servers are used for both services; no custom
  method descriptors remain for these contracts.
- Large byte counters preserve full `int64` precision and backup archives do
  not pass through base64 at the RPC layer.
- Authentication, request IDs, operation IDs, state revisions, service
  behavior, and user-facing JSON/domain models remain intact.
- Each stage is independently reviewable and committed; all relevant test,
  static-analysis, and coverage gates pass before its commit.
