# Controller reliability and typed RPC plan

## Scope and order

Keep the implementation in this order. Do not enable automatic gRPC retries as
part of this work.

### 1. Failure-oriented integration tests

1. Add a reusable gRPC integration harness that uses the production Controller
   registration, auth/logging interceptors, backend client, and fake protocol
   adapters. Keep it hermetic with `bufconn` or loopback listeners; do not
   depend on a running VDS or external network.
2. Cover Controller stop/restart while the backend client remains alive,
   unavailable Xray, disabled/unavailable AWG, and request deadlines/cancelled
   adapter calls. Assert gRPC status codes, recovery after restart, and that
   unavailable optional AWG does not affect Xray operations.
3. Inject a response-loss boundary after runtime mutation. Retry the same
   operation ID and assert that Xray users and AWG peers are not duplicated or
   incorrectly revoked. Include AWG service restart in the replay case.
4. Capture logs across backend → Controller → adapter and assert request ID,
   operation ID, attempt, revision, and error layer are observable while auth
   credentials and profile/key payloads stay absent.

**Exit criteria:** tests fail against a deliberately unavailable/restarted
service in the expected way, recover without rebuilding the client, propagate
deadlines, and preserve one side effect after a replay. Automatic retries stay
disabled.

### 2. Fence stale Xray config revisions

1. Make apply revisions a durable, strictly increasing sequence in SQLite;
   do not use wall-clock time as the ordering source. Continue carrying the
   operation ID and revision on validate/apply/replace calls.
2. Store only Xray's accepted/in-progress revision, operation ID, mutation
   fingerprints, and pending/committed markers in a dedicated, permission-locked
   supervisor-state volume. Do not put client, account, or desired config data
   in Controller or the journal.
3. Serialize revision checks and Xray mutations at `xray-supervisor`. Reject
   any operation older than the last accepted revision. A replay at the same
   revision is allowed only for the same operation ID; a different operation
   at that revision is rejected. Higher revisions supersede incomplete lower
   ones.
4. Persist an in-progress marker before calling Xray and commit the marker only
   after success. Bind replay to the canonical config path and content hash so
   a reused operation ID cannot silently apply changed bytes. On supervisor
   restart, allow the same operation to resume, reject older revisions, and
   keep a failed/in-progress revision visible in the journal/logs. A committed
   rollback keeps the high-water revision but marks the compensated original
   mutation resumable. Ensure rollback does not lower the revision fence.
5. Test out-of-order calls, same-revision replay/conflict, failed apply and
   same-operation retry, process restart, database restore from an older
   snapshot, and monotonically increasing revisions after application restart.
   Do not add RPC retries.

**Exit criteria:** a lower revision can never replace a higher accepted Xray
configuration, even across supervisor/Controller restarts; repeating the same
operation is safe; a failed higher operation can be retried with its original
ID without permitting an older operation to overtake it.

### 3. Replace `Struct` with typed Protobuf messages

1. Define typed request/response messages for every Controller RPC, including
   telemetry, capabilities, AWG status/peers, binary backup data, operation
   IDs, and explicit config revision fields. Preserve the existing private service name and method
   names for this in-repo coordinated rollout; bump the package/service version
   if wire compatibility with an independently deployed old binary is needed.
2. Add a pinned, reproducible protobuf generation workflow and check in
   generated Go message code. Keep the runtime image free of compiler tooling.
3. Convert the Controller server interface/service, manual gRPC registration,
   backend client, adapters, fakes, and tests to typed messages. Remove
   reflection-based field parsing and response decoding from the Controller
   boundary.
4. Preserve auth, request metadata, redaction, status mapping, partial
   availability, and existing HTTP/UI/SSE behavior. Add wire-level tests for
   every method and verify serialization of large backup payloads and counters.
5. Run root/AWG tests, coverage gates, race tests, vet, Compose validation, and
   a local container rollout before VDS validation.

**Exit criteria:** no Controller RPC signature or codec uses
`google.protobuf.Struct`; generated code can be reproduced from the checked-in
schema; public HTTP and UI behavior is unchanged.

## Current status

- [x] Stage 1: failure-oriented gRPC integration tests for Controller restart,
  Xray/AWG unavailability, deadlines/cancellation, Xray mutation response loss,
  and AWG persistence/replay across service restart.
- [x] Stage 2: durable revision allocation/fencing, restart-safe replay,
  failure recovery, rollback identity, and config-content fingerprints. No
  automatic RPC retries were added.
- [x] Stage 3: typed Protobuf contract, generated Go code, Buf/Docker generation
  script, and typed server/client/adapters/tests. The Controller API no longer
  uses `google.protobuf.Struct`.

Verification status: root tests (`./cmd/... ./internal/...`) and the AWG module
tests pass; handwritten coverage is 90.3% for the root module and 90.11% for
AWG, with Controller at 93.2% and Xray supervisor at 90.5%. Controller and
supervisor race tests, `go vet`, Buf regeneration, and `docker compose config`
pass. VDS runtime validation remains a manual deployment check.
