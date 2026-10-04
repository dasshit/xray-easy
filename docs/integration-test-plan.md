# Integration testing plan

## Goal

Add a dependable integration-test layer for Xray-easy that verifies service
boundaries and user-visible workflows, not only isolated functions. The tests
must catch contract, configuration, container wiring, and live-traffic regressions
without requiring a VDS or access to public Internet services.

Keep the existing unit and coverage gates. Integration tests complement them;
they do not replace high-coverage deterministic tests.

## Current state

The repository already has useful integration-level tests at several boundaries:

- `xray-runtime/internal/runtime/*_integration_test.go` starts the real embedded
  Xray engine on local listeners and exercises live user changes, inbound
  replacement, telemetry, and VLESS source-lease disconnection. The VLESS lease
  test sends a protocol request through a local echo server and checks that the
  selected connection closes while another remains usable. Multi-protocol
  engine tests cover user management and statistics mapping for VLESS, VMess,
  Trojan, Hysteria 2, and Shadowsocks 2022, but do not perform client handshakes
  for every protocol.
- `internal/controller/failure_integration_test.go` uses a real gRPC server and
  client with production auth/logging interceptors. It covers Controller
  restart, adapter failures, deadlines, and replay after simulated response
  loss; protocol adapters are test doubles there.
- Backend HTTP and SSE tests use `httptest`, a temporary SQLite database, and
  test doubles for Controller/runtime dependencies.
- AWG control tests exercise the service and gRPC APIs, but its TUN device and
  peer snapshots are represented by a fake `Device`.
- Web tests exercise the real UI with mocked HTTP and EventSource boundaries.
- `scripts/xray-runtime-test-stack.sh` starts the production Compose topology
  for developer/VDS diagnostics. The tagged `integration/compose` Go test
  builds and starts an isolated copy for smoke validation and CI.
- `.github/workflows/backend-tests.yml` runs unit tests, race detection,
  coverage, builds, type checks, and audits. It does not start Compose, connect
  a real proxy client, or run browser tests against the assembled services.

The key gap is the complete path:

```text
Web/API -> backend + SQLite -> Controller gRPC -> Xray runtime
                                      ^                 |
                                      +-- telemetry ----+
        backend SSE -> browser
```

Most links in this path are tested separately. The first new vertical test now
proves the profile-creation-to-runtime-RPC-to-SSE contract, but its Xray runtime
RPC endpoint is a deterministic gRPC test server; it does not yet send real
proxy traffic through the embedded Xray engine.

## Test design rules

1. Use local listeners, a local echo/HTTP target, and generated test
   certificates. Tests must not depend on public DNS, public websites, or VDS
   firewall behavior.
2. Prefer readiness signals, channels, and bounded polling over fixed sleeps.
   Every test has a deadline and reports relevant service logs on failure.
3. Use unique temporary directories, Compose project names, host ports, and
   subnets. Cleanup must not remove a normal developer installation or its
   named volumes.
4. Test the production composition and contracts where practical. Keep fakes at
   external boundaries only when the scenario is explicitly about that
   boundary's failure behavior.
5. Keep pull-request checks useful in duration. Run deterministic in-process
   scenarios on every PR; use cached Compose builds for smoke checks; reserve
   expensive protocol and privileged AWG scenarios for selected PRs, scheduled
   runs, and release validation.
6. Do not log credentials, private keys, generated profile links, session
   cookies, or unredacted environment files in CI artifacts.

## Stages

### Stage 1 — Backend, Controller, and runtime vertical slice

Build a reusable integration fixture that composes the real backend HTTP/SSE
server, SQLite store, authenticated Controller gRPC client/server, and runtime
RPC boundary. Keep the fixture hermetic and run it under the root Go test/race
gates. Separate the contract slice from the real-engine traffic slice so the
former stays fast without presenting a fake runtime as full proxy E2E coverage.

Scenarios:

1. Start with a temporary database and a valid minimal Xray configuration.
2. Bootstrap/authenticate an administrator using the existing test mechanisms.
3. Create a VLESS profile over the backend HTTP API.
4. Assert the profile is persisted and the same user is added through the live
   runtime RPC without invoking a full configuration apply/restart.
5. Open backend SSE and publish runtime telemetry; assert online state, source
   IP, cumulative bytes, and a current-speed sample reach the SSE client.
6. Disable the profile and assert the live runtime RPC removes the user.
7. In the real-engine slice, connect through a local proxy to an echo target,
   stop the client, and assert response bytes, offline transition, and source-IP
   cleanup.

If starting the production runtime from the root Go test would couple modules or
make ordinary unit tests too slow, split this stage into a root backend-to-
Controller contract test and a dedicated integration command that starts the
runtime module. Do not hide a production dependency behind a test-only fake and
call that full end-to-end coverage.

Contract-slice acceptance:

- The test traverses actual backend HTTP handling, SQLite, authenticated
  Controller/runtime gRPC, live user mutation, telemetry, and backend SSE.
- It confirms profile creation does not trigger full configuration apply.
- The test is deterministic, bounded, and safe under `-race` and `-count=2`.

Real-engine acceptance remains outstanding and is covered by Stage 3: a local
proxy request must transfer bytes through the embedded Xray engine and those
bytes must reach backend SSE.

### Stage 2 — Compose startup and doctor smoke test

Add a Linux CI job that invokes a tagged Go integration test and builds images
locally (never requires GHCR credentials or pulls project images). Start the
base Xray stack first; exercise optional Compose profiles in separate test
invocations. The Go test uses a unique Compose project and image tag, a
generated temporary master key, an isolated env file, temporary host ports
where possible, and deferred cleanup. On failure, preserve only Compose
status/log output as short-lived CI artifacts; never archive `.env`, mounted
volumes, profile exports, or credentials.

Base scenarios:

1. Validate the fully interpolated Compose configuration using test-only
   environment values and `docker compose config --quiet`.
2. Build and start the base services with a unique project name, temporary
   host ports, and isolated subnets.
3. Wait for all expected health checks and ensure init containers completed.
4. Run `xray-easy doctor`; require no failing checks. Treat firewall reachability
   warnings as expected because the test has no public ingress.
5. Check service reachability follows the intended network layout: UI is
   published only on loopback; backend-only services are not host-published;
   Xray egress can reach the local test target.
6. Collect `docker compose ps` and logs from this fresh, profile-free stack on
   failure, then remove only the test project's containers, networks, volumes,
   and uniquely tagged build images. Never collect container environment,
   mounted volumes, or generated credentials.

Acceptance:

- A clean Compose build and startup works from the repository checkout without
  pre-published images or pre-existing volumes.
- All expected services become healthy and doctor passes its applicable checks.
- The job leaves no containers, networks, or volumes behind.

The fresh-install doctor smoke accepts expected WARN checks (setup is pending,
no public ingress can be tested, and IPv6 egress may be unavailable on the
runner) but fails on any `FAIL` or non-zero doctor exit.

### Stage 3 — Real client protocol smoke matrix

Add an isolated client and local echo target to the Compose test topology. Pin
the client runtime version and derive credentials/configuration from the test
fixture rather than storing static secrets in the repository.

For each enabled protocol, create a profile through the supported backend
workflow, connect a real client, proxy a request to the local echo target, and
verify non-zero byte counters and online state:

- VLESS + REALITY + TCP/RAW + Vision.
- VMess over the configured TLS transport.
- Trojan over TLS.
- Shadowsocks 2022 over TCP and UDP where the client supports the selected
  operation.
- Hysteria 2 over UDP with test certificates and explicit trust settings.

Each protocol case also checks that an invalid credential is rejected, that
disable/revoke removes access, and that no protocol unexpectedly binds a
conflicting listener. Use local aliases/certificates for TLS and REALITY; do
not use public camouflage sites.

Acceptance:

- A real client transfers a known payload through each enabled protocol to the
  local echo target.
- Backend statistics reflect the transferred payload and the client goes
  offline after disconnect/idle expiry.
- Cases are independently selectable so a failure identifies the affected
  protocol.

### Stage 4 — Leases, lifecycle, and failure recovery

Use the real telemetry path and Xray connection tracking for the lease cases.
Exercise Controller and runtime restarts in the Compose stack where persistent
state is part of the production contract.

Scenarios:

1. Keep the first Xray connection active, open a second, then open a third.
   During the grace interval, verify the configured policy; after it expires,
   verify only the oldest connection is closed and the second remains usable.
2. Disconnect a client naturally and verify its lease is removed without
   waiting for a new admin request.
3. Restart the lease service during an active stream and verify it reconnects
   without applying a stale disconnect.
4. Restart Controller while backend and runtime stay up; verify gRPC and
   telemetry recover.
5. Restart the runtime and verify persisted configuration is restored,
   profiles remain consistent, and telemetry resumes.
6. Stop Xray or AWG independently and verify doctor/UI report the right partial
   outage; restore the service and verify recovery.
7. Exercise failed configuration validation/apply and confirm the previously
   active configuration and profiles remain usable.

Acceptance:

- Lease policy and oldest-connection behavior match documented limits and
  timing.
- A transient dependency outage produces an observable error and then recovers
  without duplicate users, peers, disconnects, or stale online state.
- Failed apply does not corrupt the active state.

### Stage 5 — AmneziaWG packet-level smoke test

Add an opt-in Linux job only if its runner supports `/dev/net/tun`,
`CAP_NET_ADMIN`, forwarding, and the required firewall/NAT operations. Use an
isolated peer/client and local echo endpoint. Validate peer creation, handshake,
bidirectional packet flow, online/offline transitions, source IP, and byte
counters across the AWG gRPC telemetry path.

If the standard GitHub-hosted runner cannot provide these capabilities
reliably, keep the job explicitly optional and document a reproducible
self-hosted runner contract. Do not silently skip a required assertion. Until a
privileged runner exists, keep VDS packet-level validation manual while
retaining unprivileged AWG RPC, state, and telemetry tests in regular CI.

### Stage 6 — Browser and installer E2E

Once the Compose smoke environment is stable, add Playwright against the live
control plane. Verify login, profile creation, profile delivery, live status
updates, settings save/apply, diagnostics, and logout. Keep a small happy path
on PRs and leave broad browser coverage to scheduled/release workflows.

Add a clean-install scenario using disposable data and the installer flow where
CI can provide non-interactive inputs. It must reach the same doctor gate as a
fresh user installation. Preserve failure state/logs until artifacts have been
collected.

Acceptance:

- The browser test uses the built frontend and live API; it does not mock
  `fetch` or `EventSource`.
- Clean installation creates a usable stack and passes doctor without manual
  edits to generated files.

## CI placement and execution tiers

| Tier | Runs on | Contents | Expected characteristics |
| --- | --- | --- | --- |
| Fast | Every PR and push | Existing tests plus Stage 1 hermetic vertical slice | No Docker daemon or external network; suitable for race detector |
| Container smoke | PRs touching Go runtime, Dockerfiles, Compose, installer, or workflow; also main | Stage 2 base stack | Linux Docker, local image build/cache, bounded cleanup |
| Protocol E2E | Scheduled, release candidates, and relevant protocol changes | Stage 3 and selected Stage 4 cases | Pinned clients, local echo, artifacts with secrets redacted |
| Privileged/network | Optional scheduled or self-hosted runner | Stage 5 AWG packet flow | Explicit TUN/NET_ADMIN prerequisites |
| Browser/install E2E | Main, release candidate, and selected UI/installer changes | Stage 6 | Live stack, Playwright, screenshots/logs on failure |

Avoid adding all container/client/browser scenarios to the existing coverage
jobs. Separate jobs make failures attributable and keep ordinary PR feedback
fast.

## Initial implementation order

1. [x] Add this plan and record the current CI/test baseline.
2. [x] Implement the Stage 1 contract slice and run it twice under the race
   detector; complete the real-engine traffic acceptance in Stage 3.
3. [x] Add the Stage 2 Compose integration test and path-filtered Linux CI job.
4. [ ] Verify the first Stage 2 execution in GitHub Actions.
5. [ ] Add the local echo/client fixture and Stage 3 protocol cases.
6. [ ] Add Stage 4 lease/restart/failure scenarios.
7. [ ] Evaluate runner support and decide whether Stage 5 can be required.
8. [ ] Add Stage 6 browser and clean-installer workflows after the stack test is
   stable.
9. [ ] Record CI execution time, flakes, exact assertions, and remaining manual
   VDS checks here.

## Implementation progress

- Stage 1 contract slice: `cmd/xray-easy/integration_test.go` runs the real
  backend handler and SQLite store, production authenticated Controller and
  runtime gRPC adapters, runtime user mutation, streamed telemetry, and SSE.
  It passed twice locally with `go test -race` and `-count=2`. It intentionally
  uses a deterministic runtime gRPC test server; real proxy traffic is still a
  Stage 3 requirement. The full backend race+coverage gate also passed at
  98.3% handwritten statement coverage (each handwritten package at or above
  the configured 80% floor).
- Stage 2: run the Compose Go integration test explicitly with
  `go test -tags=composeintegration -count=1 -v -timeout=40m ./integration/compose`.
  It runs Compose config validation, local image build, health-gated startup,
  fresh-install `doctor`, loopback UI binding check, and cleanup. It also checks
  the host UI health endpoint, verifies the Controller and runtime gRPC ports
  are not published, and probes a private local HTTP target from the Xray
  container. On 4 October 2026, the full smoke passed
  locally via `go test` on macOS with Docker Desktop and Compose v5.5.1: all
  expected containers became healthy, doctor reported PASS, the UI bound to
  loopback, private gRPC ports had no host bindings, and Xray reached the test
  target.
  The test override selects `json-file` logging because Docker Desktop does
  not provide journald; production `compose.yaml` remains unchanged. Doctor
  emitted expected warnings for pending first-run setup, unavailable IPv6
  egress, not-yet-applied configuration, and public firewall reachability.
  The CI workflow is limited to integration-relevant changes and the main
  branch; its first GitHub Actions run is still pending.

## Current progress

- Plan recorded on 4 October 2026.
- The Stage 1 contract slice and tagged Stage 2 Compose Go test are implemented.
- The local Docker-backed Go smoke test passed on 4 October 2026. The first
  GitHub Actions run remains to be verified.
