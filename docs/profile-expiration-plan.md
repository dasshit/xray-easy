# Profile expiration plan

## Goal

Add optional expiry dates to Xray-easy device profiles and enforce them for
VLESS, Hysteria 2, VMess, Shadowsocks, Trojan, and AmneziaWG. Expiry must work
without an open Web UI or SSE connection, survive process/container restarts,
and preserve existing profile credentials and traffic history.

## Current implementation constraints

- Xray profiles are stored in SQLite and have enabled/revoked lifecycle state,
  but no expiry field. The backend already applies per-protocol changes through
  Controller and Xray's live handler APIs.
- AmneziaWG peer identity, public keys and addresses are persisted by
  `amneziawg-service`. Its current removal operation also deletes the saved
  client configuration, so expiry must use a reversible peer-disable operation
  instead of peer removal.
- The shared profile API and Web UI combine Xray profiles and AmneziaWG peers;
  expiry must appear consistently in both.
- Traffic accounting is not part of this feature. No traffic quota or periodic
  reset semantics are introduced here.

## Product and lifecycle rules

1. Expiry is optional. A missing expiry means unlimited lifetime. The database
   migration must leave every existing profile without an expiry.
2. Store expiry instants in UTC. The UI accepts and displays local date/time and
   sends an RFC3339 timestamp with offset.
3. An expired profile is disabled, not deleted or permanently revoked. Its
   credential, profile material, traffic counters and audit history remain.
4. Expiry never silently re-enables access. An administrator may extend an
   expired profile and then explicitly enable it. If the deadline has passed
   but enforcement has not yet disabled access, reject expiry edits until the
   worker completes; this prevents an extension from cancelling a pending
   disable. Permanent revoke remains irreversible and takes precedence over
   expiry.
5. One profile's expiry applies to every protocol credential in that profile,
   including both credentials in legacy dual-protocol profiles.
6. The scheduler starts with the control plane, runs independently of SSE, and
   sweeps overdue profiles on startup. Runtime failures leave a durable pending
   operation that is retried; they must not erase the intended expiry.
7. The target enforcement latency is at most 10 seconds after the deadline
   under healthy service conditions. Doctor and diagnostics report overdue
   operations that could not be applied.
8. The UI distinguishes active, manually disabled, expired, permanently
   revoked, and expiry-pending states.

## Phased implementation

### Phase 1 — Domain, SQLite and API contract

- Add an optional `ExpiresAt` timestamp to Xray profile and AmneziaWG profile
  representations.
- Add nullable expiry in SQLite with an additive migration and preserve legacy
  rows as unlimited. Represent expiry-pending as a persisted due deadline plus
  still-enabled access; keep manual disable and permanent revoke in the existing
  lifecycle fields instead of adding a redundant disable-reason column.
- Define domain transitions so expiry, manual disable, enable, extension and
  permanent revoke cannot accidentally override one another.
- Extend the profile DTO, API contract, TypeScript/Zod model and backup/restore
  paths. Use RFC3339 UTC on the wire.

### Phase 2 — Durable expiration worker

- Add a control-plane lifecycle worker that starts independently of HTTP/SSE
  subscribers and sweeps overdue profiles immediately on startup.
- Persist the due deadline as desired state before enforcement. Derive
  expiration-pending from a due deadline plus enabled access, and retry through
  the existing idempotent state-change path at a bounded interval when
  Controller or a runtime is unavailable; a separate operation table is not
  needed for this level-triggered operation.
- Reuse the existing application use case for profile state changes instead of
  introducing a second HTTP-only implementation.
- Surface pending/failed enforcement in diagnostics and Doctor.

### Phase 3 — Xray enforcement

- Apply expiry to VLESS, Hysteria 2, VMess, Shadowsocks and Trojan through the
  current Controller/runtime boundaries, without restarting the Xray process.
- Ensure expired users are excluded from generated configuration after restart
  and are not re-added by reconciliation.
- Verify both new-connection rejection and handling of already-established
  sessions for every protocol. If the runtime cannot terminate a particular
  active session, state that limitation and define a bounded close behavior
  before claiming that protocol is fully enforced.

### Phase 4 — Reversible AmneziaWG peer disable

- Add enabled state to AWG peer persistence, with a versioned migration that
  treats peers from the current state format as enabled.
- Add authenticated typed Controller/AWG RPC support for enable/disable that
  retains peer identity, allocated addresses and the saved client `.conf`.
- Apply enable/disable live through the AWG engine and persist transactionally;
  restore the previous live state if persistence fails.
- Keep `RemovePeer` as the explicit permanent revoke path.

### Phase 5 — Web UI

- Add “Never” (default), common duration presets and custom local date/time to
  the create-profile flow; validate that new expiries are in the future.
- Allow editing the expiry of an existing profile. Extending an expired profile
  does not enable it; enabling is a separate explicit action.
- Show expiry date, remaining time, expired state and pending-enforcement state
  in the profile list and details.
- Update all supported translations and their tests.

### Phase 6 — Verification and rollout

- Test additive SQLite migration, existing backups, backup/restore, UTC and
  timezone boundaries, and concurrent expiry/enable/disable/revoke operations.
- Unit-test worker startup sweep, deadline handling, idempotency, retry and
  service-unavailable behavior with a fake clock.
- Add Xray runtime integration coverage for every supported protocol and AWG
  tests for disable/re-enable, restart persistence and client profile retention.
- Verify the UI API contract, validation, accessibility and all translations.
- Keep the established Go coverage thresholds: 90% overall and the current
  minimum per package; run race tests, web tests, Go documentation checks,
  Compose validation and image builds.
- Update README and translated READMEs, then prepare a VDS checklist covering
  expiry while UI is closed, service restart around the deadline, AWG re-enable,
  and active Xray connections.

## Acceptance criteria

- Existing profiles remain unlimited after upgrade.
- A profile is enforced after its deadline without the administrator opening
  the panel; restart does not restore expired credentials.
- Expiry does not delete profile credentials, AWG client configuration, traffic
  history or audit records.
- Extending an expired profile does not enable it without an explicit action.
- Permanent revoke remains terminal and cannot be undone by changing expiry.
- Failures to reach Controller/runtime are visible and retried until the desired
  disabled state is confirmed.
- Tests and coverage gates pass, and all supported protocol-specific guarantees
  are documented accurately.

## Implementation status

- [x] Plan recorded before implementation.
- [x] Go domain and storage: nullable expiry, additive SQLite migration, UTC
  persistence and backup compatibility; old profiles remain unlimited.
- [x] Go profile API: expiry on create, read and update; extending a deadline
  does not enable an expired profile.
- [x] Durable enforcement workers: Xray-easy sweeps on startup and every five
  seconds; AmneziaWG service sweeps on startup and every second. Both run
  independently of SSE. Overdue enabled state is durable and retried; failed
  enforcement is reported in diagnostics and logs, and doctor warns while any
  expired Xray profile or AmneziaWG peer remains enabled.
- [x] Xray new-connection enforcement: expired users are omitted from rendered
  configs and removed through the existing live HandlerService state-change
  path without restarting Xray.
- [x] Reversible AmneziaWG enforcement: versioned state migration, typed
  Controller/AWG RPCs, transactional live peer disable, and retention of peer
  identity, addresses, counters and client profile. Explicit re-enable is
  rejected until the deadline is extended. Deadline changes are also rejected
  while an overdue peer is still awaiting disable, so an extension cannot
  cancel pending enforcement.
- [x] Xray expiry race protection: expiry changes are rejected while an overdue
  profile remains enabled and enforcement is pending; the change can be retried
  after the worker has disabled access.
- [x] Xray already-established TCP sessions: removing a profile credential
  prevents new authentication and closes tracked active TCP sessions for
  VLESS, VMess and Trojan. The embedded runtime integration test exercises
  profile removal with two source-IP sessions and checks that all remaining
  sessions close.
- [x] Runtime removal logs: every Xray user removal is recorded to the
  xray-core-service log and diagnostics, with protocol and the number of
  closed TCP connections when supported; no credential or source IP is added.
- [x] Web UI and translations: create and edit flows support unlimited,
  preset and custom local date/time values; the profile list shows expiry and
  localized remaining time, plus expired and pending-disable states. Extending
  an expired profile does not enable it. All twelve UI locales contain expiry
  translations.
- [x] README documentation: primary and translated README copies explain the
  lifecycle and protocol-specific active-session behavior.
- [x] Xray existing UDP sessions: runtime now tracks every authenticated
  outbound dispatch by profile. Profile removal cancels the dispatch context
  and interrupts both sides of its Xray link, including Hysteria 2 and
  Shadowsocks UDP flows, while TCP protocols also close their tracked client
  connections. Late dispatches from already-authenticated requests are blocked
  for a bounded 30-second grace period; the marker cache is capped at 2,048
  profiles. Added regression tests for established Hysteria 2 and Shadowsocks
  dispatches without relying on a client `net.Conn`. VDS verification still
  checks the client-visible teardown of active UDP traffic.
- [x] Go unit and race coverage gates: handwritten backend coverage is 90.0%
  overall with every package at least 80%; AWG service coverage is 90.15%.
- [x] Full local verification: backend tests and race coverage, AWG tests and
  race coverage, Xray runtime race tests, Web tests/lint/typecheck/build and
  coverage, Go documentation checks, Compose validation, and local Docker
  builds of control-plane, Controller, xray-core-service and
  amneziawg-service all pass.
- [ ] Manual VDS rollout checks in Phase 6 remain outstanding.

## Rollout checklist for the administrator

The remaining checks require the deployed VDS and a real client:

1. Create one profile without expiry and confirm it stays unlimited.
2. Create profiles with a duration preset and a custom local date/time; confirm
   the displayed instant matches the selected timezone.
3. Keep the Web UI closed across a deadline and verify the profile is disabled
   by the background worker.
4. Reboot or recreate the services before a deadline and verify it is still
   enforced after startup.
5. Extend an expired profile, confirm it stays disabled, then enable it
   explicitly.
6. For VLESS, VMess and Trojan, confirm an active TCP session closes at expiry.
   For Hysteria 2 and Shadowsocks, confirm new authentication fails and an
   established UDP flow stops forwarding when its tracked dispatch is
   interrupted.
7. For AmneziaWG, confirm expiry disables the peer but preserves its profile;
   extend and explicitly re-enable it.
8. Stop Controller or the AWG service across a deadline, then restore it and
   confirm the pending disable is retried and visible in diagnostics/Doctor
   while it is pending.
