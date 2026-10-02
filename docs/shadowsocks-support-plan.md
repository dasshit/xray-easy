# Shadowsocks support plan

Status: initial classic implementation completed; SS2022 migration is in progress

## Scope and decisions

Xray-easy will add Shadowsocks as another Xray protocol handled by the
existing embedded Xray runtime and Controller. A second container is not
needed.

The original implementation used classic Shadowsocks AEAD. The project is
migrating to `2022-blake3-aes-256-gcm`; Xray's pinned SS2022 multi-user inbound
implements `UserManager`, so devices can still be added or removed through the
runtime API without replacing the inbound. See
[`shadowsocks-2022-migration-plan.md`](shadowsocks-2022-migration-plan.md) for
credential migration, implementation stages, and client compatibility details.

Shadowsocks has a dedicated public port. VLESS TCP and Hysteria 2 UDP already
use the public port from `XRAY_PUBLIC_PORT`; Shadowsocks cannot share the same
TCP listener with VLESS or the same UDP listener with Hysteria 2. The default
is therefore:

```text
VLESS       443/TCP
Hysteria 2  443/UDP
Shadowsocks 8388/TCP+UDP
VMess       9443/TCP
```

The public Shadowsocks port is configured by `XRAY_SHADOWSOCKS_PORT`. TCP and
UDP use the same number because they are separate socket namespaces. A profile
gets one unique SS2022 user PSK, stored encrypted with `XRAY_EASY_MASTER_KEY`.

The Web UI delivers an `ss://` URI, QR code, and JSON profile. It also shows
the method, network, port, status, source IP, counters, and rates. v2RAGE is
not an acceptance client for this protocol because its published protocol list
does not include Shadowsocks; manual verification uses a client with explicit
Shadowsocks support.

## Stage 0 — compatibility spike and contract

1. Verify the current Xray `26.7.28` runtime with a minimal Shadowsocks
   inbound using TCP and UDP.
2. Verify multiple SS2022 users, `AddUser`, `RemoveUser`, `ListUsers`, user
   counters, online state, and source IP observations.
3. Verify dual-stack Docker port publishing and document the required TCP and
   UDP firewall rules.
4. Verify the 2022 multi-user path and its live user-management behavior.
5. Add a compatibility entry and a runtime capability test so a future Xray
   upgrade cannot silently remove live Shadowsocks management.

Deliverable: this document, a compatibility test fixture, and an explicit
capability decision.

## Stage 1 — domain model and persistence

1. Add `ProtocolShadowsocks` and protocol access helpers to
   `internal/domain`.
2. Add encrypted password, enabled, and revoked state to the client model.
3. Add node-level Shadowsocks settings: enabled, public port, method, and
   network (`tcp`, `udp`, or `tcp,udp`).
4. Add SQLite migrations, scans, writes, backup/restore support, and backward
   compatibility with existing databases and backups.
5. Generate passwords with `crypto/rand`; keep plaintext only in the short-lived
   runtime/profile path.
6. Ensure passwords never appear in audit events, diagnostics, errors, or list
   responses.

## Stage 2 — Xray configuration renderer

1. Add the `shadowsocks` inbound tag and fixed internal listener port.
2. Render active SS2022 users with a node-level method/server PSK and a
   per-device user PSK and email.
3. Render an enabled inbound even when it currently has no users. The first
   profile may initialize the multi-user inbound through a validated full
   config apply; later profile changes use live `AddUser`/`RemoveUser`.
4. Validate method, network, port, credentials, and duplicate emails.
5. Keep output ordering stable and preserve disabled/revoked lifecycle rules.
6. Add renderer tests for TCP, UDP, dual network, invalid settings, and mixed
   protocol configurations.

## Stage 3 — embedded runtime and Protobuf

1. Add `PROTOCOL_SHADOWSOCKS` to the runtime enum.
2. Add the Shadowsocks cipher/method field to the typed `AddUserRequest`.
3. Register the Shadowsocks 2022 Xray package in the embedded runtime.
4. Extend account conversion, inbound-tag discovery, capabilities, user list,
   and telemetry mapping.
5. Preserve operation IDs, revision fencing, idempotency, and redacted
   structured logging.
6. Regenerate runtime Protobuf code and add unit/integration tests.

## Stage 4 — Controller integration

1. Add typed Shadowsocks protocol support to the Controller contract.
2. Implement add, remove, and list operations with the configured cipher.
3. Forward runtime capabilities and telemetry to the backend.
4. Add outage, timeout, restart, stale-revision, and rollback tests.
5. Keep backend-to-Controller-to-runtime correlation IDs in all three logs.

## Stage 5 — backend lifecycle and HTTP API

1. Add Shadowsocks to profile creation validation and availability checks.
2. Generate, encrypt, persist, and live-install a per-device password.
3. Disable through `RemoveUser`; revoke through `RemoveUser` plus permanent
   state transition.
4. Roll back database and runtime state when live installation fails.
5. Add `ss_uri` and JSON fields to the profile delivery response.
6. Add `format=ss-qr` and authenticated, no-store delivery routes.
7. Map telemetry to the existing online, last-seen, source-IP, total-bytes,
   and current-rate fields.
8. Return actionable errors when the runtime lacks the Shadowsocks user
   management capability.

## Stage 6 — Web UI

1. Add Shadowsocks to the create-profile modal and availability logic.
2. Add a read-only Settings card showing port, method, network, and runtime
   capability. Initial configuration remains controlled by installer/env.
3. Add Shadowsocks URI, QR, and JSON delivery to the profile modal.
4. Show protocol-specific status, source IP, last seen, traffic totals, and
   rates in the profile list.
5. Add Zod schemas, gateway mappings, component tests, and all translation
   keys for the supported UI languages.
6. Explain that Shadowsocks does not provide REALITY-style camouflage and that
   a compatible client is required.

## Stage 7 — Compose, installer, and doctor

1. Add `XRAY_SHADOWSOCKS_ENABLED`, `XRAY_SHADOWSOCKS_PORT`,
   `XRAY_SHADOWSOCKS_METHOD`, and `XRAY_SHADOWSOCKS_NETWORK` to the example
   environment.
2. Publish the same configured port for TCP and UDP in Compose.
3. Extend the installer TUI with enablement, method, network, port-conflict,
   and firewall guidance.
4. Extend doctor with config, port mapping, inbound tag, capability, stats,
   IPv6, and firewall checks.
5. Keep the service topology unchanged: embedded runtime, Controller, backend,
   and optional AmneziaWG service.

## Stage 8 — tests, documentation, and acceptance

1. Keep handwritten backend and runtime modules above the 90% coverage gate;
   add web unit coverage for API contracts, modal behavior, and translations.
2. Add runtime-stack tests for TCP, UDP, live user changes, restart, stats, and
   IPv6.
3. Update the English and localized README files with port rules, client
   examples, URI/QR/JSON delivery, and the protocol trade-offs.
4. Perform final VDS acceptance with a real Shadowsocks-capable client:
   create, connect over TCP and UDP, verify stats/source IP, disable, revoke,
   restart, restore, and test IPv4/IPv6 firewall behavior.

## Implementation notes

The service's existing lifecycle is being moved from classic Shadowsocks to
SS2022 without changing its public profile-management flow. The Web UI exposes
protocol selection, read-only listener settings, `ss://`/QR/JSON delivery, and
streamed status and traffic telemetry. Installer and doctor use the dedicated
`XRAY_SHADOWSOCKS_*` settings, and Compose publishes the configured port in
both TCP and UDP namespaces. Automated tests cover persistence, rendering,
live user lifecycle, profile delivery, telemetry, API schemas, and installer
migration. A real VDS/client pass is still required for TCP/UDP reachability,
dual-stack firewall behavior, and client interoperability.

## Commit boundaries

1. `docs: add Shadowsocks support plan`
2. `feat(domain): add Shadowsocks model and migration`
3. `feat(xray): render Shadowsocks inbound`
4. `feat(runtime): add Shadowsocks protobuf support`
5. `feat(controller): manage Shadowsocks users`
6. `feat(backend): create and manage Shadowsocks profiles`
7. `feat(api): deliver Shadowsocks URI QR and JSON`
8. `feat(web): add Shadowsocks profile flow`
9. `feat(installer): configure Shadowsocks port and method`
10. `test: cover Shadowsocks runtime and HTTP flows`
11. `docs: document Shadowsocks setup and compatibility`
