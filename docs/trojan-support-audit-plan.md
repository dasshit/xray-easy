# Trojan Support Audit Remediation Plan

## Goal

Close the implementation gaps found during the end-to-end Trojan support review. Trojan should behave consistently across configuration, runtime lifecycle, profile delivery, diagnostics, and the Web UI. Existing authentication and profile workflows must remain intact.

## Findings to address

1. The doctor checks the embedded runtime's inbound tags but does not include Trojan (or Shadowsocks) when deriving the expected tags from `active.json`.
2. Trojan's Web settings badge is derived from the feature flag and shared TLS certificate status. It can therefore display “Running” without confirming that the embedded Xray runtime actually has the Trojan inbound.
3. Trojan profile output uses `allowInsecure` for self-signed/legacy certificates. The official Xray share-link proposal maps `pcs` to `pinnedPeerCertSha256`, so both URI and JSON profiles can pin the server certificate.
4. The installer can enable Trojan and display its public port, but does not offer an interactive custom-port setting.
5. Embedded runtime integration coverage exercises VLESS, VMess, and Hysteria, but not Trojan's actual inbound user lifecycle and telemetry path.
6. The original Trojan implementation plan still describes work as planned and needs to reflect the current state after remediation.

## Phases

### 1. Repair doctor configuration checks

- Include Trojan and Shadowsocks in the supported inbound protocols used to compare `active.json` with runtime-reported tags.
- Add tests covering both protocols and mixed configurations.
- When Trojan is enabled, verify that its configured listener is represented in the active/runtime state; report a clear failure if it is missing.

### 2. Make Trojan health in the UI truthful

- Separate “enabled/configured” from “running/ready” state.
- Derive runtime readiness from the backend/runtime status rather than the environment flag and certificate alone.
- Extend the API response schema and translations if needed, and cover enabled, disabled, certificate-missing, and runtime-inbound-missing states.

### 3. Improve Trojan profile TLS verification

- Use the shared certificate's SHA-256 fingerprint to pin certificates in Trojan JSON profiles with `pinnedPeerCertSha256` and in share links with the standard `pcs` parameter.
- Do not emit `allowInsecure`; trusted certificates continue to use normal TLS verification.
- Test self-signed, trusted, missing-certificate, and malformed-fingerprint cases; document the security behavior accurately.

### 4. Complete installer port configuration

- Add an interactive Trojan public TCP port setting, defaulting to the existing default and validating the supported port range/conflicts.
- Preserve an existing setting during installer updates and ensure `.env`/Compose output remains consistent.
- Add tests for defaults, custom values, invalid values, and reconfiguration.

### 5. Cover Trojan in embedded runtime integration tests

- Add a Trojan inbound to the embedded Xray test configuration.
- Verify AddUser/RemoveUser and per-user telemetry/account mapping through the real embedded runtime integration path.
- Run root-module tests and the runtime-module tests where the environment permits loopback listeners.

### 6. Reconcile documentation and verify the complete path

- Update the original Trojan support plan's status and record any remaining manual VDS/client checks.
- Run focused tests, full Go tests, Web tests/typecheck/lint, and Compose configuration validation.
- Summarize any client URI limitation or environment-dependent test that still needs manual verification.

## Acceptance criteria

- Doctor's active inbound tag check passes with supported Trojan and Shadowsocks inbounds and detects missing runtime entries.
- The UI never labels Trojan “Running” based only on configuration; it reflects actual runtime readiness.
- Trojan JSON profiles and share links verify the server certificate using the shared certificate fingerprint for self-signed/legacy certificates; trusted certificates use normal TLS verification.
- The installer can configure and preserve a custom Trojan TCP port.
- Embedded runtime integration tests exercise Trojan user management and telemetry.
- Documentation accurately distinguishes completed automated checks from manual deployment/client verification.

## Compatibility and rollout notes

- No existing login or profile-creation interaction changes are intended.
- No unverified query parameter will be added to Trojan links.
- Existing installations retain their configured Trojan port; fresh installations use the current default.
- VDS firewall reachability and import/connectivity in V2Rage remain manual deployment checks.

## Implementation status

- Phase 1: completed. Doctor recognizes Trojan and Shadowsocks tags, and fails if an enabled Trojan listener is absent from the active or running configuration. Initial setup remains a warning until the first configuration is applied.
- Phase 2: completed. The Web UI reports Trojan as running only when the runtime is running, reports `trojan-tls`, and the shared certificate is ready.
- Phase 3: completed. Trojan URIs use Xray's `pcs` share-link field and JSON uses `pinnedPeerCertSha256`; `allowInsecure` is no longer exported.
- Phase 4: completed. The installer accepts and validates a custom Trojan TCP port and preserves it in `.env`.
- Phase 5: integration coverage added for Trojan add/list/remove and telemetry in the embedded runtime. Execution is blocked in this sandbox because it denies loopback listener binds (`operation not permitted`); the package and test compile.
- Phase 6: completed. The Trojan implementation plan and English/localized README copies now describe certificate pinning correctly.

Verification completed: full root-module Go tests, Web tests (129), Web typecheck, ESLint, production build, and `docker compose config --quiet` pass. Before release, rerun the embedded runtime integration test in an environment that permits loopback binding and manually verify V2Rage import/connectivity for the new `pcs` link plus doctor output on a VDS.
