# Shadowsocks 2022 migration plan

## Goal

Replace the classic Shadowsocks AEAD method used by Xray-easy with the
Shadowsocks 2022 multi-user protocol while preserving the existing live
profile lifecycle: create, disable, enable, revoke, reconcile, and collect
per-user telemetry without replacing the inbound.

The selected method is `2022-blake3-aes-256-gcm`. Each installation has one
server PSK and each device has its own 32-byte user PSK. Existing device keys
were generated from 32 random bytes and can be retained by decoding their
current unpadded base64url representation and re-encoding them as padded
standard base64.

## Compatibility and migration effects

- This is a protocol-format change. Existing classic Shadowsocks client
  configurations will stop connecting after deployment; users need to import
  the newly generated profiles.
- The SS2022 server PSK is derived from `XRAY_EASY_MASTER_KEY`; keep that key
  unchanged across restarts, backup restore, and updates or all SS2022 profiles
  will need to be re-imported.
- The Xray version pinned by `xray-runtime/go.mod` contains a Shadowsocks 2022
  multi-user inbound that implements Xray's live `UserManager` API. The prior
  plan's claim that this inbound could not manage users live was incorrect.
- Xray's `MultiUserInbound.AddUser` ignores errors returned by its internal
  user-list update. Xray-easy must validate user PSKs before calling the API so
  invalid keys cannot be reported as successfully added.
- The Xray warning about Shadowsocks is emitted for the protocol generally by
  the config builder, including the SS2022 branch. SS2022 improves replay
  protection but does not promise the transport camouflage or forward secrecy
  supplied by TLS/REALITY. Do not treat changing the method as a way to silence
  every upstream warning.
- v2RAGE currently does not list Shadowsocks among its supported protocols.
  VDS acceptance must use a client that explicitly supports the selected
  Shadowsocks 2022 method.

## Implementation stages

### 1. Correct the Xray capability record

1. Replace the stale statement in `docs/shadowsocks-support-plan.md` that says
   SS2022 cannot use live user management.
2. Record the source-backed behavior and SS2022-specific constraints, including
   the supported multi-user ciphers and the error-handling caveat.

### 2. Define fixed SS2022 credentials and settings

1. Make `2022-blake3-aes-256-gcm` the only Shadowsocks method accepted by the
   domain, backend, and installer.
2. Derive a stable, installation-specific 32-byte server PSK from
   `XRAY_EASY_MASTER_KEY` with a dedicated HKDF context. Encode it with padded
   standard base64. Never expose it in status or diagnostics responses.
3. Derive a separate hidden bootstrap user PSK from the master key and render
   it only when no active device users exist. This keeps Xray's inbound in
   multi-user mode after a restart, so the first profile can be added live;
   runtime user lists, telemetry, and connection events must hide the reserved
   bootstrap identity.
4. Generate each user PSK from 32 cryptographically random bytes and encode it
   with padded standard base64 before encrypting it in SQLite.
5. Normalize existing encrypted legacy credentials during decrypt/render: old
   profile keys are 32-byte random values encoded as unpadded base64url, so
   decode those bytes and re-encode them as padded standard base64. Keep the
   encrypted database value unchanged unless normalization cannot preserve the
   original key bytes.

### 3. Render the SS2022 server inbound

1. Render the selected method and server PSK at the inbound settings level.
2. Render active device credentials as `users`, each with its user PSK and
   email; omit per-user methods because SS2022 fixes the method for the inbound.
3. Keep TCP/UDP listener selection, public port mapping, tags, statistics, and
   existing profile lifecycle behavior intact.
4. Validate server and user PSKs as exactly 32 decoded bytes before rendering.

### 4. Add/remove users through the embedded runtime

1. Construct `shadowsocks_2022.Account` values in the runtime rather than
   classic Shadowsocks accounts.
2. Accept only the selected SS2022 method and validate padded standard-base64
   credentials as exactly 32 bytes before invoking `UserManager`.
3. Keep the Controller/Runtime protobuf shape stable if the existing method
   field can represent the selected cipher without ambiguity.
4. Exercise add, duplicate add, list, remove, and telemetry on an embedded
   SS2022 inbound. Confirm no inbound replacement is needed for device changes.

### 5. Generate client artifacts

1. Generate SIP-002 `ss://` links using
   `method:serverPSK:userPSK` as the encoded credential payload.
2. Generate Xray client JSON with the SS2022 method and the client password
   `serverPSK:userPSK`.
3. Update QR generation and profile delivery tests for the new method and
   credential format.
4. Keep profile secrets out of logs and HTTP caches as before.

### 6. Migrate installer, settings, Web, and docs

1. Update installer defaults and normalize legacy `.env` method values to the
   fixed SS2022 method without changing the user's master key or ports.
2. Ensure an old Compose environment value cannot start a classic inbound after
   upgrade; the application must use the fixed SS2022 method.
3. Update Web settings/API fixtures and README protocol descriptions, including
   the V2RAGE compatibility limitation and required client capabilities.
4. Update translated READMEs consistently.

### 7. Verify and hand off for VDS acceptance

1. Run root Go tests and backend coverage gates.
2. Run `xray-runtime` unit tests and the embedded integration test where local
   listener binding is permitted.
3. Run Web lint, typecheck, tests, and production build if API fixtures or UI
   labels changed.
4. Validate Compose configuration and inspect generated JSON/URI fixtures.
5. Hand off the deployment for manual VDS tests: upgrade with existing
   Shadowsocks profiles, create a new device, import via an SS2022-capable
   client, verify TCP and UDP traffic, statistics, disable/enable/revoke, then
   re-import old device profiles using newly generated credentials.

## Completion criteria

- Active server config uses `2022-blake3-aes-256-gcm` and a stable server PSK.
- Every device has an independent random 32-byte SS2022 PSK; the hidden
  bootstrap user uses a separately derived key and is never exposed as a
  device or telemetry record.
- Dynamic add/remove and reconciliation work through the current live Xray
  `UserManager` without replacing the inbound.
- QR, share URI, JSON, installer, settings, Doctor, and documentation agree on
  SS2022 behavior.
- Tests verify normalization of old user keys and reject malformed user keys.
- Documentation clearly states that deployed classic profiles must be
  re-imported and v2RAGE compatibility is not currently advertised.
