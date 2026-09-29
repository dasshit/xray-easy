# VMess support plan

## Goal

Add VMess as an independent, optional profile protocol alongside VLESS +
REALITY and Hysteria 2. VMess is a compatibility option for clients such as
V2Rage; it is not presented as a DPI-resistance improvement.

## Protocol and transport decisions

- Use one VMess identity per profile, backed by a generated UUID.
- Use TCP + TLS on a dedicated public port. Default the public port to `9443`
  through `XRAY_VMESS_PORT`; keep the Xray container listener on an internal
  port distinct from the existing VLESS/REALITY listener.
- Reuse the certificate versions already managed by the control plane. VMess
  profile creation remains unavailable until a usable certificate exists and
  covers the advertised TLS server name. For self-signed or legacy certificates,
  generated profiles pin the leaf certificate's SHA-256 fingerprint using the
  VMess share-link `pcs` field and Xray's `pinnedPeerCertSha256`; trusted custom
  certificates use normal CA validation.
- Add and remove VMess users through Xray HandlerService so profile lifecycle
  changes do not restart Xray.
- Export the standard `vmess://` Base64 JSON share link, a QR code, and a client
  JSON file.
- Explain that VMess requires the server and client clocks to stay within two
  minutes and that VMess is easier to classify than VLESS + REALITY or
  Hysteria 2.

## Implementation stages

1. **Domain, storage, and rendering**
   - Add VMess to protocol/access models and persist its independent enabled and
     revoked state without changing existing VLESS, Hysteria 2, or migrated
     dual-protocol records.
   - Render the optional VMess TLS inbound from active VMess profiles and
     shared certificate metadata.
   - Add VMess profile link and JSON generation.

2. **Runtime lifecycle and reconciliation**
   - Add VMess HandlerService user operations.
   - Extend create, enable, disable, revoke, bootstrap, and reconciliation flows
     to manage VMess users without restarting Xray.
   - Include VMess in statistics and runtime-versus-database consistency
     checks.

3. **API and Web UI**
   - Add protocol-specific VMess creation and profile delivery contracts.
   - Require a valid shared certificate before VMess creation and explain how
     to provision one in Settings.
   - Show only the VMess link, QR and JSON export for VMess profiles; retain
     existing delivery behavior for other protocols and migrated profiles.

4. **Deployment and verification**
   - Publish the dedicated TCP port through Compose and add its setting to the
     generated `.env`, doctor output, and README. Keep the install wizard's port
     questions unchanged and default VMess to TCP port 9443.
   - Validate port conflicts and report the configured VMess port in doctor.
   - Run backend and frontend tests, typecheck, lint and image builds; finish
     with manual V2Rage import and connection verification on macOS/iOS.

## Acceptance criteria

- Existing databases and profiles migrate without losing credentials or
  access state.
- A VMess profile can be created, disabled, re-enabled, revoked and reconciled
  without restarting Xray.
- A generated VMess share link and QR import into V2Rage, and the profile's
  traffic statistics remain associated with the profile.
- Missing or mismatched TLS certificates prevent new VMess profile creation
  with a clear message.
- Compose publishes the configured VMess TCP port, doctor reports it, and
  existing VLESS + REALITY and Hysteria 2 behavior remains unchanged.
