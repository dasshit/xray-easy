# Stage 1: Go control plane

`cmd/xray-easy` is the first usable control-plane slice. It is intentionally
small but already enforces the deployment invariants that later features rely
on:

- `XRAY_EASY_MASTER_KEY` is required at startup and must decode from base64 to
  at least 32 bytes;
- SQLite is created in `/data/state.db` with WAL, foreign keys and a busy
  timeout;
- the first setup creates one canonical lower-case admin username and an
  Argon2id password hash;
- login sessions are random bearer tokens stored only as SHA-256 hashes and
  expire after three hours;
- setup status, health, login, logout and current-admin endpoints are present;
- setup validates and probes the REALITY target and generates an encrypted
  X25519 key pair; the first device apply writes the server configuration
  through the supervisor;
- authenticated device create/list/profile endpoints render VLESS URI, QR and
  client JSON, with enable/disable/revoke actions.

TOTP, traffic polling, backups/restore, settings rotation and the remaining
diagnostics endpoints are intentionally left for subsequent slices.
`compose.stage1.yaml` builds the control plane beside the supervisor and binds
the UI port to VDS loopback, ready for SSH local forwarding. It uses a separate
development subnet (`172.31.241.0/24`) so both compose fixtures can run at the
same time.

Set a master key and run:

```sh
openssl rand -base64 32
export XRAY_EASY_MASTER_KEY='...'
umask 077; mkdir -p prototype/secrets
openssl rand -base64 32 > prototype/secrets/xray_supervisor_token
docker compose -f compose.stage1.yaml up -d --build
```

Then open the forwarded UI port, complete setup and create a device. The
`XRAY_PUBLIC_PORT` value in Compose is the read-only public port used in the
generated profiles.
