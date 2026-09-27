# Xray-easy

Xray-easy is an administration panel for a single Xray node. The product plan
is in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Current implementation slice

The current slice implements the usable device and administration flow:

- `xray-supervisor` runs as PID 1 and starts the Xray child process;
- candidate configs are checked with the pinned Xray binary before apply;
- apply restarts Xray with a bounded graceful shutdown;
- status, health, bounded redacted logs and a TLS target probe are available on
  a private HMAC-authenticated API;
- the Go control plane stores one-admin state in SQLite and encrypts the REALITY
  private key with `XRAY_EASY_MASTER_KEY`;
- the setup wizard validates and probes a REALITY target and generates the
  X25519 key pair; the first device apply renders the pinned VLESS + REALITY +
  TCP/Vision server config;
- authenticated device CRUD supports enable, disable, revoke, VLESS URI, QR
  and client JSON export;
- Xray HandlerService CRUD, StatsService polling, reconciliation and an
  authenticated SSE stream keep live users and traffic counters synchronized;
- optional TOTP is available after the first password login. The encrypted
  secret is stored in SQLite, recovery codes are shown once and only their
  hashes are stored. Password + TOTP is required on subsequent logins;
- the UI has logout-all-sessions, and the control-plane CLI supports
  `admin logout-all`, `admin reset-totp` and `admin recovery-codes`;
- the Vue dashboard is embedded into the control-plane image;
- `compose.stage0.yaml` keeps the supervisor and Xray API off the host network.

Backups/restore, settings rotation and the complete diagnostics/API surface
from the plan are still subsequent slices.

## Run the stage 0 container

Requirements: Docker Compose v2 and an internet connection to pull the pinned
Xray image.

```sh
cp .env.example .env
mkdir -p prototype/secrets
openssl rand -hex 32 > prototype/secrets/xray_supervisor_token
chmod 600 prototype/secrets/xray_supervisor_token
docker compose -f compose.stage0.yaml build
docker compose -f compose.stage0.yaml up -d
```

The default public mapping is TCP `${XRAY_PUBLIC_PORT:-443}` to port `8443` in
the Xray container. The stage 0 prototype config is deliberately a bootstrap
config without a public inbound; use stage 1 for the control plane and setup
wizard that generate the first public configuration.

For the current control-plane slice, put a generated base64 master key in
`.env` and use `compose.stage1.yaml`. Its UI port is published only on
`127.0.0.1` for
SSH local forwarding. `XRAY_PUBLIC_PORT` is the single source of truth for the
host public port and is shown read-only in setup.

```sh
cp .env.example .env
openssl rand -base64 32   # put the output in XRAY_EASY_MASTER_KEY
umask 077; mkdir -p prototype/secrets
openssl rand -base64 32 > prototype/secrets/xray_supervisor_token
docker compose -f compose.stage1.yaml up -d --build
ssh -N -L 8080:127.0.0.1:8080 user@vds
```

Open `http://127.0.0.1:8080`, finish setup, then create a device and import its
QR/URI/JSON profile into V2Rage.

Administrative recovery commands run inside the control-plane container:

```sh
docker compose -f compose.stage1.yaml exec xray-easy xray-easy admin logout-all
docker compose -f compose.stage1.yaml exec xray-easy xray-easy admin reset-totp
docker compose -f compose.stage1.yaml exec xray-easy xray-easy admin recovery-codes
```

`recovery-codes` prints a new one-time set and immediately invalidates the
previous set. `reset-totp` disables TOTP and revokes all sessions.
