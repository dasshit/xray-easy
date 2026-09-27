# Xray-easy

Xray-easy is an administration panel for a single Xray node. The product plan
is in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Current implementation slice

The current slice implements the first usable device flow:

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
- the Vue dashboard is embedded into the control-plane image;
- `compose.stage0.yaml` keeps the supervisor and Xray API off the host network.

TOTP, traffic polling, backups/restore, settings rotation and the complete
diagnostics/API surface from the plan are still subsequent slices.

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
the Xray container. The prototype config is deliberately a bootstrap config
without a public inbound; the control plane will generate the first public
configuration in the next implementation slice.

For the control-plane slice, put a generated base64 master key in `.env` and
use `compose.stage1.yaml`. Its UI port is published only on `127.0.0.1` for
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
