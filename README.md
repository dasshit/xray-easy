# Xray-easy

Xray-easy is an administration panel for a single Xray node. The product plan
is in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Current implementation slice

The first slice implements the Xray process boundary:

- `xray-supervisor` runs as PID 1 and starts the Xray child process;
- candidate configs are checked with the pinned Xray binary before apply;
- apply restarts Xray with a bounded graceful shutdown;
- status, health, bounded redacted logs and a TLS target probe are available on
  a private HMAC-authenticated API;
- `compose.stage0.yaml` keeps the supervisor and Xray API off the host network.

This is an implementation foundation, not the complete device management
product. The SQLite-backed control-plane slice is available in
`compose.stage1.yaml`; it provides setup/status, password sessions and the
Vue setup/login shell. Device rendering, REALITY settings and Xray API
reconciliation are the next implementation slice.

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
SSH local forwarding.
