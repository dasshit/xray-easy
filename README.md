# Xray-easy

Xray-easy is a private web panel for one Xray server. It runs Xray and the Go
control plane in separate Docker containers and helps one administrator create
VLESS + REALITY + TCP/RAW + XTLS Vision profiles for their devices. The panel
is bound to the server's loopback address; open it through an SSH tunnel.

The current pinned Xray version is **26.7.28**. It was selected for compatibility
with the current V2Rage client and supports the gRPC API used for live device
changes and statistics. Manual release testing on macOS/iOS remains on the
checklist. The complete product scope and remaining release work are in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Quick start

You need a Linux VPS with an `amd64` or `arm64` CPU, Docker Engine with the
Compose v2 plugin, SSH access, and an available public TCP port (443 by
default). Allow that port in the VPS firewall/security group. The VPS needs
outbound access for Docker images and for Xray traffic. Go and Node.js are
**not required** on the VPS.

Run these commands **on the VPS**:

```sh
git clone https://github.com/dasshit/xray-easy.git
cd xray-easy
./install.sh
```

The repository is currently private, so GitHub access is required to clone it.
The installer builds its terminal UI in a temporary Docker container, then
opens a full-screen terminal workspace. Use **↑/↓ or Tab** to move between
fields, **Enter** to continue, **Esc** to cancel, and **Ctrl+C** to stop. It checks
Docker/Compose, asks for the public and panel ports, generates the master key
and supervisor token, writes `.env` and `secrets/xray_supervisor_token` with
mode `0600`, then runs `docker compose up -d --build --wait`. It waits for the
services to become healthy. A repeat run reuses the existing keys and Docker
volumes.

Example configuration screen (shortened):

```text
  XRAY-EASY  /  PRIVATE SERVER INSTALLER
  01 CHECK     02 CONFIGURE     03 REVIEW     04 START

  02 / 04   Configuration
  ╭─────────────────────────────────────────────────────╮
  │  Public Xray TCP port                               │
  │  › [ 443 ]                                          │
  │  Web UI port on VDS loopback                         │
  │    [ 8080 ]                                         │
  │  The panel is reached through an SSH tunnel.        │
  ╰─────────────────────────────────────────────────────╯

  ↑↓ / Tab  Move     Enter  Continue     Esc  Cancel
```

On **your own computer**, start a tunnel to the VPS (replace the user and
host):

```sh
ssh -N -L 8080:127.0.0.1:8080 user@your-vds
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). If you chose another Web
UI port in the installer, use it in both places in the command and URL. The
panel is never published on the VPS public interface by `compose.yaml`.

In the browser, create the administrator, enter the VPS public IPv4 address or
DNS name, choose a REALITY target and SNI, and create the first device. Import
its QR code, VLESS link or JSON profile into a client. The public port shown in
the setup screen comes from `.env`; it is not edited in the panel. A working
public inbound is created when the first device is applied.

## What is available

- Device creation, enable/disable/revoke, QR code, VLESS link and JSON export.
  New devices are normally applied through Xray's gRPC API without restarting
  the Xray process; the supervisor validates and applies full config changes.
- Online and last-seen indicators, cumulative upload/download totals, and live
  panel updates through SSE.
- Node settings with a preview of changes, confirmation and an automatic
  backup before changes that revoke existing profiles.
- Password login, optional TOTP with recovery codes, three-hour sessions, and
  a command to sign out all sessions.
- Diagnostics showing supervisor state and recent redacted warnings/errors.
- Manual and automatic backups in `/data/backups`; the last ten are retained.
  Backups are plaintext, so protect the VPS and any copies you export.

The Compose control network has IPv6 enabled. Xray's public TCP port is mapped
to container port `8443`; the panel is mapped to `127.0.0.1` on the VPS. Xray
and the control plane share a private supervisor token, and their persistent
state lives in Docker named volumes.

## Day-to-day commands

Run commands from the repository directory on the VPS:

```sh
docker compose ps
docker compose logs --tail=100 xray xray-easy
docker compose logs -f xray
docker compose down                         # stop, preserving named volumes
docker compose up -d --build --wait          # start again
```

To update the code, create a backup from the Security page or CLI, then run:

```sh
git pull
./install.sh
```

The installer keeps an existing `.env` and supervisor token. Keep the value of
`XRAY_EASY_MASTER_KEY`: it decrypts the stored REALITY private key and verifies
backups. Changing the public port in `.env` affects issued profiles and requires
reviewing their replacement in the panel.

Administrative commands run inside the control-plane container:

```sh
docker compose exec xray-easy xray-easy admin logout-all
docker compose exec xray-easy xray-easy admin reset-totp
docker compose exec xray-easy xray-easy admin recovery-codes
docker compose exec xray-easy xray-easy backup create
docker compose exec xray-easy xray-easy backup list
docker compose exec xray-easy xray-easy restore BACKUP_NAME RESTORE
```

Use an actual name from `backup list` in place of `BACKUP_NAME`. Restore checks
the backup and master key and creates a backup of the current state before
applying it. Recovery-code reissue invalidates previous codes; TOTP reset
revokes all sessions. To copy the unencrypted backup directories to the VPS
filesystem before transferring them over SSH:

```sh
docker compose cp xray-easy:/data/backups ./backups
```

## Manual setup and existing installations

For a manual first install, copy [.env.example](.env.example), fill in
`XRAY_EASY_MASTER_KEY` with a persistent value from `openssl rand -base64 32`,
create the token, then start Compose:

```sh
cp .env.example .env
openssl rand -base64 32                    # paste into XRAY_EASY_MASTER_KEY in .env
umask 077
mkdir -p secrets
openssl rand -base64 32 > secrets/xray_supervisor_token
chmod 600 .env secrets/xray_supervisor_token
docker compose up -d --build --wait
```

If you previously used `compose.stage1.yaml`, keep its `.env` and
`prototype/secrets/xray_supervisor_token`, update the checkout and run
`./install.sh`. The new Compose file defaults to the old project name for an
existing `.env` without `XRAY_EASY_PROJECT_NAME`, so it reuses the existing
volumes. Fresh installations use the project name `xray-easy` and store the
token under `secrets/`. The old stage 0 prototype had no panel state to
migrate.

If startup fails, inspect `docker compose ps` and
`docker compose logs --tail=100 xray xray-easy`. Installer failures retain
`.env` and the token so you can correct the problem and rerun `./install.sh`.

Backend test coverage and the test plan are documented in
[docs/backend-test-plan.md](docs/backend-test-plan.md). Run
`bash scripts/backend-coverage.sh` to check coverage thresholds locally.
The planned web unit-test coverage is documented in
[docs/web-test-plan.md](docs/web-test-plan.md).

Run web checks from `web/` with `npm ci`, `npm run lint`, `npm test`,
`npm run test:coverage`, `npm run typecheck`, and `npm run build`.
