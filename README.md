# Xray-easy

Xray-easy is a private web panel for one Xray server. It runs Xray and the Go
control plane in separate Docker containers and helps one administrator create
VLESS + REALITY + TCP/RAW + XTLS Vision profiles for their devices. The panel
is bound to the server's loopback address; open it through an SSH tunnel.

The pinned and verified Xray version is **26.7.28**. The panel reports both
`XRAY_VERSION` from Compose and the version reported by the running binary, and
marks unverified versions as experimental. `doctor` checks the HandlerService
and StatsService endpoints and warns when versions differ or the binary is
outside the verified matrix. See [the version record](versions/xray-compatibility.json).
Before changing `XRAY_VERSION`, create a backup from Security or with
`docker compose exec xray-easy xray-easy backup create`. Recheck V2Rage when
changing Xray, profile generation or Compose networking. The
complete product scope and implementation notes are in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Quick start

You need a Linux VPS with an `amd64` or `arm64` CPU, Docker Engine **28.0.0 or
newer**, Docker Compose plugin **2.33.1 or newer**, SSH access, and an available
public TCP port (443 by default). These Docker versions are required to choose
the correct IPv4/IPv6 egress gateway for Xray. Allow the public TCP port in the
VPS firewall/security group for each address family you intend to use. The VPS
needs outbound access for Docker images and Xray traffic. Go and Node.js are
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
services to become healthy, then runs the final `xray-easy doctor` check. A
repeat run reuses the existing keys and Docker volumes. If Compose cannot make
the services healthy, the installer displays `compose ps --all` and the latest
100 lines from both service logs in the terminal. It leaves containers and
configuration in place and prints recovery commands.

The installer builds the application images locally from this checkout for the
VPS architecture. Prebuilt images are not distributed.

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

In the browser, create the administrator, enter the VPS public IPv4 address,
IPv6 address, or DNS name, choose a REALITY target and SNI, and create the first
device. Enter an IPv6 address without brackets or a port, for example
`2001:db8::1`. Use a DNS name with both A and AAAA records to let clients choose
their available address family. Import the QR code, VLESS link or JSON profile
into a client. The public port shown in the setup screen comes from `.env`; it
is not edited in the panel. A working public inbound is created when the first
device is applied.

## What is available

- Device creation, enable/disable/revoke, QR code, VLESS link and JSON export.
  New devices are normally applied through Xray's gRPC API without restarting
  the Xray process; the supervisor validates and applies full config changes.
- Online and last-seen indicators, cumulative upload/download totals, and live
  panel updates through SSE.
- Node settings with a preview of changes, confirmation and an automatic
  backup before changes that revoke existing profiles. The Settings page also
  controls Xray log verbosity (`debug`, `info`, `warning`, `error`, `none`);
  changing it restarts Xray and briefly interrupts active connections without
  revoking device profiles. Debug logging is verbose, so return to `warning`
  after troubleshooting.
- Password login, optional TOTP with recovery codes, three-hour sessions, and
  a command to sign out all sessions. The Security page can change the
  administrator password; the change ends every active session.
- Diagnostics showing supervisor state, configured and running Xray versions,
  and recent redacted warnings/errors.
- Manual and automatic backups in `/data/backups`; the last ten are retained.
  Backups are plaintext, so protect the VPS and any copies you export.

The Compose control and Xray egress networks have IPv6 enabled. Xray's public
TCP port is published on the VPS and mapped to container port `8443`; Docker
publishes it on IPv4 and IPv6 host addresses when the host daemon supports
dual-stack port publishing. The panel remains mapped only to `127.0.0.1` on the
VPS. Xray and the control plane share a private supervisor token, and their
persistent state lives in Docker named volumes. IPv6 handling in Compose,
profiles and `doctor` is implemented; actual reachability still depends on the
VPS IPv6 route, Docker daemon and firewall, so verify it with the checks below.

## IPv6 checks

Docker Desktop can check the Compose file and create an IPv6-enabled network,
but it does not prove IPv6 routing on a Linux VPS. On the VPS, confirm it has a
global IPv6 address and a default route:

```sh
ip -6 address show scope global
ip -6 route show default
```

Allow inbound TCP on the configured Xray port in both the VPS firewall and the
provider security group. Then, from a separate IPv6-capable device, test the
VPS address and port before importing the profile:

```sh
nc -6 -vz 2001:db8::1 443
```

Replace the example address and port with the VPS values. A successful TCP test
checks reachability only; finish by connecting with the client and opening a
site. For DNS profiles, verify the hostname's AAAA record points to a working
IPv6 endpoint before publishing it. Clients may try the AAAA record first, so a
stale or unreachable IPv6 address can make an otherwise working profile appear
unstable.

`xray-easy doctor` also checks outbound IPv6 TCP connectivity from the Xray
container by opening a short connection to Cloudflare's public IPv6 resolver at
`[2606:4700:4700::1111]:443`, then closing it without sending application data.
It reports a warning if that route is unavailable; IPv4 can still work. This
probe cannot confirm inbound reachability, provider firewall rules, or
application traffic to every IPv6 destination. Docker uses an IPv6-enabled
bridge with NAT by default, so outbound connections should appear to remote
sites from the VPS address. If the IPv6 Docker network cannot be created, check
the [Docker daemon IPv6 setup](https://docs.docker.com/engine/daemon/ipv6/) and
the host's kernel IPv6 support.

## Day-to-day commands

Run commands from the repository directory on the VPS:

```sh
docker compose ps
docker compose logs --tail=100 xray xray-easy
docker compose logs -f xray
docker compose down                         # stop, preserving named volumes
docker compose up -d --build --wait          # start again
docker compose exec -T xray-easy xray-easy doctor
docker compose exec -T xray-easy xray-easy doctor bundle
```

`./install.sh` runs the same doctor command after Compose reports both services
healthy. `PASS` completes installation; warnings are shown for follow-up (for
example, pending first-run setup, an unavailable optional stats RPC, IPv6
egress, or the VDS firewall, which cannot be checked from inside Compose). A
`FAIL` leaves the containers and configuration in place and prints the command
to rerun doctor after fixing the reported issue. Doctor checks the active
config without applying it or restarting Xray. If the control-plane container is stopped, run
a one-off diagnostic container with:

```sh
docker compose run --rm --no-deps xray-easy doctor
docker compose run --rm --no-deps xray-easy doctor bundle
```

`doctor bundle` prints the same checks and saves a `.tar.gz` archive under
`/data/diagnostics` in the persistent app volume. Its first report lines show
the Xray-easy build and configured Xray image versions, plus the public/UI
ports from the active Compose environment. It contains that report, Xray
supervisor status, up to 100 recent Xray log lines,
and a redacted active config. It saves the archive even when a check fails, but
still exits with a non-zero status in that case. It omits the database, master key, supervisor
token, client UUIDs, names, REALITY private key, and short IDs. Review the
archive before sharing it: non-secret server settings such as the REALITY
target and SNI remain useful for troubleshooting. When the control-plane
service is running, copy a generated file to the current directory with the
path printed by the command:

```sh
docker compose cp xray-easy:/data/diagnostics ./doctor-reports
```

The command copies all generated bundles; share the specific archive printed by
`doctor bundle`.

To update the code, create a backup from the Security page or CLI, then run:

```sh
git pull
./install.sh
```

Changing `XRAY_VERSION` is a separate manual change. Create a backup before
editing `.env`, rebuild the Xray image, and run `doctor` before relying on an
unverified version.

The installer keeps an existing `.env` and supervisor token. Keep the value of
`XRAY_EASY_MASTER_KEY`: it decrypts the stored REALITY private key and verifies
backups. Changing the public port in `.env` affects issued profiles and requires
reviewing their replacement in the panel.

Administrative commands run inside the control-plane container:

```sh
docker compose exec xray-easy xray-easy admin logout-all
docker compose exec xray-easy xray-easy admin reset-password
docker compose exec xray-easy xray-easy admin reset-totp
docker compose exec xray-easy xray-easy admin recovery-codes
docker compose exec xray-easy xray-easy backup create
docker compose exec xray-easy xray-easy backup list
docker compose exec xray-easy xray-easy restore BACKUP_NAME RESTORE
```

Use an actual name from `backup list` in place of `BACKUP_NAME`. Restore checks
the backup and master key and creates a backup of the current state before
applying it. Recovery-code reissue invalidates previous codes; TOTP reset
revokes all sessions. Password reset prompts twice without echoing input and
revokes all sessions; run it in an interactive terminal without `-T`. To copy
the unencrypted backup directories to the VPS filesystem before transferring
them over SSH:

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
docker compose exec -T xray-easy xray-easy doctor
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
