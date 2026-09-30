# Xray-easy

Xray-easy is a private web panel for one Xray server. It runs Xray and the Go
control plane in separate Docker containers and helps one administrator create
VLESS + REALITY + TCP/RAW + XTLS Vision profiles, plus optional VMess + TLS and
Hysteria 2 inbounds in the same Xray process. AmneziaWG is an optional,
independent container with its own Web UI section and UDP port. The panel is
bound to the server's loopback address; open it through an SSH tunnel.

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
public TCP port (443 by default). VMess + TLS also uses TCP port 9443 by
default. Hysteria 2 requires UDP on the VLESS port. These Docker versions are
required to choose the correct IPv4/IPv6 egress gateway for Xray. Allow inbound
TCP on the ports for the protocols you use in the VPS firewall/security group.
The VPS needs outbound access for Docker images and VPN traffic. AmneziaWG
additionally needs a Linux Docker host with `/dev/net/tun`, `NET_ADMIN`, IPv4
and IPv6 forwarding, and working egress for both address families. Go and
Node.js are **not required** on the VPS.

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
Docker/Compose, asks for the public and panel ports, the optional Hysteria 2
TLS mode and whether to enable AmneziaWG, generates the master key
and supervisor token, writes `.env` and `secrets/xray_supervisor_token` with
mode `0600`, then runs `docker compose up -d --build --wait`. It waits for the
services to become healthy, then runs the final `xray-easy doctor` check. A
repeat run reuses the existing keys and Docker volumes. After the first start,
manage Hysteria 2 settings and certificates in the Web UI. If Compose cannot make
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
  │  Public Xray TCP / UDP port                         │
  │  › [ 443 ]                                          │
  │  Web UI port on VDS loopback                        │
  │    [ 8080 ]                                         │
  │  VMess TCP defaults to 9443                         │
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
device profile. Enter an IPv6 address without brackets or a port, for example
`2001:db8::1`. Use a DNS name with both A and AAAA records to let clients choose
their available address family. Choose **VLESS + REALITY**, **VMess + TLS** when
a valid certificate is available in Settings, or **Hysteria 2** when enabled and
its certificate is ready. VMess does not require the Hysteria 2 inbound to be
enabled. The profile dialog shows that protocol's QR code and link; VLESS and
VMess profiles also offer JSON files. To give one device multiple transports,
create a separate profile for each transport with the same device name. The
VLESS/Hysteria public port and VMess TCP port come from `.env`; they are not
edited in the panel. The VMess host port defaults to 9443. An inbound is created
when the first profile for its protocol is applied.

## What is available

- Protocol-specific device creation, enable/disable/revoke and profile delivery.
  New profiles use either VLESS + REALITY, VMess + TLS or Hysteria 2, never a
  combination. Existing
  migrated profiles keep both transports and are marked as legacy in the list.
  Reopening a profile shows the same saved credentials; it does not rotate them.
- VLESS profiles provide a QR code, VLESS link and JSON export. Their fingerprint
  can be selected per profile.
- Hysteria 2 profiles provide a QR code and `hysteria2://` link, with an
  independently generated password by default. An administrator can set a
  password in the form's Advanced section. Hysteria 2 has no client JSON export.
  Its option is available only while the inbound is running and its certificate
  is valid; the form links to Settings when it is unavailable.
- VMess profiles provide a QR code, standard `vmess://` share link, and client
  JSON. The inbound uses TCP + TLS on the separate `XRAY_VMESS_PORT` (9443 by
  default), with `alterId: 0`. VMess reuses the certificate configured under
  **Settings → Hysteria 2**, even when the Hysteria 2 transport is disabled.
  Create or upload a certificate there before creating a VMess profile. For an
  self-signed or legacy certificate, the VMess link pins its SHA-256 certificate
  fingerprint (`pcs`) and the downloadable Xray JSON uses
  `pinnedPeerCertSha256`; trusted custom certificates use normal CA validation.
  Re-import the profile after changing the certificate. This compatibility
  option requires server/client clocks within about two minutes and is easier to
  identify by traffic analysis than VLESS + REALITY or Hysteria 2. It is not
  presented as a DPI-resistance improvement. Allow inbound TCP at
  `XRAY_VMESS_PORT` in the VPS firewall/security group.
- The REALITY short-ID reserve holds five free values. While IDs remain in the
  reserve, new VLESS users are added through HandlerService without restarting
  Xray. When it is exhausted, Xray's gRPC API replaces only the VLESS inbound;
  its active connections may briefly reconnect. The control plane validates
  candidate configs and reconciles SQLite, `active.json` and runtime state after
  interruptions.
- Optional Hysteria 2 profile transport for V2Rage. It runs as a second inbound
  in the same Xray container, on UDP at `XRAY_PUBLIC_PORT`. During the initial
  `./install.sh`,
  choose one of three options:

  1. **Off:** VLESS/REALITY only. This is the default.
  2. **mkcert for public IPv4:** enter the VPS public IPv4. If the installer
     finds one public IPv4 on the host, press Enter to accept its suggestion;
     otherwise type the address. The Web UI suggests the selected address
     during first-run setup and requires the public host to match it. The
     installer builds `mkcert` and generates a certificate with that IP in its
     SAN. The CA is not installed
     into any trust store and its private key is discarded. Generated Hysteria 2
     links include `insecure=1`. This disables server certificate verification
     in the client, so this mode does not authenticate the server against a
     man-in-the-middle. The certificate is kept in a Docker volume and reused
     on repeat installation until it is within 30 days of expiry or the
     configured IPv4 changes. Run `./install.sh` again to renew it later.
  3. **My TLS certificate:** enter paths to a PEM full chain and matching
     private key on the VPS. You can leave them blank if they are already at
     `secrets/hysteria/fullchain.pem` and `secrets/hysteria/privkey.pem`. The
     installer checks the pair and imports it. Enter a DNS name or IP address
     covered by the certificate. If clients connect to an IPv4 address while
     the certificate covers a DNS name, enter that DNS name; it becomes the
     URI `sni` value. These links
     omit `insecure`, so clients verify the certificate normally. Make sure
     the chain is trusted by your clients.

  The control plane manages the Hysteria TLS volume; Xray mounts it read-only.
  After setup, use **Settings → Hysteria 2** to enable or disable the inbound,
  generate a mkcert certificate, upload a trusted PEM pair, or change host/SNI
  and advanced transport options. Settings are stored in SQLite; the Hysteria
  `.env` values only seed a new installation. The private key is not sent to the
  browser. Each change shows a preview and creates a backup. It updates only the
  affected Hysteria 2 and/or VMess inbounds; active connections on those
  inbounds may briefly reconnect, while VLESS stays running. A host, SNI,
  certificate or TLS-mode change can require importing updated profile links.
  Allow inbound UDP at `XRAY_PUBLIC_PORT` in the VPS firewall/security group.
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
VLESS TCP port is published on the VPS and mapped to container port `8443`;
the VMess TCP port is mapped to container port `8444`. Docker publishes them on
IPv4 and IPv6 host addresses when the host daemon supports
dual-stack port publishing. The panel remains mapped only to `127.0.0.1` on the
VPS. Xray and the control plane share a private supervisor token, and their
persistent state lives in Docker named volumes. IPv6 handling in Compose,
profiles and `doctor` is implemented; actual reachability still depends on the
VPS IPv6 route, Docker daemon and firewall, so verify it with the checks below.

The control plane communicates with `xray-supervisor` over authenticated gRPC
on the private Compose `control` network. The gRPC port is not published on the
VPS. Requests use HMAC-SHA256 signatures and replay-protected nonces; this
authenticates requests but does not encrypt traffic, so keep the service on the
private Docker network. The in-container healthcheck uses the same gRPC API.

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

## Optional AmneziaWG transport

The installer can enable a separate `awg` container. It runs the pinned
AmneziaWG Go engine, exposes only a token-protected gRPC API on the private
Compose control network, and publishes the configured UDP port. The API is not
published to the host. Xray and AmneziaWG remain independent services.

To enable it during initial setup or later, run `./install.sh`, choose
**Enable for AmneziaWG clients**, and enter the public IP address or DNS name
that clients will use. The installer stores `COMPOSE_PROFILES=awg`,
`AWG_PUBLIC_HOST`, and `AWG_PUBLIC_PORT` in `.env` and starts the service.
The public UDP port defaults to `1234` (mapped to UDP `51820` inside the
container); the installer rejects a collision
with the Xray UDP port. Allow inbound UDP `AWG_PUBLIC_PORT` for IPv4 and IPv6
in the VDS firewall and provider security group.

AmneziaWG requires a Linux Docker host with `/dev/net/tun`, the `NET_ADMIN`
capability, IPv4/IPv6 forwarding, and working egress for both address families.
The service configures separate NAT rules for the IPv4 and IPv6 egress
interfaces and reports a startup error when either route is unavailable. It
uses the default client networks `10.88.0.0/24` and `fd88:88:88::/64`, with DNS
servers `1.1.1.1` and `2606:4700:4700::1111`; do not overlap those networks
with routes already used by the VPS.

When the optional Compose profile is enabled, create an AmneziaWG device from
the shared **Profiles** screen by choosing **AmneziaWG** in the protocol list.
It appears alongside VLESS, VMess and Hysteria 2 profiles. Open its profile to
scan the QR code in the official AmneziaWG client on iOS or macOS, or download
the `.conf` file. The profile contains the client's private key. Treat QR
codes, downloads and backups as credentials; transfer them securely and do not
commit or attach them to diagnostics. Revoking a peer creates an automatic
backup first, removes its saved profile from the volume and records a redacted
audit event. AmneziaWG is read-only in **Settings**, where the active endpoint,
ports, networks, peer count, server public key and service version are shown.

The shared profile list shows online/offline state, last seen, cumulative
upload/download, current sampled upload/download rates and observed source IPs.
Xray source addresses come from StatsService IP observations; AmneziaWG uses
the remote endpoint from its latest handshake. Online is a five-minute
freshness estimate, not a live socket count. Speeds are averages over the
control plane's ten-second polling interval, not link limits; they are zeroed
when a device is offline or a sample becomes stale. Source IP is omitted when
the protocol has not reported a recent address.

The service allocates IPv4 and IPv6 addresses, enables full-tunnel routes, and
applies peer changes to the live engine without restarting the container. It
persists server state in `awg_data`; the server private key is encrypted using
`XRAY_EASY_MASTER_KEY`. Backups contain that state and saved client profiles.
Backups are plaintext with mode `0600`, so protect the VPS and any copies you
export. Restore requires the AmneziaWG Compose profile to be enabled and a
backup created while the service was enabled; otherwise the restore command
stops before changing application state. `doctor` checks the service, peer
state and warns that public UDP reachability must be verified from outside.
Deleting or recreating `awg_data` loses the server identity and peer state;
previously exported profiles will no longer connect and must be reissued.

If the public endpoint or shared AWG preset changes, reopen each device profile
in the Web UI and import the refreshed `.conf` or QR code. The service refreshes
the saved profile when it is requested; copies already exported to clients keep
their previous endpoint or obfuscation settings.

The built-in AmneziaWG 3.x preset follows current defaults in the
[official Amnezia client implementation](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/installers/awgInstaller.cpp):
`Jc=4`, `Jmin=10`, `Jmax=50`, `S1`–`S4=12`, `H1`–`H4=1`–`4`, header protection,
content padding, timing ranges, random trailers and disabled cookies. These
values provide protocol compatibility, not a guarantee against DPI or
blocking. Advanced container controls remain in `.env`; if you change shared
obfuscation values, recreate the `awg` service and re-import profiles so
client and server parameters match. The lower-level gRPC API and maintenance
commands are described in [awg-service/README.md](awg-service/README.md).
The unified profiles and telemetry implementation plan is recorded in
[docs/amneziawg-unified-profiles-plan.md](docs/amneziawg-unified-profiles-plan.md).

VDS checks passed with the official AmneziaWG iOS client: a clean AWG volume
connected and carried traffic; peer state survived a container restart and VDS
reboot; backup/restore recovered a revoked test peer and its profile, and the
client connected again. The previous volume failed key authentication and was
reinitialized, so upgrade/recovery from that existing encrypted state remains
unverified. Longer-term stability, macOS client coverage and IPv6 egress still
need separate verification.

Backend test coverage and the test plan are documented in
[docs/backend-test-plan.md](docs/backend-test-plan.md). Run
`bash scripts/backend-coverage.sh` to check coverage thresholds locally.
The planned web unit-test coverage is documented in
[docs/web-test-plan.md](docs/web-test-plan.md).

Run web checks from `web/` with `npm ci`, `npm run lint`, `npm test`,
`npm run test:coverage`, `npm run typecheck`, and `npm run build`.
