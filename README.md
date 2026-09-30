# Xray-easy

<div align="center">
  <p><img src="web/public/favicon-light.svg" width="48" height="48" alt="Xray-easy icon"></p>
  <p><img src="docs/assets/xray-easy-banner.svg" width="100%" alt="Xray-easy — a private VPN control panel for your own server"></p>
  <p><strong>Self-hosted VPN, managed from a private web panel.</strong><br>
  Build it on your VPS, open the panel through SSH, and create client profiles without editing Xray configs by hand.</p>
</div>

Xray-easy is a Docker Compose application for one administrator and one server.
It combines Xray and optional AmneziaWG with a web UI for setup, device
profiles, diagnostics and maintenance. The panel listens on the VPS loopback
interface and is intended to be accessed through an SSH tunnel.

## Contents

- [Quick start](#quick-start)
- [Ports and firewall](#ports-and-firewall)
- [Protocol guide: Xray](#protocol-guide-xray)
- [Protocol guide: AmneziaWG](#protocol-guide-amneziawg)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Security and architecture](#security-and-architecture)
- [Development](#development)

## Quick start

### Requirements

- Linux VPS with an **amd64** or **arm64** CPU and SSH access.
- Docker Engine **28.0.0+** and Docker Compose plugin **2.33.1+**.
- A public IPv4 address or DNS name. IPv6 can also be used when the VPS,
  Docker and firewall have working IPv6 routing.
- An available public TCP port, **443** by default.

The VPS needs outbound network access to build/download dependencies and to
carry VPN traffic. Go and Node.js are not required on the VPS: the installer
builds the project images from the cloned source.

### 1. Clone and install

Run these commands on the VPS:

~~~sh
git clone https://github.com/dasshit/xray-easy.git
cd xray-easy
./install.sh
~~~

The installer opens a full-screen terminal wizard. It checks Docker, guides
you through the public and panel ports, optional Hysteria 2 TLS and optional
AmneziaWG, then creates the secrets, builds the images, starts Compose and runs
the final health check. Use **↑/↓** or **Tab** to move, **Enter** to continue,
**Esc** to cancel and **Ctrl+C** to stop.

Images are built locally from this checkout; prebuilt application images are
not published. If a service does not become healthy, the installer keeps the
configuration for troubleshooting and prints recent logs and recovery
commands. It reuses existing keys and Docker volumes on repeat runs.

### 2. Open the panel through SSH

Keep this command running on your own computer. Replace the SSH user, VPS host
and port if you chose a panel port other than 8080:

~~~sh
ssh -N -L 8080:127.0.0.1:8080 user@your-vps
~~~

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080) in a browser. The panel
is bound to **127.0.0.1 on the VPS**; do not expose its port in a public
firewall or reverse proxy.

### 3. Finish first-run setup

In the panel:

1. Create the administrator login and password.
2. Set the public host clients will use: the VPS IPv4, IPv6, or a DNS name.
   For dual-stack DNS, configure working A and AAAA records.
3. Choose the REALITY target and SNI for the default VLESS profile.
4. Create the first device and select its protocol.
5. Scan the QR code or download/copy the profile into the matching client.

The installer configures deployment-wide values such as public ports. The
panel manages protocol settings and individual devices. Enable TOTP from the
Security page after the first login.

## Ports and firewall

Allow only the ports for transports you use. Apply the rules in both the VPS
firewall and the provider security group, for IPv4 and IPv6 where enabled.

| Transport | Default public port | Protocol | Notes |
| --- | ---: | --- | --- |
| VLESS + REALITY | 443 | TCP | Default Xray profile |
| Hysteria 2 | 443 | UDP | Optional; shares the public port number with VLESS |
| VMess + TLS | 9443 | TCP | Optional separate Xray inbound |
| AmneziaWG | 1234 | UDP | Optional separate service |
| Web UI | 8080 | TCP, loopback only | Reach through SSH; never open publicly |

Ports are configurable during installation and stored in the root **.env**
file. Xray uses **XRAY_PUBLIC_PORT** for VLESS TCP and optional Hysteria 2 UDP,
and **XRAY_VMESS_PORT** for VMess TCP. AmneziaWG uses **AWG_PUBLIC_PORT**.

## Protocol guide: Xray

The `xray` container runs the project runtime service with Xray-core embedded
as a Go library. The project pins Xray **26.7.28** as the currently verified
version for its API integration and VLESS + REALITY profile workflow.
The UI and doctor report when the configured or running version differs from
the verified compatibility record at
[versions/xray-compatibility.json](versions/xray-compatibility.json). Treat
other versions as experimental until tested with your clients.

| Profile type | Transport and security | Profile delivery |
| --- | --- | --- |
| VLESS | TCP/RAW + REALITY + XTLS Vision | QR, VLESS link, JSON |
| Hysteria 2 | UDP + TLS | QR, hysteria2 link |
| VMess | TCP + TLS, alterId 0 | QR, vmess link, JSON |

Each new profile uses one protocol. To give one device multiple transports,
create a separate profile for each one with the same device name.

### VLESS + REALITY

This is the default protocol. New clients are added live through Xray's
HandlerService while one of five reserved REALITY short IDs is available.
When the reserve is exhausted, Xray replaces the VLESS inbound; its active
connections may briefly reconnect. The UI validates and previews sensitive
settings changes before applying them and creates an automatic backup where
needed.

Changing the REALITY key, target or SNI can invalidate issued profiles. Follow
the warning in the panel and re-import refreshed profiles on clients. Xray
log verbosity is managed separately in Settings; debug logs are verbose, so
return to warning after troubleshooting.

### Hysteria 2

Hysteria 2 runs as an optional UDP inbound in the same Xray container. Enable
it during installation or later from **Settings → Hysteria 2**. Its profiles
have an independent password and are available once the inbound and TLS
certificate are ready.

The TLS setup supports two modes:

- **mkcert certificate:** the installer generates a certificate for a
  public IPv4 address. Generated client links use **insecure=1**. This lets
  clients connect but disables server certificate verification, so the client
  does not authenticate the server against a man-in-the-middle.
- **Custom certificate:** provide a matching PEM full chain and private key.
  Use a certificate trusted by clients and whose name matches the endpoint or
  configured SNI. Links use normal certificate verification.

The panel can enable/disable the inbound, update TLS and transport settings,
and replace certificates. Applying changes may briefly reconnect Hysteria 2
clients; VLESS remains running. Allow inbound UDP on the configured Xray
public port.

### VMess + TLS

VMess uses a separate TCP port, **9443** by default. It reuses the certificate
managed under **Settings → Hysteria 2**, even if the Hysteria 2 inbound is
disabled. Configure that certificate before creating a VMess profile.

For self-signed or legacy certificates, the generated VMess link pins the
certificate fingerprint and the downloadable Xray JSON uses
**pinnedPeerCertSha256**. Client and server clocks should be within about two
minutes. Re-import profiles after replacing the certificate. VMess is provided
for compatibility and is easier to identify by traffic analysis than VLESS +
REALITY or Hysteria 2; it is not presented as a DPI-resistance improvement.

### Xray status and troubleshooting

Profiles show online/last-seen state, cumulative upload/download, sampled
current rates and the last observed source IP when the protocol reports it.
Online status is a five-minute freshness estimate; rates are sampled over the
control plane's ten-second polling interval.

Run the doctor from the VPS repository directory:

~~~sh
docker compose exec -T xray-easy xray-easy doctor
~~~

It checks configuration, runtime/API availability, version compatibility and
network prerequisites. It cannot test inbound firewall reachability from
inside Compose; verify public ports from another network. For IPv6-specific
checks, see [IPv6 verification](#ipv6-verification).

## Protocol guide: AmneziaWG

AmneziaWG is an optional independent service, not an Xray inbound. Enable it
in the installer and enter the public IP or DNS name clients will connect to.
It appears in the shared **Profiles** workflow alongside Xray protocols and
in **Settings** as a read-only summary of the active endpoint, ports, address
pools, peer count, server public key and service version.

The service requires a **Linux Docker host**, **/dev/net/tun**, the
**NET_ADMIN** capability, IPv4 and IPv6 forwarding, and working egress for both
address families. Rootless Docker or host policies that block TUN access may
prevent startup. The default public UDP port is **1234**; the internal listen
port is **51820**. Allow the public port in the VPS and provider firewalls.

Profiles include the client private key. Scan the QR code with the official
AmneziaWG client on iOS or macOS, or download the **.conf** file. Handle both
as credentials. Peer changes apply to the live engine without restarting its
container. Revoking a peer creates an automatic backup first and deletes the
saved profile from the server.

The profile list reports handshake-based online state, last seen, cumulative
and sampled traffic, plus source IP when available. These are observations
from the latest handshake, not a live socket count. The built-in AmneziaWG 3.x
obfuscation preset matches current client defaults. Advanced overrides are
available through **AWG_*** values in **.env.example**; changing shared
parameters requires refreshing and re-importing client profiles.

AmneziaWG allocates addresses from **10.88.0.0/24** and **fd88:88:88::/64** by
default, with DNS **1.1.1.1** and **2606:4700:4700::1111**. Change these
networks if they overlap routes already used by the VPS.

## Operations and troubleshooting

### Logs, status and upgrade

Run commands from the repository directory on the VPS:

~~~sh
docker compose ps
docker compose logs --tail=100
docker compose logs -f xray
docker compose logs -f
~~~

To update from source, create a backup first, then pull and rerun the installer:

~~~sh
git pull
./install.sh
~~~

The installer keeps the existing **.env**, secret and Docker volumes. Keep
**XRAY_EASY_MASTER_KEY** unchanged: it encrypts the persisted Xray and
AmneziaWG server keys and is required to restore backups. The embedded runtime
currently pins Xray-core **26.7.28**; changing **XRAY_VERSION** to another value
causes the image build to stop until that embedded version has been deliberately
updated and verified.

During the embedded runtime rollout, the previous supervisor Compose file is
available for rollback. It uses the same project name and persistent data
volumes as the default file. Run only one Compose variant at a time:

~~~sh
docker compose -f compose.supervisor-rollback.yaml up -d --build --wait --wait-timeout 180
~~~

Return to the embedded runtime with `docker compose up -d --build --wait` after
the cause is resolved.

### Backups and restore

The Security page can create a manual backup. The application also creates
automatic backups before operations such as changing Hysteria 2 settings,
rotating REALITY credentials or revoking an AmneziaWG peer. The ten newest are
kept under **/data/backups** in the persistent Docker volume. Backups are
plaintext, so protect the VPS and any exported copies. Create a manual backup
before updating the checkout.

~~~sh
docker compose exec xray-easy xray-easy backup create
docker compose exec xray-easy xray-easy backup list
docker compose exec xray-easy xray-easy restore BACKUP_NAME RESTORE
docker compose cp xray-easy:/data/backups ./backups
~~~

Replace **BACKUP_NAME** with a name from the list. Restore requires the backup
name and the confirmation word **RESTORE** as CLI arguments, validates the
snapshot, then backs up the current state before applying it. AWG data can only
be restored when AmneziaWG is enabled in Compose.

### Administrator recovery

These commands run in the control-plane container:

~~~sh
docker compose exec xray-easy xray-easy admin reset-password
docker compose exec xray-easy xray-easy admin reset-totp
docker compose exec xray-easy xray-easy admin recovery-codes
docker compose exec xray-easy xray-easy admin logout-all
~~~

Password reset prompts twice without echoing input and revokes all sessions.
Run it in an interactive terminal without **-T**. TOTP reset and recovery-code
reissue also invalidate sessions or previous codes as appropriate.

### Doctor bundle

If doctor reports a failure, create a support bundle:

~~~sh
docker compose exec -T xray-easy xray-easy doctor bundle
docker compose cp xray-easy:/data/diagnostics ./doctor-reports
~~~

The bundle contains the doctor report, Xray runtime status, recent Xray
logs and a redacted active config. It omits database contents, keys, tokens,
UUIDs, device names and REALITY short IDs. The selected REALITY target and SNI
remain in the report; review the archive before sharing it.

### IPv6 verification

On the VPS, check for a global IPv6 address and a default route:

~~~sh
ip -6 address show scope global
ip -6 route show default
~~~

From another IPv6-capable network, test the public Xray TCP port:

~~~sh
nc -6 -vz 2001:db8::1 443
~~~

Replace the example address and port. A successful TCP check confirms basic
reachability only; also test an actual client connection. For DNS profiles,
confirm the AAAA record points to a working endpoint. Doctor tests outbound
IPv6 connectivity from the Xray container, not public inbound reachability.

## Security and architecture

- The web panel is published only on the VPS loopback interface. Admin access
  is through SSH port forwarding, with password login and optional TOTP.
- Backend, Controller, the embedded Xray runtime and optional AmneziaWG use
  separate containers and private Compose networks. Runtime gRPC ports are not
  published to the VPS. A temporary `compose.supervisor-rollback.yaml` is kept
  for rollback during the embedded runtime rollout.
- Internal RPC links use authentication but are not encrypted; keep them on
  the private Docker networks and do not attach untrusted containers.
- **XRAY_EASY_MASTER_KEY** must be base64 encoding at least 32 bytes. The
  installer generates it on first run. Store it safely and keep it for the
  lifetime of the data volume.
- Backups are plaintext and include credentials needed to restore devices.
  Secure backup files and copied client profiles as secrets.
- Interaction logs correlate backend, Controller and runtime calls with a
  random request ID. They include method, result and duration, not RPC payloads
  or profiles. Xray core connection logs do not include that request ID.

## Development

The backend, Controller, embedded Xray runtime and AmneziaWG service are Go
components; the web UI uses TypeScript, Vue and Vite. Local development tools
are not required on the VPS.

Run the root backend tests and coverage gate:

~~~sh
go test ./...
bash scripts/backend-coverage.sh
~~~

The AWG implementation and protobuf contract are separate Go modules:

~~~sh
cd awg-service && go test -race ./...
cd ../awg-contract && go test ./...
~~~

For web checks, run from **web/**:

~~~sh
npm ci
npm run lint
npm test
npm run test:coverage
npm run typecheck
npm run build
~~~

Regenerate checked-in typed protobuf bindings from the repository root with
**scripts/generate-protobuf.sh**. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for third-party components
and licenses.
