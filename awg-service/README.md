# AmneziaWG service

This Go module provides the optional AmneziaWG service alongside Xray-easy. It embeds the pinned
[`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go) engine in a
userspace TUN device and exposes an authenticated gRPC API. The installer
enables its Compose profile, the authenticated Web UI manages peers and client
profiles, `doctor` checks runtime state, and backup/restore includes the
service's persistent state and private client profiles.

## Runtime model

- `awg-service serve` creates the TUN interface, configures the engine and
  peer state, enables IPv4/IPv6 forwarding and NAT, then serves gRPC.
- The public service is UDP only. gRPC binds to the private control-network
  address configured by `AWG_GRPC_LISTEN`; Compose does not publish it to the
  host.
- The service runs as UID `0`, GID `10001` inside the container because the
  Linux TUN `TUNSETIFF` ioctl needs effective `CAP_NET_ADMIN`. Compose drops all
  capabilities and adds back only `NET_ADMIN`; the root filesystem is
  read-only and `no-new-privileges` is enabled. The data volume is owned by
  this UID/GID, and no host root filesystem paths are mounted. It needs
  `/dev/net/tun` and a Linux Docker host. Rootless Docker or a host/container
  policy that blocks TUN ioctls may still prevent interface creation.
- Separate IPv4 and IPv6 routes are discovered at startup. Each address family
  uses its own egress interface for forwarding and masquerading. Both routes
  are required because client profiles route all IPv4 and IPv6 traffic through
  the tunnel.
- Peer changes use the engine UAPI directly and do not restart the container.
  The service writes the peer to persistent state after applying it live and
  rolls the live change back if persistence fails. Restoring a backup validates
  the server key, peer state and matching private client profiles before it
  replaces live state; a failed apply restores the old peers and profiles.

## Persistent data and secrets

`AWG_MASTER_KEY` must be base64 encoding at least 32 bytes. Compose passes the
installation's `XRAY_EASY_MASTER_KEY`. The server private key is encrypted in
`/data/state.json` using AES-GCM; peer public keys, addresses and creation times
are stored there in plaintext. The header-protection key is derived with a
separate HMAC context from the same master key.

Each client private key exists only in process memory while creating or
refreshing a profile and in `/data/profiles/NAME.conf` for delivery. Profile
files are mode `0600`; treat them as credentials. Peer removal revokes the key
from the live engine, persists that state, and deletes the corresponding saved
profile. Copies already exported from the container are not deleted.

The gRPC bearer token is provisioned once into a dedicated Compose volume with
mode `0440`; the control network and data volume are private to the deployment.
The service uses plaintext gRPC protected by the token, so do not publish the
port or attach untrusted containers to the control network.

## Commands

All commands run in the AWG container. `peer-add` creates a client keypair,
registers the public key live and persistently, then saves the private client
profile in the AWG volume. `profile` rewrites that saved profile using current
shared transport settings without placing the private key in shell arguments.

```sh
docker compose --profile awg-prototype exec -T amneziawg-service awg-service status
docker compose --profile awg-prototype exec -T amneziawg-service awg-service peer-list
docker compose --profile awg-prototype exec -T amneziawg-service awg-service peer-add --name iphone
docker compose --profile awg-prototype exec -T amneziawg-service awg-service profile --name iphone
docker compose --profile awg-prototype exec -T amneziawg-service awg-service peer-remove --name iphone
```

In a regular deployment with AmneziaWG enabled by `./install.sh`, the
control-plane UI is the normal peer management interface. These container CLI
commands remain available for diagnostics and advanced maintenance. Use the
configured Compose profile (`awg` for current deployments, `awg-prototype` for
an older prototype environment).

`peer-add` and `profile` print JSON containing the profile path, not the
private key. Copy the profile out with `docker compose cp`. `keygen` prints a
keypair to stdout for advanced/manual use; avoid shell tracing or logging its
output.

## gRPC contract

The typed contract is in [`../awg-contract/api/v1/control.proto`](../awg-contract/api/v1/control.proto)
and the Go stubs are generated in the lightweight `awg-contract` module. Run
`scripts/generate-protobuf.sh` from the repository root to regenerate all
private service bindings. The API is registered as
`/xrayeasy.awg.v1.Control/{Method}`. Calls must include metadata:
`authorization: Bearer <base64 token from /data/control.token>`.

| Method | Typed request | Typed response |
| --- | --- | --- |
| `GetStatus` | `google.protobuf.Empty` | `StatusResponse`, including server key, endpoints, peer count and client networks |
| `ListPeers` | `google.protobuf.Empty` | `ListPeersResponse`; each `Peer` has a `Timestamp` creation time |
| `GetPeerStats` | `google.protobuf.Empty` | `GetPeerStatsResponse`; `int64` byte counters, source IP and optional handshake timestamp |
| `AddPeer` | `AddPeerRequest` | `Peer`; activates it immediately |
| `RemovePeer` | `RemovePeerRequest` | `RemovePeerResponse` |
| `CreatePeer` | `CreatePeerRequest` | `Peer`; generates keys, activates the peer and saves its private profile |
| `GetClientConfig` | `GetClientConfigRequest` | `ClientConfigResponse`; returns the active peer's saved profile |
| `ExportBackup` | `google.protobuf.Empty` | `BackupResponse` with raw archive `bytes` (no base64 at the RPC layer) |
| `RestoreBackup` | `RestoreBackupRequest` with archive `bytes` | `RestoreBackupResponse`; validates and applies a complete snapshot without restarting the container |
| `RenderClientConfig` | `RenderClientConfigRequest` | `ClientConfigResponse`; verifies that the private key matches the registered peer |

This private contract is wire-incompatible with the earlier Struct prototype;
update the Controller/backend and AWG containers from the same checkout.

Names contain 1–32 ASCII letters, digits or hyphens. Keys use standard
base64-encoded 32-byte Curve25519 values. The control API never stores a client
private key in the state file. Backup archives include the client profiles, so
they contain private keys and must be protected as plaintext credentials.

## Obfuscation settings

The default AmneziaWG 3.x settings mirror the current client implementation:
Jc 4, Jmin 10, Jmax 50, S1–S4 12, H1–H4 1–4, I1 payload, header protection,
content padding, timing ranges, random trailers and disabled cookies. The
server and generated profiles use the same settings. Supported `AWG_*`
overrides are listed in the root `.env.example`. After changing an override,
recreate the service and run `profile --name NAME` for every peer before
re-importing those profiles.

These values establish protocol compatibility; they are not a claim that a
particular profile will evade DPI or work through every network.

## Validation boundary

Unit tests, race checks, `go vet`, Linux amd64/arm64 cross-builds, Compose
configuration validation and a local image build run off-VDS. On a VDS, a clean
AWG volume passed checks with the official AmneziaWG iOS client: a new profile
connected and carried traffic; peer state survived an AWG container restart and
a VDS reboot; backup/restore recovered a revoked test peer and its profile, and
the client connected again. The earlier AWG volume failed AES-GCM key
authentication and was reinitialized, so migration and recovery of that old
encrypted state remain unverified. Long-term stability, macOS clients and IPv6
egress still need separate validation.
