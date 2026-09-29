# AmneziaWG service prototype

This Go module is an isolated prototype for managing AmneziaWG as an optional
service alongside Xray-easy. It embeds the pinned
[`amneziawg-go`](https://github.com/amnezia-vpn/amneziawg-go) engine in a
userspace TUN device and exposes a small authenticated gRPC API. The production
Xray-easy backend, Web UI, installer, backup flow and doctor do not manage it.

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
  rolls the live change back if persistence fails.

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

The gRPC bearer token is created once at `/data/control.token`, mode `0640`;
the control network and data volume are private to the Compose deployment. The
prototype uses plaintext gRPC protected by the token, so do not publish the
port or attach untrusted containers to the control network. Production
integration should define its final transport and identity policy explicitly.

## Commands

All commands run in the AWG container. `peer-add` creates a client keypair,
registers the public key live and persistently, then saves the private client
profile in the AWG volume. `profile` rewrites that saved profile using current
shared transport settings without placing the private key in shell arguments.

```sh
docker compose --profile awg-prototype exec -T awg awg-service status
docker compose --profile awg-prototype exec -T awg awg-service peer-list
docker compose --profile awg-prototype exec -T awg awg-service peer-add --name iphone
docker compose --profile awg-prototype exec -T awg awg-service profile --name iphone
docker compose --profile awg-prototype exec -T awg awg-service peer-remove --name iphone
```

`peer-add` and `profile` print JSON containing the profile path, not the
private key. Copy the profile out with `docker compose cp`. `keygen` prints a
keypair to stdout for advanced/manual use; avoid shell tracing or logging its
output.

## gRPC contract

The prototype contract is in [`api/v1/control.proto`](api/v1/control.proto).
For now every request and response uses `google.protobuf.Struct` to keep the
surface easy to call from the existing Go control plane while validating the
lifecycle. The API is registered as
`/xrayeasy.awg.v1.Control/{Method}`. Calls must include metadata:
`authorization: Bearer <base64 token from /data/control.token>`.

| Method | Request fields | Response |
| --- | --- | --- |
| `GetStatus` | none | Running state, server public key, public/listen endpoints, peer count and client networks |
| `ListPeers` | none | `peers[]` with name, client public key, IPv4/IPv6 and creation time |
| `AddPeer` | `name`, `publicKey` | Created peer metadata; activates it immediately |
| `RemovePeer` | `name` | `{ "removed": true, "name": ... }` |
| `RenderClientConfig` | `name`, `privateKey` | `{ "config": "..." }`; verifies that the private key matches the registered peer |

Names contain 1–32 ASCII letters, digits or hyphens. Keys use standard
base64-encoded 32-byte Curve25519 values. The control API never stores a client
private key in the state file.

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
configuration validation and a local image build run off-VDS. A VDS smoke test
succeeded with the official AmneziaWG iOS client: after creating and importing
a peer profile, the container was restarted, the peer and its addresses
persisted, and the client reconnected with working traffic. Long-term
stability, macOS clients, and IPv6 egress still need separate validation before
product integration.
