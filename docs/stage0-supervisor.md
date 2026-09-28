# Stage 0: Xray supervisor

This stage provides the process boundary that the Go control plane will use to
validate and apply generated Xray configurations. The supervisor is the PID 1
process in the Xray container and starts Xray as its child.

## Local setup

Create a token file before starting Compose:

```sh
mkdir -p prototype/secrets
openssl rand -hex 32 > prototype/secrets/xray_supervisor_token
chmod 600 prototype/secrets/xray_supervisor_token
```

The file is intentionally ignored by Git. The same secret is used by the
control plane to sign requests to the private supervisor API.

Compose copies this file through the one-shot `init-supervisor-secret` service
into a named volume owned by UID `10001`, so the source can safely remain mode
`0600` while the supervisor runs as a non-root user.

The prototype compose file exposes only the Xray public TCP port. Ports 10085
and 10086 bind to `172.31.240.2`, the service address on the internal control
network, and are not published to the host or the egress network.

## Supervisor API

Every request is authenticated with HMAC-SHA-256. The signature covers the HTTP
method, path, operation ID, nonce, and SHA-256 of the request body. The API is
versioned as `v1` and currently supports:

- `GET /health`
- `GET /status`
- `GET /logs`
- `POST /validate` with `{ "path": "/etc/xray/candidate.json", "operation_id": "..." }`
- `POST /apply` with the same body; validation succeeds before restart
- `POST /probe-target` with `{ "target": "example.com:443", "sni": "example.com" }`

The target probe performs a bounded TLS handshake. It does not accept an
arbitrary shell command or a path outside the mounted Xray config directory.

The current image tag is recorded in `versions/xray.env`. Before release, the
tag must be resolved to an immutable image digest and verified in CI.
