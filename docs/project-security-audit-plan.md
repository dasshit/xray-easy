# Project security audit and hardening plan

## Scope and constraints

This plan covers the whole repository after the web-admin boundary hardening in
`docs/web-admin-security-plan.md`. The changes must preserve the existing
administrator flow: the user still enters the same username, password, and
optional TOTP code, in the same order. This plan also preserves the private
Compose-network gRPC design; moving those links to TLS is a separate
deployment-level decision because every peer already authenticates with a
file-backed bearer token.

The goal is to reduce the impact of a compromised container, reject malformed
inter-service credentials consistently, and make dependency and static checks
repeatable in CI. No public gRPC port, Docker socket, or new external service
will be introduced.

## Audit baseline

The initial review found:

- `go vet ./...` passes for the root, AmneziaWG, and embedded-runtime modules.
- No tracked `.env`, private key, certificate, token, or database file was
  found; `.dockerignore` excludes local secrets and VCS metadata.
- The control plane is published on loopback and is intended to be reached
  through SSH forwarding. Xray, Controller, and AmneziaWG gRPC listeners are
  private Compose-network endpoints. AmneziaWG already runs read-only with
  dropped capabilities except `NET_ADMIN`.
- The control plane, Controller, and Xray runtime containers still have a
  writable root filesystem and no explicit `no-new-privileges`/capability
  policy. They only need their named data/config mounts to be writable.
- AWG unary authentication accepted the first value when duplicate
  `authorization` metadata was supplied, while the streaming interceptor
  already required exactly one value. This makes the two authentication paths
  inconsistent.
- Controller startup accepted any non-empty token text. Runtime and AWG token
  readers already enforce stronger minimum entropy and file permissions.
- Production images intentionally use a configurable `latest` default. This
  is convenient for development but a release deployment should pin a tested
  immutable release tag.
- `npm audit --omit=dev --audit-level=high` could not reach the npm registry in
  the audit environment because DNS resolution was unavailable. The command
  must therefore run in CI, where the network is available, rather than being
  treated as a local pass.

## Implementation stages

### Stage 1 — Harden long-running containers

Add the following Compose restrictions to `xray-core-service`, `controller`,
and `control-plane`:

- `read_only: true`;
- `security_opt: [no-new-privileges:true]`;
- `cap_drop: [ALL]`;
- a writable `/tmp` tmpfs.

Named volumes remain the only writable persistent locations. The short-lived
root init jobs keep their current root identity because they create mount
points, change ownership, and generate secrets. Their lifetime and
`restart: no` policy limit the exposure. Do not add these restrictions to the
AWG service in a way that removes its required `NET_ADMIN` capability or TUN
device access.

Validate the rendered Compose file and build/start checks after the change.

### Stage 2 — Make all private credentials strict and consistent

Change the Controller token reader to require a base64 value containing at
least 32 decoded random bytes and to reject group/world-readable token files.
The existing init job already generates a compatible token, so this is a
validation-only tightening. Update unit fixtures to use realistic tokens.

Require exactly one `authorization` metadata value in the AWG unary
interceptor, matching the streaming interceptor. Empty, duplicate, malformed,
or mismatched values must return `Unauthenticated`; add focused unit coverage
for each case. Keep constant-time comparison and do not log token material.

### Stage 3 — Repeatable dependency and static security checks

Extend GitHub Actions with a security-audit job (or an equivalent step in the
existing test workflow) that runs:

- `go vet ./...` in each Go module;
- `npm audit --omit=dev --audit-level=high` after `npm ci`;
- the existing Go unit/race/coverage and web lint/type/test gates.

The job should upload command output on failure and must not make the normal
local Docker build depend on a globally installed security tool. Keep action
versions on the repository's current Node 24-compatible major versions.

### Stage 4 — Document secure release operation

Add a concise security section to the README and translated README copies:

- keep the UI loopback-bound and access it over SSH;
- set `XRAY_EASY_SECURE_COOKIES=true` and enable an HTTPS reverse proxy only
  when the proxy is trusted and `XRAY_EASY_TRUST_PROXY=true` is appropriate;
- pin `XRAY_EASY_IMAGE_TAG` to a tested release instead of `latest` in
  production;
- explain that private gRPC links are bearer-authenticated and isolated on
  Compose networks;
- provide the local and CI audit commands.

### Stage 5 — Verification and release

Run Go tests, web tests/typecheck/lint/build, Compose config validation, and
the security audit commands. Review the diff for accidental secret or
credential logging, run `git diff --check`, create a dedicated implementation
commit, and only then create and push the `v1.4.1` tag together with `main`.

## Out of scope

This audit does not redesign user authentication, add login rate limiting,
replace private-network gRPC with mTLS, rotate existing credentials, or
introduce a WAF. Those are separate changes with deployment and recovery
implications.
