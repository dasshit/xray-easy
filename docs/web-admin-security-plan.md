# Web admin security plan

## Scope and compatibility constraint

This plan hardens the HTTP boundary of the control plane without changing the
administrator's visible login sequence. The existing sequence remains:

1. enter username and password;
2. if TOTP is enabled, enter a TOTP code or switch to a recovery code;
3. receive a session and open the dashboard.

The default deployment continues to bind the UI to the VDS loopback address
and is used through SSH port forwarding. The plan therefore must not mark the
session cookie `Secure` for ordinary HTTP-over-SSH access. HTTPS deployments
may opt in explicitly.

## Findings from the current implementation

### Existing protections

- Passwords use bounded Argon2id hashes and are never stored in plaintext.
- Session tokens are 256-bit random values; only SHA-256 hashes are stored.
- Session cookies are `HttpOnly` and `SameSite=Strict` with a three-hour TTL.
- TOTP secrets are encrypted with the master key and recovery codes are stored
  as hashes.
- The UI port is published on `127.0.0.1` by Compose and internal gRPC/token
  volumes are not published.
- JSON decoding has a one-megabyte limit, but the outer `requestLimit`
  middleware is currently a no-op.

### Findings to fix in this stage

1. State-changing routes do not validate the request origin. SameSite helps,
   but an explicit Host/Origin policy is needed for defense in depth and for
   deployments where a browser or reverse proxy changes cookie behavior.
2. `/api/auth/logout` performs a state change without restricting the method.
   It should accept POST only, matching the existing UI call.
3. The server sends no baseline browser security headers (CSP,
   `X-Content-Type-Options`, frame protection, referrer policy, or a restrictive
   permissions policy).
4. `requestLimit` does not cap request bodies or header/query abuse. JSON
   handlers have their own body limit, but this protection is inconsistent and
   does not cover all routes.
5. Authenticated/profile and event responses do not consistently declare
   `Cache-Control: no-store`; profile payloads are bearer credentials and must
   not be retained by browser/proxy caches.
6. The cookie has no explicit `Secure` opt-in for an HTTPS reverse proxy. It
   cannot be enabled by default because the supported SSH flow uses plain HTTP
   on localhost.

## Implementation stages

### Stage 1 — HTTP boundary middleware

- Add a single control-plane middleware that:
  - applies security headers to every response;
  - applies `Cache-Control: no-store` to `/api/` responses;
  - caps request bodies with `http.MaxBytesReader` while preserving the
    existing JSON error behavior;
  - validates Host/Origin (and same-origin Referer fallback) for
    state-changing browser requests without requiring a new UI field or token;
  - emits an explicit `Vary` header where request-origin decisions are made.
- Keep requests without browser origin metadata usable for CLI, tests, and
  local operational tooling. When Origin/Referer is supplied, it must match
  the request host and effective scheme.
- Add tests for matching/mismatching origins, method handling, body limits,
  headers, and cache policy.

### Stage 2 — Authentication and bearer-response hardening

- Make logout POST-only and use the same cookie attributes when clearing it.
- Add `XRAY_EASY_SECURE_COOKIES` (default `false`) and set `Secure` when it is
  enabled or the request is directly TLS-terminated. This preserves HTTP-over-
  SSH while making HTTPS reverse-proxy deployments explicit.
- Mark login, TOTP enrollment, recovery-code, logout, and profile delivery
  responses `no-store`; never add bearer URIs to logs or audit details.
- Add focused regression tests without changing the login form or TOTP steps.

### Stage 3 — Operational verification

- Run Go unit tests and web tests/typecheck/lint/build.
- Validate the Compose file and inspect the response headers with a local
  HTTP client.
- Document the optional secure-cookie environment variable and the fact that
  the normal SSH tunnel remains unchanged.

## Deferred items and residual risk

- Login rate limiting is intentionally not introduced in this stage: the
  supported exposure is SSH-only and the user-facing flow must remain stable.
  It is a separate follow-up if the panel is ever exposed through a reverse
  proxy.
- A strict host allow-list is not possible without breaking arbitrary SSH
  local-forward names. The implemented policy compares supplied Origin/Referer
  to the actual request host and leaves requests without browser metadata for
  operational compatibility.
- TLS termination, certificate management, and external firewall policy stay
  outside the control plane.
