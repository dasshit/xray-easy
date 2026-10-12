# Claude Code instructions

Before editing this repository, read the root [`AGENTS.md`](AGENTS.md). It is
the canonical guide to the repository layout, architecture, security
requirements, generated code, and development commands. Also read any more
specific `AGENTS.md` in the directory you are changing. Follow the user's
current request where it gives a more specific direction.

## Project at a glance

Xray Easy is a Go and Vue/TypeScript application deployed with Docker Compose.
It has independent Go modules at the root, `awg-service/`, `awg-contract/`, and
`xray-runtime/`; tests and vet checks must be run from each module as needed.
The web app is under `web/`. The root `README.md` describes supported behavior,
and `docs/domain-architecture.md` explains the backend and frontend boundaries.

## Working rules

- Inspect the relevant implementation, tests, and current working tree before
  editing. Keep unrelated user changes intact.
- Preserve the domain/application/infrastructure boundaries, SQLite migration
  compatibility, RPC authentication, secret handling, and private Compose
  network assumptions described in `AGENTS.md`.
- Change `.proto` sources and regenerate bindings with
  `scripts/generate-protobuf.sh`; do not edit generated bindings by hand.
- When dependency or bundled third-party code changes, update the appropriate
  module manifests and `THIRD_PARTY_NOTICES.md`, preserving upstream licenses.
- For web UI changes, follow `DESIGN.md` and `ACCESSIBILITY.md`; maintain
  keyboard access and update translations for supported locales.
- Add or update focused tests when behavior changes. Run the relevant checks
  listed in `AGENTS.md`, and state clearly which checks were run or skipped.
- Treat `.env`, `secrets/`, databases, backups, tokens, private keys, and client
  profiles as sensitive. Do not expose their contents in output, logs, tests,
  or commits.
- Do not run deployment, release, or destructive data commands without an
  explicit user request.

## Reference files

- `README.md`: setup, Compose services, protocols, operations, and development.
- `CONTRIBUTING.md`: contribution workflow and CI checks.
- `SECURITY.md`: vulnerability reporting process.
- `THIRD_PARTY_NOTICES.md`: dependency and bundled-code notices.
- `DESIGN.md`, `ACCESSIBILITY.md`: web visual and accessibility guidance.

Keep this file aligned with `AGENTS.md` when repository-wide instructions
change; `AGENTS.md` remains the detailed source of truth for commands and
component-specific guidance.
