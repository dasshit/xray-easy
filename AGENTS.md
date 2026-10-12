# Repository instructions

These instructions apply to the whole repository. Follow any more specific
`AGENTS.md` found in a subdirectory as well. The user's current request takes
precedence over these defaults.

## Project overview

Xray Easy is a self-hosted server manager for Xray protocols and optional
AmneziaWG. It consists of several Go modules, a Vue/TypeScript web panel, and a
Docker Compose deployment. The control plane, Controller, Xray runtime, lease
service, and AmneziaWG service run as separate components. Read the root
`README.md` for the supported product and deployment behavior; do not infer
runtime behavior from a prototype or an old implementation plan.

The project-authored code is licensed under GPL-3.0-or-later. Bundled and
build-time dependencies retain their own terms; consult `THIRD_PARTY_NOTICES.md`
and preserve upstream license files.

## Repository map

- `cmd/xray-easy/`: control-plane composition, HTTP API, and administrative CLI.
- `cmd/xray-controller/`, `internal/controller/`: internal Controller service
  and its Xray/AmneziaWG orchestration.
- `cmd/xray-lease-service/`, `internal/lease/`, `internal/leasehealth/`:
  source-IP lease service and health support.
- `cmd/xray-easy-install/`, `install.sh`: interactive installer and host setup.
- `internal/domain/`: transport- and persistence-independent entities,
  validation, and lifecycle rules.
- `internal/store/`: SQLite/GORM persistence, schema migrations, and
  transactions.
- `internal/xray/`: Xray configuration and client-profile generation.
- Other `internal/` packages contain authentication, secrets, backups,
  diagnostics, statistics, UI handlers, RPC clients, and shared runtime code.
- `internal/controller/api/v1/*.proto`,
  `internal/xrayruntime/api/v1/*.proto`, `awg-contract/api/v1/*.proto`:
  service contracts. Generated Go bindings live beside the contracts.
- `awg-service/`: independent Go module for the optional AmneziaWG service.
- `awg-contract/`: independent Go module for the shared AmneziaWG gRPC API.
- `xray-runtime/`: independent Go module embedding and supervising Xray-core.
- `web/`: Vue 3, TypeScript, Vite, and Vitest application.
- `compose.yaml`, `Dockerfile.*`, `.env.example`: deployment and image setup.
- `integration/compose/`: opt-in Docker Compose integration smoke test.
- `third_party/`: locally maintained third-party source and license texts.
- `scripts/`: protobuf generation, coverage gates, reports, and development
  helpers.
- `docs/`: architecture, design, and supporting plans. Plans can describe
  completed or historical work; verify current behavior in code, README, and
  CI before treating a plan as current requirements.

## Architecture and change boundaries

### Go services

- Keep business rules in `internal/domain`; HTTP handlers, RPC, and persistence
  should adapt to those rules rather than reimplementing them.
- Keep storage concerns in `internal/store`. Preserve compatibility with
  existing SQLite data when changing models or migrations. A migration must
  account for old schemas and failure/rollback behavior, not just a fresh
  database.
- Keep API DTOs and transport conversion at the boundary. Coordinate changes
  across the control plane, Controller, runtime, and AWG service when they share
  an RPC contract.
- Internal gRPC services are deployed on private Compose networks. Preserve
  their authentication and do not expose them publicly through port mappings.
- Follow existing context cancellation, shutdown, error wrapping, and resource
  cleanup patterns. Avoid introducing package cycles or moving business rules
  into `cmd/` entrypoints.

### Web application

`docs/domain-architecture.md` describes the intended dependency direction:
`domain` is transport independent; `application` depends on domain and ports;
`infrastructure` implements HTTP/SSE/API boundaries; `presentation` owns UI
state, localization, and rendering. Keep server snake_case DTOs and endpoint
paths in the infrastructure mapping rather than leaking them into domain/UI
models.

When changing visible UI, follow `DESIGN.md` and `ACCESSIBILITY.md`. Preserve
semantic controls, keyboard operation, visible focus, accessible names, and
status announcements. Keep translations consistent across the locales already
supported by the application.

### Contracts, generated code, and dependencies

- Edit `.proto` sources, then regenerate checked-in bindings from the repository
  root with `scripts/generate-protobuf.sh`. The script uses the pinned Buf
  container and requires Docker. Do not hand-edit generated `.pb.go` files.
- Treat other generated files as generated too; find and update their source or
  generator instead of editing output manually.
- When changing a dependency, update the correct module's manifest and lock/sum
  file. There are separate Go module files in the root, `awg-service`,
  `awg-contract`, and `xray-runtime`; a root `go test ./...` does not cover the
  nested modules.
- If third-party code or a bundled/build-time component is added, removed, or
  materially changed, update `THIRD_PARTY_NOTICES.md` and preserve required
  license notices. Do not silently replace the local `third_party/go-qrcode`
  fork with an upstream module or edit vendored code without an explicit reason.

## Security and data handling

This project manages credentials and network services. Treat authentication,
authorization, origin checks, secret handling, and private-network boundaries as
core behavior:

- Never put passwords, session cookies, TOTP/recovery material, bearer tokens,
  private keys, client profiles, master keys, or real user data in logs, errors,
  test snapshots, fixtures, screenshots, or commits. Redact diagnostic output.
- Treat `.env`, `secrets/`, database files, backups, and exported profiles as
  sensitive. Prefer `.env.example` and synthetic test data. Do not print local
  secret values while investigating a task.
- Preserve restrictive file permissions and existing encryption/authentication
  boundaries. Do not weaken cryptographic checks, same-origin protections,
  token validation, or container isolation as a workaround.
- Keep tests deterministic and local. Prefer temporary directories, in-process
  servers, injected clocks/random sources, and fakes already used in the code.
  Do not contact real servers or use production credentials in tests.
- Do not run deployment, release, or destructive data commands unless the user
  explicitly requested that operation.

## Go and web conventions

- Format handwritten Go with `gofmt`. Add Go doc comments for handwritten
  exported APIs; the repository checker is `go run ./scripts/check-go-docs.go`.
- Keep tests near the package under test and follow the standard `testing`
  patterns already present. When behavior changes, add or update tests for
  success, validation/error handling, and rollback/compatibility paths where
  relevant.
- Keep Vue/TypeScript changes consistent with existing ESLint, type-checking,
  component, and Vitest patterns. Update UI tests when observable behavior
  changes.
- Update README or operational documentation when setup, configuration,
  compatibility, security, or user-visible behavior changes.
- Keep pull requests focused. Summarize behavior changes, verification, and any
  compatibility, security, migration, or deployment impact.

### Commit messages

Use the format `<type>: <short summary>`, with a lowercase type, a colon and
one space, and an imperative summary without a final period. Prefer these
project prefixes:

- `docs`: documentation-only changes, for example `docs: add deployment guide`.
- `feat`: a new capability or user-visible behavior, for example
  `feat: add profile expiry controls`.
- `fix`: a bug or incorrect behavior, for example
  `fix: preserve settings during restore`.
- `tests`: test-only changes, for example `tests: cover backup rollback`.

For a commit that changes implementation and tests together, choose `feat` or
`fix` to describe the implementation; reserve `tests` for commits that only
change tests. Keep commits focused and use a clear conventional prefix such as
`refactor` or `chore` when none of the preferred types accurately describes
the change. Add a commit body when context or compatibility impact needs more
explanation.

## Development commands

The module toolchain is Go 1.27.1. CI uses Node.js 24. Run commands from the
indicated directory. Choose checks that cover the files and behavior changed;
the coverage scripts run the tests themselves.

### Root Go module

```sh
go test ./...
go vet ./...
go run ./scripts/check-go-docs.go
bash scripts/backend-coverage.sh
```

CI runs backend tests with the race detector and enforces at least 90% coverage
for handwritten statements overall and per package.

### AmneziaWG service and contract

```sh
(cd awg-service && go test -race ./...)
(cd awg-service && go vet ./...)
bash scripts/awg-coverage.sh
(cd awg-contract && go test ./...)
```

CI also cross-builds `awg-service` for Linux amd64 and arm64. The service
coverage gate is at least 90% for handwritten code.

### Xray runtime

```sh
(cd xray-runtime && go test ./...)
(cd xray-runtime && go vet ./...)
bash scripts/xray-runtime-coverage.sh
```

CI runs this module with the race detector and checks at least 90% coverage for
each handwritten runtime Go file.

### Web application

```sh
(cd web && npm ci)
(cd web && npm run lint)
(cd web && npm test)
(cd web && npm run test:coverage)
(cd web && npm run typecheck)
(cd web && npm run build)
```

CI runs lint, typecheck, coverage tests, and build. Use `npm test` for a faster
web test run when a coverage report is not needed.

### Compose integration smoke test

This test is opt-in, needs Docker and Compose, and creates an isolated test
stack. Run it only when relevant and safe for the current environment:

```sh
go test -tags=composeintegration -count=1 -v -timeout=40m ./integration/compose
```

## Before finishing a change

1. Inspect `git status` first and preserve unrelated user changes.
2. Read the nearest implementation, its tests, relevant docs, and CI workflow
   before deciding how to change behavior.
3. Make the smallest coherent change and update generated outputs only through
   their documented generator.
4. Run the relevant checks above when appropriate; report checks that were not
   run and why. Do not claim a check passed unless it was run.
5. Review the diff for accidental secrets, generated noise, unrelated edits,
   and missing documentation or notices.
