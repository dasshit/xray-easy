# Coverage remediation plan

## Goal

Raise the existing coverage gates without lowering thresholds or excluding
handwritten production code from the reports. Tests should exercise observable
behavior, including failure and recovery paths, rather than only execute lines
to increase percentages.

The gates to preserve are:

- Root Go module: at least 90% handwritten statement coverage overall and at
  least 80% in every handwritten package.
- `awg-service`: at least 90% handwritten statement coverage for the module.
- `xray-runtime`: at least 90% statement coverage in every handwritten runtime
  source file selected by `scripts/xray-runtime-coverage.sh`.
- Web: at least 90% statements, lines, and functions; at least 85% branches;
  and at least 90% lines in every included file.

## Baseline

Measured on 2 October 2026 from the current checkout with the repository's
coverage commands and Go race detector enabled:

| Area | Result | Gate | Status |
| --- | ---: | ---: | --- |
| Root Go handwritten statements | 8,073 / 9,208 (87.7%) | 90% overall | Fails |
| Root Go packages | Every package at least 80% | 80% per package | Passes |
| AWG handwritten statements | 1,485 / 1,656 (89.67%) | 90% | Fails |
| Runtime `engine.go` | 265 / 299 (88.6%) | 90% per file | Fails |
| Runtime `service.go` | 471 / 581 (81.1%) | 90% per file | Fails |
| Other selected runtime files | At least 93.2% each | 90% per file | Passes |
| Web statements | 1,011 / 1,113 (90.83%) | 90% | Passes |
| Web lines | 707 / 736 (96.05%) | 90% overall and per file | Passes |
| Web functions | 255 / 286 (89.16%) | 90% | Fails |
| Web branches | 849 / 1,018 (83.39%) | 85% | Fails |

All 127 web tests passed. The Go test suites ran, but the coverage gates failed
on the percentages above. Runtime integration tests need permission to bind
loopback TCP ports; the runtime baseline was therefore collected outside the
restricted sandbox after an in-sandbox run was denied by the OS.

## Implementation stages

### 1. Recheck the baseline and map high-value gaps

- Run the root, AWG, runtime, and web coverage commands with their current
  thresholds and race settings.
- Use Go coverage profiles and the web HTML/text report to identify uncovered
  production branches and decisions. Keep generated protobuf and test code
  excluded as today.
- Prioritize branches that represent user-visible behavior, state transitions,
  input validation, persistence and rollback, error handling, and service
  lifecycle. Do not spend effort covering generated accessors or unreachable
  operating-system-specific behavior solely for a percentage.

### 2. Restore AWG module coverage

- Add focused tests for the uncovered branches in `awg-service/internal/control`
  and `awg-service/cmd/awg-service`.
- Cover state transitions, snapshot failures/recovery, malformed or missing
  peer data, and shutdown behavior where those paths are currently untested.
- Keep the monitor's existing online/offline semantics and structured log
  behavior intact.
- Re-run `scripts/awg-coverage.sh` with the race detector; target at least 90%
  with a small margin rather than exactly 90%.

### 3. Raise embedded Xray runtime per-file coverage

- Add behavior-focused tests for uncovered branches in `internal/runtime/engine.go`
  and `internal/runtime/service.go`.
- Exercise configuration validation and apply/revision outcomes, invalid or
  repeated requests, upstream/core errors, context cancellation, and telemetry
  collection failures using existing fakes or narrow test seams.
- Avoid tests that rely on public network access; loopback listeners used by
  current integration tests are permitted in the environment running this gate.
- Re-run `scripts/xray-runtime-coverage.sh`; every selected handwritten file
  must reach at least 90%.

### 4. Raise web function and branch coverage

- Use the generated web coverage report to find the untested decisions and
  functions, especially in `App.vue`, settings panels, and modal components.
- Add component tests for meaningful UI states and interactions: validation,
  loading/success/failure states, conditional fields, cancel/confirm behavior,
  and translation/language fallback branches.
- Keep tests isolated and assert user-visible output or emitted API calls.
- Re-run `npm run test:coverage`; satisfy all configured global and per-file
  thresholds.

### 5. Raise root Go module coverage

- Add focused tests in the largest under-covered handwritten areas, beginning
  with `cmd/xray-easy`, `internal/store`, `internal/backup`, and
  `internal/controller`, then address remaining gaps revealed by updated
  reports.
- Prefer extracting small deterministic helpers only when that improves the
  existing design and makes behavior directly testable. Do not refactor solely
  to manipulate the denominator.
- Include success, invalid input, dependency failure, rollback, and recovery
  behavior for the covered operations.
- Re-run `scripts/backend-coverage.sh` with the race detector until handwritten
  overall coverage is at least 90%, retaining the existing 80% per-package
  requirement.

### 6. Final verification and report

- Run all four coverage gates, Go race tests, Go vet, web lint, typecheck, and
  web production build.
- Check formatting and `git diff --check`.
- Record final percentages and any remaining files intentionally below 90%
  where the gate is module-level only; do not describe the work as complete if
  any enforced gate fails.

## Completion criteria

The root backend gate, AWG module gate, runtime per-file gate, and all web
coverage thresholds pass without weakening configuration. The associated test
suites pass with race detection where configured, and the final report lists
measured coverage values for every area.
