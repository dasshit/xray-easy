# Contributing

Thanks for considering a contribution to Xray Easy. Bug reports, focused fixes,
documentation improvements, and carefully scoped features are welcome.

## Before you start

- For a bug or feature, check the existing issues first. Open an issue to discuss
  a substantial change before investing in implementation.
- Keep pull requests focused. Explain the problem being solved, the approach,
  and any behavior or configuration changes users should know about.
- Do not include passwords, tokens, private keys, server addresses, or other
  sensitive data in issues, logs, screenshots, or test fixtures. For a suspected
  security vulnerability, use GitHub's private vulnerability reporting if it is
  enabled for this repository; do not publish exploit details in a public issue.

## Development setup

The project has a root Go module and separate modules for the Xray runtime,
AmneziaWG service, and shared AmneziaWG contract. The web app lives in `web/`.
Use Go 1.27.1 and Node.js 24, as configured in CI.

Run the checks relevant to your change from the repository root unless noted:

```sh
# Main backend
go test ./...
go run ./scripts/check-go-docs.go
bash scripts/backend-coverage.sh
go vet ./...

# AmneziaWG service and shared contract
(cd awg-service && go test -race ./...)
(cd awg-service && go vet ./...)
(cd awg-contract && go test ./...)

# Xray runtime
(cd xray-runtime && go test ./...)
(cd xray-runtime && go vet ./...)

# Web app
(cd web && npm ci)
(cd web && npm run lint)
(cd web && npm test)
(cd web && npm run test:coverage)
(cd web && npm run typecheck)
(cd web && npm run build)
```

The CI coverage gates require at least 90% coverage for handwritten backend
code and the AmneziaWG service; the Xray runtime gate checks each handwritten
runtime file. Add or update tests with behavior changes. CI also runs race-enabled
Go checks and `go vet` for each Go module. Pushing a stable `vMAJOR.MINOR.PATCH`
tag publishes the service images after the required checks pass.

The Compose integration smoke test requires Docker and is opt-in:

```sh
go test -tags=composeintegration -count=1 -v -timeout=40m ./integration/compose
```

## Code and documentation

- Format Go code with `gofmt`. Keep handwritten exported Go declarations
  documented; `go run ./scripts/check-go-docs.go` checks this requirement.
- Follow the existing TypeScript, Vue, and test patterns in `web/`.
- For Protocol Buffer changes, edit the `.proto` source and regenerate checked-in
  bindings from the repository root with `scripts/generate-protobuf.sh`. Do not
  edit generated `.pb.go` files by hand. The script uses Docker to run the pinned
  Buf generator.
- Update the relevant README or documentation when a change affects setup,
  configuration, supported behavior, or operations.
- When adding, removing, or changing a bundled or build-time third-party
  component, update [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and keep
  any required upstream license files with the code.

## Pull requests

1. Create a branch from the current `main` branch and make a focused change.
2. Run the applicable checks above. If a check cannot be run, mention that and
   explain why in the pull request.
3. Open a pull request against `main`. Include relevant issue links, tests run,
   and screenshots for visible web UI changes. Call out any compatibility,
   migration, security, or deployment impact.
4. Keep the pull request up to date with review feedback and make sure required
   GitHub Actions checks pass.

There is no required commit-message format or pull request template at this
time.

## License

Project-authored contributions are distributed under
[GPL-3.0-or-later](LICENSE), consistent with the project license. By submitting
a contribution for inclusion, you confirm that you have the right to submit it
under those terms. Contributions that include third-party code must be
compatible with the project and retain applicable notices; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
