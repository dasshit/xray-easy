# SOLID/DRY review

The review found two concrete sources of coupling and duplication:

- HTTP and CLI paths repeated the conversion from persisted settings and
  clients to the Xray renderer model. `internal/xray/domain_adapter.go` now
  owns that boundary and is covered by tests.
- The HTTP client handler encoded enable, disable, and revoke transitions with
  booleans. `domain.Client.Transition` now owns the state machine and rejects
  invalid transitions before persistence or runtime apply.
- `App.vue` contained HTTP decoding, theme persistence, byte/date formatting,
  and presentation state in one module. API transport is in
  `web/src/infrastructure/api.ts`; UI utilities are in
  `web/src/application/ui.ts`; profile action selection remains in the domain
  module.

These changes keep policy in domain code, adapters at boundaries, and the
component focused on composing the four screens. Further extraction of the
large dashboard component can be done when the UI gains independent routes;
the current split avoids introducing a component framework solely for a
refactor.
