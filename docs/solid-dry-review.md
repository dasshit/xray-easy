# SOLID/DRY review

The review found two concrete sources of coupling and duplication:

- HTTP and CLI paths repeated the conversion from persisted settings and
  clients to the Xray renderer model. `internal/xray/domain_adapter.go` now
  owns that boundary and is covered by tests.
- The HTTP client handler encoded enable, disable, and revoke transitions with
  booleans. `domain.Client.Transition` now owns the state machine and rejects
  invalid transitions before persistence or runtime apply.
- `App.vue` had accumulated translation dictionaries, endpoint paths, wire
  payloads, SSE construction, and display helpers in addition to screen state.
  Translation messages and locale persistence now live in
  `web/src/presentation/i18n`; formatters and theme preferences live in the
  presentation layer.
- `web/src/infrastructure/api.ts` remains the generic HTTP transport. The
  typed adapter in `web/src/infrastructure/xrayEasyApi.ts` owns endpoint paths,
  request payloads, profile resource URLs, and DTO-to-model conversion.
  Snake_case API contracts live in `web/src/infrastructure/api-contracts.ts`.
- `web/src/application/ports/xrayEasyGateway.ts` defines the boundary consumed
  by application services. `dashboard.ts` handles the composite dashboard
  load and its partial-failure behavior. The component retains screen state
  and simple interaction sequencing rather than adding wrappers around every
  API call.
- `web/src/main.ts` provides the concrete gateway at the composition root;
  `App.vue` receives the port through Vue dependency injection. The
  application-level `APIError` preserves server error codes such as
  `totp_required` without making the component depend on the HTTP adapter.
- Native `EventSource` creation is isolated in
  `web/src/infrastructure/events.ts`; the component still controls the
  authenticated connection lifecycle and retry timing.

The extraction preserves the existing single-page UI and backend contract. It
does not add a routing or state-management framework. Dedicated components or
stores can be introduced when independent routes or shared state make them
useful.
