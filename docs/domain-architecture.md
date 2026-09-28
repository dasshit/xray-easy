# Domain architecture

The application keeps business rules independent from transport and storage:

- `internal/domain` contains the `Client` and `Settings` entities, validation,
  and profile lifecycle transitions.
- `internal/store` is the SQLite adapter. It persists domain entities and keeps
  compatibility aliases for storage-only callers; it does not own validation.
- `internal/xray` renders Xray configuration and profiles. Its validation
  entry points delegate to the domain so HTTP and rendering use one rule set.
- `cmd/xray-easy` is the composition and HTTP layer. It maps domain entities to
  API DTOs and coordinates adapters such as the supervisor, statistics, and
  backup services.
- `web/src/domain` contains transport-independent client and settings models
  plus profile lifecycle rules. Models use camelCase internally.
- `web/src/application/models.ts` and `web/src/application/ports` define
  frontend use-case data, the `APIError` crossing the HTTP boundary, and the
  `XrayEasyGateway` port.
- `web/src/application/services/dashboard.ts` composes authenticated dashboard
  data and applies the existing partial-failure rules for status and logs.
- `web/src/infrastructure/api.ts` owns generic HTTP transport and API error
  decoding. `web/src/infrastructure/api-contracts.ts` describes the server's
  snake_case JSON, and `xrayEasyApi.ts` maps it to application/domain models
  while owning endpoint paths and request payloads.
- `web/src/infrastructure/events.ts` owns the SSE endpoint and native
  `EventSource` adapter. The presentation layer decides when to connect and
  reconnect.
- `web/src/presentation` owns translation messages, locale persistence,
  formatting, theme preferences, and navigation-section types.
- `main.ts` is the composition root that provides the concrete gateway.
  `App.vue` consumes the application port and composes presentation state and
  user interactions; it does not define translations, API routes, wire DTOs,
  or construct event sources.

Dependencies point inward: infrastructure implements the application gateway,
application services depend on that port, and domain models do not depend on
Vue, HTTP, storage, or server JSON. The component remains the composition root
for the current single-page interface; additional feature components or stores
should be introduced when the UI structure needs them, not only to wrap API
calls.
