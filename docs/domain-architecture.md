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
- `web/src/domain` contains frontend domain types and profile rules.
- `web/src/infrastructure/api.ts` owns HTTP transport and API error decoding;
  `App.vue` composes the presentation state from these modules.

The next refactoring step can split the remaining HTTP orchestration into
application use cases without moving transport concerns back into the domain.
