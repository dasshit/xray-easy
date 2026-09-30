# План удаления неиспользуемого кода и устаревших HTTP-маршрутов

## Цель

Удалить код, который не участвует в текущем пользовательском сценарии, и
синхронизировать документацию с действующей архитектурой. Публичный для
браузера HTTP API `xray-easy` остаётся: Vue использует его для JSON-запросов и
SSE, а Compose — для healthcheck. Частный обмен между backend, Controller,
Xray-supervisor и AmneziaWG выполняется по gRPC.

REST-маршруты backend не описаны в README как внешняя интеграционная
поверхность. В этой задаче считаем их внутренним контрактом пары
`xray-easy`/Web UI и допускаем удаление неиспользуемых дубликатов. Маршруты,
которые продолжает использовать текущий UI, сохраняются либо сначала
переносятся на канонический ресурс.

## Результаты аудита

- `(*server).createClient` в `cmd/xray-easy/main.go` не имеет вызовов; его
  аргумент `privateKey` также не используется. Создание профиля проходит через
  `createProtocolClient`.
- `GET /api/readyz` — алиас `GET /api/healthz`; он не вызывается Compose или
  Web UI.
- `POST /api/settings/validate` дублирует `PATCH /api/settings`; Web UI
  использует `PATCH`.
- Старый AWG CRUD API `/api/transports/amneziawg/peers` и методы
  `listPeers`/`createPeer`/`removePeer` в web gateway не нужны для текущего
  списка общих профилей. Ссылки загрузки конфигурации и QR ещё используют
  вложенные пути `/api/transports/amneziawg/peers/{name}/profile`; перед их
  удалением они будут переведены на `/api/clients/{id}/profile?format=conf|qr`.
  Отзыв AWG-профиля также должен обрабатываться непосредственно общим
  `/api/clients/{id}/revoke`, без внутреннего HTTP-перенаправления.
- `docs/xray-supervisor-grpc-plan.md` описывает удалённые HTTP-маршруты
  supervisor как действующие. Таблицы маршрутов в `IMPLEMENTATION_PLAN.md`
  также содержат удаляемые алиасы.

## Этапы реализации

1. **Удалить подтверждённо мёртвую обёртку.** Удалить `createClient` и не
   затрагивать общий путь `createProtocolClient`.
2. **Удалить дубли HTTP API.** Удалить `/api/readyz` и
   `/api/settings/validate`, соответствующие методы и тесты; сохранить
   `/api/healthz` и `PATCH /api/settings`.
3. **Унифицировать AWG выдачу профиля и отзыв.** Перевести Web UI на
   `/api/clients/awg%3A{name}/profile?format=conf|qr`. Реализовать выдачу,
   резервный backup перед отзывом и аудит в общем обработчике AWG-клиента.
   Сохранить текущую авторизацию, no-store заголовки, формат файла/QR,
   проверки peer и ошибки.
4. **Удалить старый AWG CRUD HTTP слой.** Удалить legacy collection/item
   handlers `/api/transports/amneziawg/peers`, регистрации маршрутов,
   неиспользуемые методы web gateway, DTO и модели, оставив маршрут статуса
   `/api/transports/amneziawg` и активные общие клиентские сценарии.
5. **Обновить документацию.** Обозначить миграцию supervisor на gRPC как
   завершённую, убрать описание старого частного HTTP API и обновить
   актуальную таблицу маршрутов в `IMPLEMENTATION_PLAN.md`.
6. **Проверить результат.** Запустить Go-тесты и действующие coverage gates,
   web unit-тесты, lint, typecheck и build, проверить Compose-конфигурацию,
   повторный поиск всех удалённых символов и маршрутов, `git diff --check`.

## Границы

- Не удалять HTTP API backend целиком, `/api/events`, `/api/healthz`, API
  аутентификации, устройств, настроек, диагностики и backup.
- Не менять контракты Controller, supervisor или AWG gRPC и сетевую топологию.
- Не удалять AWG status endpoint, который использует Web UI.
- Не урезать сгенерированные Xray Protobuf-типы в рамках этой чистки: они
  связаны зависимостями generated HandlerService, а размер/минимизация API
  Xray требуют отдельного обоснования.

## Критерии завершения

- Удалённые маршруты и функции отсутствуют в production-коде и документации.
- Web UI создаёт, показывает/скачивает и отзывает AWG-профили через общий
  ресурс устройств.
- Для AWG revoke сохраняются автоматический backup, traffic cleanup и audit.
- Все проверки этапа 6 проходят; изменения реализации фиксируются отдельным
  коммитом после коммита этого плана.
