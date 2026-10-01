# План потоковой телеметрии профилей

## Цель

Уменьшить задержку обновления статуса, source IP и скоростей upload/download в
Web UI. В целевой схеме Xray runtime и AmneziaWG service публикуют нормализованные
наблюдения в Controller, Controller передаёт их backend, а backend рассылает
снимки через существующий SSE endpoint `/api/events`.

Высокочастотные gRPC-подписки работают только пока существует хотя бы один
аутентифицированный SSE-клиент. При нескольких вкладках backend и Controller
разделяют одну upstream-подписку на каждый настроенный протокол.

## Исходное состояние до реализации

- `internal/stats.Manager` запускает сбор при старте control plane и опрашивает
  Controller каждые 10 секунд.
- SSE в `cmd/xray-easy/main.go` подписывается на уведомления Manager и отправляет
  текущий snapshot. Сам SSE сейчас не управляет запуском сбора.
- Xray runtime получает абсолютные счётчики и список активных source IP из
  встроенного Xray Stats Manager через `GetTelemetry`.
- AWG service получает счётчики и endpoint из снимка интерфейса через
  `Device.Snapshot()`.
- Backend хранит накопленные байты в SQLite, объединяя приращения счётчиков,
  поэтому накопительный трафик переживает перезапуск протокольных процессов.

## Архитектурные решения

1. **Поток открывается по подписке, а не по каждому событию браузера.** Первое
   SSE-подключение запускает общий telemetry hub backend и один
   `Controller.WatchTelemetry`. Controller создаёт по одной подписке к каждому
   доступному источнику. Последнее отключившееся SSE-подключение отменяет поток
   Controller и upstream-подписки.
2. **Направление данных — источник к потребителю.** Xray runtime и AWG service
   реализуют server-streaming `WatchTelemetry`; Controller начинает подписку
   запросом и получает поток сообщений. Controller также реализует
   server-streaming RPC для backend. Это сохраняет явное управление временем
   жизни подписки и передаёт телеметрию от VPN-сервисов к UI.
3. **В поток идут агрегированные снимки, не события на каждый пакет.** Источники
   агрегируют частоту до примерно одного обновления в секунду, объединяют
   промежуточные изменения и ограничивают буферы. Потеря промежуточного
   snapshot не теряет байты между samples, потому что счётчики в сообщениях
   абсолютные.
4. **Каждая подписка сначала получает полный snapshot.** Далее отправляются
   изменения клиентов и снимки-сверки с ограниченной периодичностью. SSE при
   подключении или автоматическом переподключении также начинает с полного
   состояния; replay-очередь дельт браузеру не нужна.
5. **Скорость — вычисляемая величина.** Сервисы сообщают абсолютные upload и
   download bytes, `sampled_at`, `last_activity`, source IP, generation и
   sequence. Backend вычисляет байт/сек между принятыми снимками и сохраняет
   накопительный total в SQLite. Счётчики с уменьшившимся raw значением или
   новым generation трактуются как сброс источника без отрицательной скорости.
6. **Online означает недавний пользовательский трафик.** Профиль становится
   online при первом наблюдённом росте счётчика. После 15 секунд без нового
   пользовательского трафика источник отправляет переход в offline. Handshake
   или простаивающее, но открытое соединение сами по себе не продлевают online.
7. **SQLite остаётся долговечным источником totals.** Backend продолжает
   низкочастотный 10-секундный опрос, даже когда Web UI закрыт, и применяет те
   же absolute counters в SQLite. Высокочастотные gRPC-потоки открываются
   только при активном SSE. Это сохраняет учтённые totals и ограничивает
   возможную потерю байтов при рестарте источника промежутком от последнего
   успешного poll до рестарта. Удалять этот страховочный poll можно только
   отдельным изменением после внедрения и проверки локальных checkpoint-ов в
   `xray_runtime_state` и `awg_data`.
8. **Controller остаётся адаптером.** Он нормализует идентификаторы клиентов и
   протоколы, объединяет снимки двух источников и сообщает доступность каждого
   источника. Недоступность AWG не прерывает Xray-события и наоборот.
9. **Семантика HTTP/SSE сохраняется.** Имена событий `stats` и `status` и
   JSON-форма `stats.clients` остаются совместимыми с текущим Web UI. Вызовы
   остаются аутентифицированными на каждом gRPC hop; тела телеметрии и секреты
   не записываются в логи.

## Этапы реализации

### 1. Контракт и правила жизненного цикла

- Добавить typed protobuf-сообщения для snapshot клиента, snapshot потока,
  generation, sequence, source availability и времени измерения.
- Добавить server-streaming `WatchTelemetry` в контракты Xray runtime, AWG и
  Controller, сохранив unary `GetTelemetry`/`GetPeerStats` на время миграции.
- Зафиксировать ограничения размера snapshot, частоту обновления, offline TTL
  15 секунд и правила для нулевого/сброшенного счётчика.
- Генерировать Go-код штатным `scripts/generate-protobuf.sh`.

**Приёмка:** контракты компилируются во всех четырёх Go-модулях; сообщения не
содержат UUID, приватные ключи или данные конфигураций; старые unary-клиенты
продолжают работать.

### 2. Xray runtime: источник событий

- Сэмплировать Xray counters только при активном `WatchTelemetry`; текущий
  backend polling остаётся низкочастотным способом учёта totals без SSE.
- Вычислять activity по росту абсолютных uplink/downlink counters, сохранять
  последний activity timestamp на время stream и отправлять полные snapshots
  с online/offline состоянием.
- На каждую подписку отправлять полный roster snapshot; затем передавать
  coalesced snapshots не чаще целевой частоты. Отмена потока удаляет подписчика
  и прекращает высокочастотную работу.
- Сохранять и передавать source IP observations, не писать их в логи.

**Приёмка:** тесты проверяют первое событие, счётчики и source IP, online при
росте счётчика, offline по TTL, отмену, несколько подписчиков и сброс Xray
counters. Durable ledger — отдельная будущая задача перед удалением polling.

### 3. AWG service: источник событий

- Во время активной подписки снимать `PeerTelemetry()` с ограниченной частотой,
  объединять результаты и публиковать обновления только при изменении данных.
- Вне активной подписки оставить только backend 10-секундный опрос для
  накопительного учёта; частый kernel sampling запускается только через stream.
- Определять online по изменению transfer counters; handshake использовать
  только как вспомогательную last-seen информацию.
- Отправлять полный peer snapshot при старте потока, offline transition через
  15 секунд тишины и source IP последнего актуального endpoint.

**Приёмка:** тесты проверяют peer mapping, counter reset, online/offline TTL,
подписку/отписку, endpoint, отсутствие утечки private key и неблокирующую
публикацию. Persistent ledger — отдельная будущая задача перед удалением polling.

### 4. Безопасный streaming gRPC на протокольных сервисах

- Добавить stream auth interceptors и разрешённые RPC-methods для каждого
  сервиса, используя текущие отдельные секреты.
- Добавить structured lifecycle logs: stream start/end, protocol, subscriber
  count, duration, sequence и результат. Не логировать payload и source IP.
- Использовать ограниченный latest-value/coalescing buffer. Запись события не
  должна блокировать обработку пользовательского трафика.
- Добавить stream heartbeat/availability и корректную отмену через context.

**Приёмка:** интеграционные тесты закрывают auth, cancellation, stream error,
heartbeat, медленного читателя и остановку сервиса.

### 5. Controller: общий relay двух источников

- Реализовать `Controller.WatchTelemetry`, который на первого потребителя
  открывает Xray и при наличии AWG server streams.
- Свести snapshots к общей идентичности профиля/протокола, сохраняя
  недоступность каждого источника отдельно.
- Текущий backend telemetry hub поддерживает одно Controller stream на процесс
  и делит его между вкладками. Controller открывает по upstream stream каждому
  активному backend stream consumer.
- При падении одного runtime продолжать отдавать второй, переподключать источник
  с exponential backoff и после восстановления отправлять его полный snapshot.

**Приёмка:** тесты проверяют запуск/остановку по refcount, фан-аут без потери
последнего состояния, недоступность только одного источника, reconnect,
backpressure, stream auth и отсутствие фоновых upstream-подписок при нуле
потребителей.

### 6. Backend: stream hub, durable totals и SSE

- Добавить общий backend telemetry hub с refcount SSE-подписчиков. Во время
  открытой SSE-подписки streamed snapshots обновляют UI; постоянный 10-секундный
  polling остаётся резервным сборщиком для сохранения totals при закрытом UI.
- В момент 0→1 подписчиков открыть Controller stream; в момент 1→0 отменить
  его. Несколько вкладок получают данные из одного upstream stream.
- При каждом snapshot сверить source cumulative counters с SQLite и применить
  только новые байты. Сохранять snapshot с transaction-safe обработкой
  generation, sequence и повторных сообщений.
- При ошибке потока сохранить последний total, обнулить скорости, показать
  telemetry unavailable/stale и переподключиться с ограниченным backoff.
- Отправлять текущий полный stats snapshot каждому SSE-подключению, затем
  snapshots по изменениям. Существующий status heartbeat и повторная проверка
  аутентификации продолжают работать.
- Оставить 10-секундный poll вне SSE как safety net для SQLite totals. Удаление
  возможно только после отдельной реализации source-local durable ledgers.

**Приёмка:** backend integration tests проверяют два SSE клиента/один gRPC
stream, полную отмену, reconnect, duplicate sequence, cumulative totals,
сброс generation, сохранение ранее учтённых totals при закрытом Web UI и
ограниченную потерю не более чем промежутком между последним poll и рестартом
источника.

### 7. Web UI и эксплуатационная документация

- Оставить API shape для `stats` совместимой; подтвердить обновление online,
  last seen, source IP, total и rates без перезагрузки профилей.
- Проверить браузерный reconnect EventSource, первоначальный snapshot и закрытие
  источника при logout/смене сессии.
- Обновить диагностику/README: фактическая частота и семантика online, статус
  stream, команды просмотра логов и ограничения накопительных checkpoint-ов.

**Приёмка:** web unit-тесты покрывают обработку нескольких быстрых событий,
последний snapshot, reconnect/error и закрытие EventSource; ручная проверка на
VDS подтверждает latency и Xray/AWG parity.

### 8. Нагрузочная проверка и удаление polling

- Сравнить CPU, число gRPC вызовов, SSE частоту и задержку до/после на пустом и
  активном сервере, в том числе при нескольких вкладках.
- Проверить долгоживущие/простаивающие VLESS, VMess, Hysteria 2 и AWG-профили.
- Проверить рестарт Controller, Xray runtime, AWG service, backend и браузера,
  а также одновременную потерю одного runtime.
- Сначала пройти локальные unit/integration тесты и собрать stack. После
  коммита пользователь выполняет VDS-приёмку; удаление страховочного polling и
  закрытие этапа допускаются после успешного результата.

**Итоговые критерии:** online появляется не позднее одного интервала публикации;
offline наступает через 15 секунд после последнего учтённого user-data traffic;
rates обновляются примерно раз в секунду; persistent totals не теряют учтённые
байты из SQLite; возможная потеря между источниковым рестартом и следующим
10-секундным poll задокументирована; gRPC Watch активен только при наличии
SSE-подписчиков.

## Проверки

- Backend и каждый самостоятельный Go module удерживают существующую планку
  unit test coverage не ниже 90% по модулям.
- Web сохраняет текущие coverage thresholds и проходит lint/typecheck.
- Все stream RPC проходят cancellation, reconnect, slow-consumer, source failure
  и multi-subscriber integration tests.
- `docker compose config --quiet`, полная локальная сборка и `doctor` должны
  проходить до VDS-проверки.

## Статус

- [x] План и архитектурные решения зафиксированы.
- [x] Этап 1 — typed telemetry contracts и generated Go bindings.
- [x] Этап 2 — Xray runtime publisher: полные snapshots, absolute counters,
  source generation/sequence, online TTL и отмена вместе со stream.
- [x] Этап 3 — AWG publisher с той же семантикой и online TTL.
- [x] Этап 4 — stream auth и lifecycle logging на Xray, AWG, Controller и
  backend hops; payload и source IP в логи не попадают.
- [x] Этап 5 — Controller fan-in, независимая доступность источников, reconnect,
  отмена upstream и per-source latest-value coalescing при backpressure.
- [x] Этап 6 — backend stream hub с refcount SSE listeners, duplicate/restart
  fencing, расчётом rates и SQLite totals; 10-секундный poll сохранён как
  safety net вне SSE.
- [x] Этап 7 — сохранена форма событий `stats`/`status`, обновлена документация
  про частоту, offline TTL и границу сохранности totals; web unit tests, lint и
  typecheck прошли без изменения UI-кода.
- [x] Backend coverage gate: 90.0% по handwritten-коду, все handwritten
  packages выше минимального порога 80%.
- [x] AWG coverage gate: 90.03%.
- [x] Xray runtime coverage gate: каждый handwritten Go-файл не ниже 90%.
- [x] Web unit tests: 123 теста, 93.34% statement coverage; lint и typecheck
  прошли.
- [x] Все Docker-образы собраны, `docker compose config --quiet` прошёл.
- [ ] Локальный запуск изолированного Compose stack и `doctor`: попытка
  заблокирована до старта сервисов, потому что Docker-хост не поддерживает
  настроенный logging driver `journald` (`journald is not enabled on this
  host`). Это ограничение локального окружения; проверка на VDS остаётся
  необходимой.
- [ ] Ручная VDS-приёмка и сравнение задержки/нагрузки; затем можно отдельно
  решить, достаточно ли source-local durable ledgers для удаления fallback poll.
