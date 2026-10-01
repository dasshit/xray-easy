# План удаления устаревшего Xray StatsService-кода

## Цель

Удалить оставшийся прямой gRPC-клиент к Xray `StatsService/GetUsersStats` и
связанные с ним generated bindings, тесты и устаревшие описания. После перехода
на embedded Xray runtime статистика читается из его in-process stats manager и
передаётся через Controller; прямой Xray StatsService для этого не нужен.

## Что сохраняем

- Периодический `stats.Manager` и его `Poll`: он накапливает долговременные
  totals в SQLite, даже когда Web UI не подключён к SSE, и даёт резервный путь,
  если telemetry stream временно недоступен.
- Controller RPC `GetXrayTelemetry`, runtime RPC `GetTelemetry`, а также unary
  AWG `GetPeerStats`: они используются как начальный снимок и fallback рядом со
  стримом.
- Счётчики Xray внутри `corestats.Manager`, верхнеуровневую секцию `stats` и
  пользовательские policy counters. Удаляется только внешний Xray
  `StatsService` API и его прямой клиент.
- Исторические планы и fixtures, где StatsService описывает прежнюю
  архитектуру. Они остаются историей; актуальные инструкции и проверки должны
  описывать текущий runtime telemetry путь.

## Этапы

1. **Зафиксировать архитектурную границу.** Сохранить этот план в `docs` до
   изменения исходников. Проверить все production-ссылки на старый клиент и
   отдельно подтвердить активные unary polling/fallback вызовы.
2. **Удалить прямой Xray StatsService adapter.** Перенести общие DTO
   `UserStats` и `IPObservation` из `stats_client.go` в самостоятельный файл,
   удалить неиспользуемый `StatsClient`, его тесты и больше не импортируемые
   generated protobuf bindings из `internal/xrayapi/stats`.
3. **Убрать ненужную Xray API поверхность.** Удалить `StatsService` из
   сгенерированной Xray-конфигурации, оставив `HandlerService` и
   `LoggerService`; сохранить in-process `stats` и пользовательские policy
   counters. Проверить сериализованную конфигурацию и работу встроенного
   runtime без внешнего StatsService listener.
4. **Обновить текущие описания и диагностику.** Переименовать Doctor check в
   «Embedded Xray telemetry», описать его Controller/runtime источник,
   обновить README protobuf-подсистемы, актуальную заметку о coverage и
   compatibility manifest. Историческую документацию не переписывать; убрать
   только вводящее в заблуждение текущее требование Doctor о `GetUsersStats`.
5. **Проверить результат.** Запустить тесты затронутых пакетов, полный backend
   coverage gate и отдельный Xray runtime coverage gate; убедиться, что каждый
   модуль сохраняет требуемое покрытие ≥90%. Проверить форматирование,
   `git diff --check`, Compose-конфигурацию и поиск production-ссылок.
6. **Зафиксировать и опубликовать.** Создать один коммит с удалением legacy
   adapter и документацией, затем отправить `main` в `origin`.

## Критерии готовности

- В production-коде нет прямого Xray `StatsService/GetUsersStats` клиента или
  его protobuf bindings.
- Polling через Controller/runtime остаётся доступен для durable totals и
  восстановления после отключения SSE.
- Xray продолжает собирать in-process per-user counters, а создаваемая
  конфигурация не открывает ненужный StatsService API.
- Doctor корректно сообщает о доступности runtime telemetry.
- Все backend и runtime coverage gates проходят с покрытием каждого модуля не
  ниже 90%.
- Изменения закоммичены и запушены.

## Статус выполнения

- [x] Этап 1: аудит и фиксация плана.
- [x] Этап 2: удалить прямой StatsService adapter и bindings.
- [x] Этап 3: удалить StatsService из активной конфигурации Xray.
- [x] Этап 4: обновить текущую диагностику и документацию.
- [x] Этап 5: выполнить тесты и coverage gates.
- [x] Этап 6: создать коммит и push.
