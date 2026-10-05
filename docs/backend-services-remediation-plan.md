# План исправления backend-сервисов

## Цель и ограничения

Устранить находки из
[ревью backend-сервисов](backend-services-review-2026-10-05.md), не меняя
контракт HTTP API для веб-панели. Взаимодействие между приложениями — только
gRPC. Сохранить fail-open поведение lease enforcement при потере телеметрии,
scope токенов и пороги покрытия. Не снижать пороги и не исключать handwritten
production-код ради зелёного отчёта.

## Этапы

### 1. Сохранить protocol identity telemetry — выполнено

- [x] Сделать выбор протокола детерминированным при общем Xray email.
- [x] Выбирать lease-поддерживаемый протокол для VLESS/Hysteria dual identity,
  сохраняя одну агрегированную строку трафика.
- [x] Добавить регрессионный тест для legacy dual профиля.

### 2. Перевести lease health с HTTP на gRPC — выполнено

- [x] Использовать стандартный gRPC health и выставлять `SERVING` только после
  получения пригодного Xray snapshot.
- [x] Перевести Docker healthcheck на локальный gRPC health.
- [x] Перевести Doctor на gRPC health.
- [x] Удалить внутренний HTTP server, HTTP client и связанные настройки.
- [x] Покрыть статусы ready/not-ready, некорректный адрес, ошибку транспорта и
  отменённый context изолированными gRPC тестами.

### 3. Ограничить остановку сервисов и изолировать необязательный AWG — выполнено

- [x] Добавить ограниченную остановку gRPC Controller и AWG с принудительным
  завершением и тестом активного stream.
- [x] Добавить SIGINT/SIGTERM и ограниченный HTTP shutdown в control-plane;
  после завершения HTTP отменить и дождаться workers.
- [x] Не прерывать Controller при ошибке необязательного AWG adapter; оставить
  ошибку видимой в журнале и при вызове AWG API.

### 4. Убрать повторный сбор stats — выполнено

- [x] Сохранять unary poll каждые 10 секунд, когда нет активного stream.
- [x] Подавлять периодический unary poll при активном telemetry stream.
- [x] Возобновлять poll после обрыва stream; сохранить durable counters и
  вычисление rate.
- [x] Описать окно потери процессных counters до durable checkpoint.

### 5. Ограничить попытки аутентификации и зафиксировать структурный долг — выполнено

- [x] Ограничить число запросов входа от одного source и число параллельных
  Argon2-проверок.
- [x] Применить ограничения к login, TOTP login и recovery login.
- [x] Оставить повторный dispatch-рефакторинг отдельной behavior-preserving
  задачей: он не требуется для исправления gRPC-границы и требует отдельного
  тестового среза.

### 6. Проверить изменения — выполнено

- [x] Запустить корневые Go тесты и coverage gate: минимум 90% handwritten
  statement coverage в целом, сохранить per-package порог.
- [x] Запустить AWG и embedded-runtime coverage gate; минимум 90% по их
  критериям и по выбранным runtime source files.
- [x] Запустить web tests/coverage, чтобы проверить отсутствие изменений
  контракта панели.
- [x] Запустить `go vet`, форматирование, Compose validation и `git diff --check`.
- [x] Записать фактические результаты, ограничения и оставшиеся пункты здесь и
  в отчёте ревью.

## Результаты проверок

Проверки выполнены 5 октября 2026 года в network-disabled контейнерах с уже
доступными зависимостями. Покрытие рассчитано по Go cover profiles с исключением
сгенерированных `*.pb.go`; handwritten-порог проверен отдельно от сводной
статистики Go, которая включает generated packages.

| Область | Команда/проверка | Результат |
| --- | --- | --- |
| Корневые Go сервисы и библиотеки | `go test -covermode=atomic -coverprofile=backend-final.out ./cmd/... ./internal/...` | PASS; handwritten overall **97,96%** (10 368/10 584 statements); минимальный handwritten package — `internal/backup`, **91,76%**; все пакеты выше сохранённого порога 80%. |
| AWG отдельный Go module | `go test -covermode=atomic -coverprofile=awg.out ./...` из `awg-service/` | PASS; handwritten overall **96,46%** (1 851/1 919); `cmd/awg-service` 96,6%, `internal/control` 96,4%. |
| Embedded Xray runtime | `go test -covermode=atomic -coverprofile=runtime.out ./...` из `xray-runtime/` | PASS; `cmd/xray-runtime` 97,8%, `internal/runtime` 95,0%; каждый выбранный production source file выше 90%, минимум — `engine.go` 92,2%. |
| Web panel | `npm run test:coverage` | PASS; 22 test files, 199 tests; 100% statements, branches, functions и lines. |
| Go static analysis | `go vet ./cmd/... ./internal/...`, `go vet ./...` из `awg-service/` и `xray-runtime/` | PASS без diagnostics. |
| Формат и конфигурация | `gofmt -l` по всем изменённым Go файлам; `docker compose -f compose.yaml config --quiet`; `git diff --check` | PASS; gofmt не вывел файлов, Compose и diff check завершились с кодом 0. |
| Граница HTTP/gRPC | Поиск HTTP-клиентов в backend Go-коде | Межсервисных HTTP-вызовов не найдено; единственный runtime URL — loopback healthcheck самого control-plane. HTTP `/api/...` остаётся интерфейсом панели. |

Root Go suite выполнялся отдельно от AWG и embedded runtime, потому что это
отдельные Go modules. Coverage profile подтверждает общий порог 90%+ во всех
трёх областях. Генерируемые gRPC файлы исключались из handwritten-метрики;
их package-level проценты в стандартном выводе `go test` не отражают покрытие
собственного production-кода.

`-race` не запускался: тестовая среда использовала Alpine toolchain с
`CGO_ENABLED=0`, а Go race detector требует CGO. Это не влияет на приведённые
результаты тестов и coverage.

## Отложенная работа

Вынести дублирующиеся protocol dispatch ветки HTTP entrypoint и Controller в
отдельный рефакторинг после регрессионной фиксации поведения add/list/remove.
Проверка качества не должна снижать пороги покрытия для этого кода.
