# План перехода от Xray supervisor к встроенному Xray runtime service

## Цель

Заменить запуск внешнего Xray-бинарника под управлением `xray-supervisor` на
отдельный Go-сервис, который встраивает закреплённую версию Xray-core как
библиотеку, владеет одним `core.Instance` и предоставляет собственный
типизированный gRPC API.

```text
Web UI --HTTP--> xray-easy backend --gRPC--> Controller
                                              |--gRPC--> Xray runtime service
                                              |           `-- in-process Xray-core
                                              `--gRPC--> AWG service
```

Новый процесс заменяет entrypoint существующего Compose-сервиса `xray`; новый
контейнер для Xray не добавляется. AmneziaWG остаётся отдельным сервисом.
Backend остаётся источником истины для администраторов, устройств, настроек,
ревизий, аудита и backup. Runtime service хранит только необходимое состояние
работающего движка и не подключается к SQLite backend.

План начинает с проверки встраивания, а не предполагает заранее, что любые
внутренние данные Xray доступны или что всю конфигурацию можно применять без
перерыва соединений. Рекомендуемая реализация — Go-обёртка над upstream
Xray-core, аналогичная AWG service. Собственный форк Xray-core не входит в
первоначальный объём: он потребуется только если прототип докажет, что
необходимый API или hook нельзя реализовать через доступные интерфейсы.

## Текущее состояние

- `Dockerfile.xray` берёт исполняемый файл из upstream-образа
  `ghcr.io/xtls/xray-core:${XRAY_VERSION}` и добавляет к нему
  `xray-supervisor`.
- Supervisor запускает Xray дочерним процессом. Он проверяет и применяет
  кандидатные конфиги, восстанавливает прежнюю конфигурацию при ошибке,
  заменяет отдельные inbound’ы, хранит revision fence, собирает статус и
  редактированные логи, выполняет сетевые probes и обращается к Xray
  Handler/Stats API.
- Controller использует typed gRPC контракт supervisor’а. Backend и Web UI
  общаются с runtime только через Controller.
- Для выдачи REALITY shortId уже применяется пул зарезервированных значений;
  исчерпание пула может потребовать замены inbound.

Текущие обязанности и gRPC контракт описаны в
[`xray-supervisor-grpc-plan.md`](xray-supervisor-grpc-plan.md), а границы
Controller и runtime adapters — в
[`controller-service-plan.md`](controller-service-plan.md).

## Архитектурные решения и ограничения

1. **Собственный API — доменный, не копия API Xray.** Controller вызывает
   операции уровня продукта: получить возможности и состояние runtime,
   применить желаемую конфигурацию, добавить/отозвать пользователя, получить
   телеметрию. Внутренние protobuf-типы и `TypedMessage` Xray не становятся
   публичным контрактом Xray-easy.
2. **Один активный путь записи.** При переключении один Controller adapter
   выполняет изменения в Xray. Не отправлять одну мутацию одновременно старому
   и новому runtime.
3. **Стабильное владение данными.** Runtime service не изменяет базу backend и
   не становится вторым владельцем списка устройств. После рестарта он
   загружает желаемую конфигурацию из согласованного источника и сверяет её с
   текущим runtime.
4. **Версия Xray закреплена и проверяема.** Сервис собирается из Go-модуля
   Xray-core с точной версией в `go.mod`/`go.sum`. Нужно документировать
   соответствие этой версии текущей переменной `XRAY_VERSION`, совместимой
   записи и версии, показываемой Doctor. Версии из upstream image tag и Go
   module не считать взаимозаменяемыми без проверки.
5. **Новый процесс — один Xray runtime.** Внутри контейнера не запускается
   второй дочерний Xray. После закрытия `core.Instance` нельзя считать его
   повторный запуск в том же процессе надёжным, пока это не подтверждено
   тестами для закреплённой версии. После неисправимого сбоя runtime service
   завершает процесс; восстановление выполняет политика перезапуска контейнера.
6. **Встраивание не является hot reload всей конфигурации.** Изменения,
   которые Xray поддерживает через live API, можно применять без полной
   пересборки runtime. Замена inbound кратко разрывает соединения на нём.
   Полная замена конфигурации, TLS/REALITY параметров или самого экземпляра
   может оборвать все активные соединения.
7. **Не логировать конфигурации и секреты.** Запрещено писать в логи UUID,
   пароли, private keys, профили, полные protobuf payloads, master key и токены.
   IP-адрес клиента не включать в логи по умолчанию.
8. **Не обещать неподдерживаемые измерения.** Отдавать возможности и
   телеметрию с явными признаками `supported`/`unavailable` по протоколам.
   Счётчик трафика, online IP map и полный список текущих соединений — разные
   данные.

## Этапы реализации

### Этап 0. Зафиксировать поведение и контрактные сценарии

- Инвентаризировать все текущие вызовы Controller к supervisor: health,
  status, logs, validate/apply, replace inbound, REALITY target probe, IPv6
  probe, Handler users, Stats users, reconciliation, backup/restore.
- Зафиксировать для VLESS, VMess и Hysteria 2 операции добавления/отзыва,
  изменения настроек, поведение shortId pool, ошибки и ожидаемый разрыв
  подключений.
- Определить, какие операции сейчас передают путь к файлу, а какие — только
  тег/идентификатор; проверить общие mounts `xray_config` и revision state.
- Создать матрицу parity-тестов для старого runtime. Записать текущую
  совместимую версию из проекта, базовые ответы API, статистику и поведение
  восстановления.
- Не менять рабочую Compose-схему и не удалять supervisor на этом этапе.

**Готово, когда:** инвентаризированы все production call sites, сохранены
ожидаемые результаты/ошибки и известны все вызываемые типы Xray API.

### Этап 1. Spike: проверить встраивание Xray-core

- Создать изолированный экспериментальный Go-модуль (либо отдельный пакет,
  если это не конфликтует с зависимостями AWG) с точной версией Xray-core.
- Подключить необходимые upstream registrations/distro imports и загрузить
  реальный конфиг, сформированный текущим control plane.
- Создать и запустить `core.Instance` с VLESS + REALITY; проверить штатное
  завершение по сигналу и доступность функций inbound, stats и policy.
- Через интерфейсы `core.Instance.GetFeature`, `inbound.Manager` и
  `proxy.UserManager` проверить получение inbound/user roster и live
  add/remove для поддерживаемого сценария. Не передавать данные через
  Xray HandlerService в экспериментальном пути.
- Через `stats.Manager` исследовать пользовательские counters и online maps:
  определить точные ключи, необходимые policy flags, время жизни IP и то,
  какие из используемых протоколов публикуют ожидаемые значения.
- Проверить, можно ли безопасно валидировать кандидат, пока активный runtime
  слушает те же порты. Если создание/запуск кандидата резервирует listener’ы,
  определить безопасный preflight: построение config без `Start`, отдельный
  validator-процесс или сохранение upstream `xray run -test` как временного
  инструмента.
- Проверить несколько последовательных циклов создания, запуска и закрытия
  **разных** `core.Instance` в одном процессе. Если чистое восстановление
  предыдущего runtime после неудачного apply нельзя гарантировать, зафиксировать
  вариант завершения runtime service с последующим Compose restart на прежнем
  `active.json`.
- Оценить размер и время multiarch-сборки, версию Go, образы и влияние
  зависимостей на текущие Go modules.
- Сохранить краткий результат spike в этом плане или в отдельном отчёте до
  начала миграции.

**Готово, когда:** подтверждено, что активный runtime работает как библиотека,
данные user/counter можно безопасно читать, описана валидация кандидата и
перечислены ограничения по протоколам. При блокирующем ограничении пересмотреть
дизайн до замены production-пути.

**Результат spike от 2026-09-30:**

- Создан изолированный модуль `xray-runtime/`. Go не принимает upstream tag
  `v26.7.28` как module version для модуля без `/v26`, поэтому зависимость
  закреплена pseudo-version
  `v1.260327.1-0.20260728075948-5ca6f4b7d4dc`, построенной по release commit
  `5ca6f4b7d4dc`. Она соответствует Xray-core 26.7.28.
- У upstream модуля указано `go 1.26.0`; корневой backend-модуль остаётся на
  своей текущей версии Go. Встроенный runtime собирается отдельно новым
  toolchain, чтобы не повышать требование для всего приложения.
- Тест `xray-runtime/internal/spike` сформировал конфигурацию с используемыми
  проектом VLESS + REALITY, VMess + TLS и Hysteria 2, успешно прошёл её через
  `infra/conf/serial.LoadJSONConfig`, `core.New` и `Instance.Start`.
- Для трёх inbound’ов публичная цепочка
  `inbound.Manager.GetHandler` → `proxy.GetInbound` → `proxy.UserManager`
  позволяет напрямую читать roster и выполнять add/remove пользователей без
  вызова Xray HandlerService. `stats.Manager` напрямую предоставляет traffic
  counters и online maps. Тест подтвердил их доступность и работу интерфейсов;
  сбор реального трафика и online IP отдельно проверяется на следующем этапе.
- В исходнике закреплённой версии `Instance.Start` документирован как
  однократный запуск; после `Close` повторный старт не гарантируется. Поэтому
  production recovery после неудачной полной замены runtime должен полагаться
  на restart процесса/контейнера и прежний durable `active.json`, а не на
  повторный `Start` того же `Instance`.
- Не подтверждены этим spike: фактическая telemetry на пользовательском
  трафике для каждого протокола, безопасный preflight без bind портов,
  multiarch Docker build и стоимость образа. Эти проверки остаются в этапах
  4–6 до переключения Controller.

### Этап 2. Спроектировать собственный typed gRPC контракт

- Добавить новую версионируемую службу, например
  `xrayeasy.xray.v1.Runtime`, в отдельный protobuf package.
- Использовать product-level поля и идентификаторы. Не принимать произвольные
  Go/Xray-типы и не возвращать сырые `TypedMessage`.
- Рассмотреть следующие группы RPC:
  - `Health`, `GetRuntimeStatus`, `GetCapabilities`, `GetRecentLogs`;
  - `ValidateConfiguration` и `ApplyConfiguration`/`ReconcileDesiredState`;
  - `CreateUser`, `RemoveUser` или единый idempotent `ReconcileUsers`;
  - `GetTelemetry` с cumulative byte counters, sample timestamp, online
    status, last-seen и опциональными source IP;
  - `ProbeRealityTarget` и `ProbeIPv6Egress`.
- Передавать `operation_id`, монотонную `revision` и request correlation;
  сохранять проверку повтора одной операции с тем же payload и отказ от
  автоматических RPC retry до доказательства идемпотентности.
- Уточнить способ передачи конфигурации. Не передавать container filesystem
  path через контракт. Выбрать между сериализованным candidate snapshot,
  ограниченным чтением подготовленного файла внутри Xray service или
  протокольными настройками; не включать secrets в обычные диагностические
  ответы.
- Для каждого telemetry поля описать смысл, частоту обновления, единицы,
  возможное отсутствие, поведение после рестарта и уровень поддержки по
  протоколам.
- Оставить gRPC на закрытой Compose control network, не публиковать host port,
  использовать отдельный токен service-to-service и текущие правила
  корреляции/redaction.
- Сначала покрыть контракт тестами на fake runtime; только затем реализовывать
  основной сервис.

**Готово, когда:** согласованы `.proto`, таблица ошибок/status codes,
идемпотентность, auth и тесты сериализации/совместимости; Controller может
подключить новый adapter без изменения backend HTTP API и Web UI.

**Результат этапа 2 от 2026-09-30:**

- Добавлен контракт `xrayeasy.xray.v1.Runtime` в
  `internal/xrayruntime/api/v1/runtime.proto` и закреплена генерация Go/gRPC
  кода в protobuf scripts.
- API покрывает health/status/capabilities/logs, проверку и применение
  конфигурационного snapshot, замену inbound, операции с пользователями,
  telemetry и сетевые probes. Протоколы представлены enum; сведения о
  доступности telemetry описаны отдельными capability flags.
- Кандидат передаётся как snapshot bytes с `operation_id` и `revision`, а не
  как путь внутри контейнера. Snapshot содержит runtime secrets; контракт
  прямо запрещает включать его в логи или ошибки.
- Добавлены сериализационный и descriptor tests: проверяются versioned service,
  основные методы, enums и отсутствие path-based config request. `go test
  ./internal/xrayruntime/api/v1` проходит.
- Runtime authentication/interceptors и поведенческие fake-runtime тесты
  остаются в этапах 3 и 6; API ещё не подключён к production Controller.

### Этап 3. Реализовать оболочку runtime service

- Создать `cmd/xray-runtime` и изолированный модуль/target сборки с pinned
  Xray-core dependency.
- Реализовать конфигурацию процесса, структурированные логи, signal handling,
  private gRPC listener, auth interceptor и healthcheck CLI.
- Загрузить конфигурацию через upstream config builder, используя только
  необходимые и явно перечисленные регистрации протоколов.
- Создать ровно один `core.Instance`; внедрить интерфейсы runtime и loader,
  чтобы unit tests не требовали сетевых портов.
- Подключить version/capability reporting. Compose image version, версию
  runtime и версию, принятую compatibility matrix, показывать отдельно и
  сравнивать в Doctor.
- Отработать безопасную shutdown sequence и поведение при ошибках `New`,
  `Start`, RPC listener и Xray runtime. Не ловить panic как будто экземпляр
  можно безопасно перезапустить; неисправимая ошибка должна завершать
  контейнерный процесс с redacted ошибкой.

**Готово, когда:** новый бинарник собирается для amd64/arm64, стартует
закреплённый runtime, проходит healthcheck, корректно закрывается и не меняет
старый production path.

**Результат этапа 3 от 2026-09-30:**

- Добавлен самостоятельный `xray-runtime` в nested Go module, поэтому
  требование Go 1.26 от Xray-core не поднимает версию корневого backend.
- Сервис при запуске загружает `active.json` через upstream config builder,
  создаёт один `core.Instance` и запускает его. Без файла конфигурации сервис
  готов к первичной настройке и сообщает состояние `NO_CONFIGURATION`.
- Добавлены private gRPC listener, healthcheck CLI и отдельная HMAC
  аутентификация для `healthcheck` и `control-plane` с nonce replay protection.
  RPC-логи содержат безопасные поля корреляции и результата, но не payload.
- Добавлены version/status/capability ответы и preflight через upstream
  config builder без создания `core.Instance`. Ошибки наружу возвращаются
  обобщённо, без тела Xray ошибки и секретных фрагментов. Это пока синтаксическая
  проверка: полноценный `core.New` вынесен в этап 4, поскольку создание instance
  меняет process-global logger и system dialer и могло бы нарушить работу
  действующего runtime.
- Warning/error сообщения Xray направляются в bounded diagnostics buffer;
  access-сообщения отбрасываются, UUID/секреты и IP endpoints маскируются.
- Создан отдельный `Dockerfile.xray-runtime`. Buildx сборка для
  `linux/amd64` и `linux/arm64` проходит. Рабочие `compose.yaml`,
  `Dockerfile.xray` и supervisor path не переключались.
- Unit-тесты сервисного lifecycle, статуса, capability, auth и ошибок, корневой
  `go test ./...`, runtime `go test ./...` (включая реальный Xray integration
  spike с локальными TCP/UDP listeners) и `go vet ./...` прошли. Runtime
  mutation/telemetry RPC пока остаются явно `Unimplemented` и переносятся на
  этапы 4–5; coverage gates runtime будут закрыты на этапе 6.

### Этап 4. Перенести runtime lifecycle, ревизии и мутации

- Перенести durable revision fence и привязку повтора к operation ID,
  mutation type и hash точного candidate payload. Не сохранять секретный
  конфиг в revision journal.
- Реализовать конфигурационный preflight без изменения активного runtime;
  применять уже проверенный candidate под сериализованной блокировкой.
  `core.New` нельзя вызывать в основном процессе для candidate, пока работает
  активный instance: Xray-core меняет process-global logger и system dialer при
  создании instance. Полную candidate-проверку следует изолировать в отдельном
  короткоживущем validator-процессе либо найти эквивалентный безопасный путь.
- Определить транзакционную последовательность `candidate → runtime → active`
  и точку commit. Не считать повторное использование закрытого `core.Instance`
  допустимым. Если запуск candidate не удался и восстановление предыдущего
  runtime в том же процессе не подтверждено, завершить сервис так, чтобы
  Compose restart поднял сохранённый прежний `active.json`; сохранить
  диагностическую причину сбоя и operation/revision semantics.
- Перенести targeted inbound replacement, сохранив её семантику: краткий
  разрыв соединений конкретного inbound и rollback старого inbound при
  ошибке нового.
- Перенести add/remove пользователей на live manager API там, где это
  поддерживается и прошло протокольные тесты. Для REALITY коротких ID
  сохранить пул и текущую стратегию при исчерпании; не обещать изменение
  shortIds без замены inbound.
- Не пытаться применять неподдерживаемый live update через обходные
  Xray-интерфейсы без отдельного теста на закреплённом runtime.
- Для каждого изменения сохранить backup-before-dangerous-change,
  reconciliation и восстановление после рестарта согласно существующим
  продуктовым правилам.

**Готово, когда:** parity-тесты подтверждают успешный apply, ошибки валидации,
rollback, stale revision, replay/conflict, отмену deadline, restart service и
все ранее поддерживаемые live user/inbound операции.

**Результат этапа 4 от 2026-09-30:**

- Добавлен versioned durable revision journal runtime service по умолчанию в
  `/etc/xray/revision-state.json`. Он сохраняет revision, operation ID,
  mutation key и SHA-256 fingerprint, но не записывает snapshot, credential,
  email пользователя или другие секреты. Запись выполняется атомарно через
  временный файл, `fsync` и rename с правами `0600`.
- На рестарте committed операции переводятся в pending для повторного
  согласования с восстановленным `active.json`. Apply сравнивает snapshot с
  активным содержимым; add/remove проверяют фактический user manager; inbound
  replacement сравнивает настройки текущего handler. Поэтому повтор операции
  после сбоя не должен повторно менять уже согласованное состояние.
- Полная проверка конфигурации сначала запускает upstream config builder, затем
  передаёт candidate по stdin отдельному `xray-runtime validate-candidate`
  subprocess. В subprocess выполняется `core.New` без `Start`; его stdout/stderr
  отбрасываются, а parent учитывает gRPC cancellation/deadline. Candidate не
  сохраняется во временный файл и не меняет глобальные настройки активного
  процесса.
- Реализованы ApplyConfiguration с последовательной заменой единственного
  `core.Instance`, targeted `ReplaceInbound` через `inbound.Manager` и
  `core.AddInboundHandler`, а также Add/Remove/List users через публичные
  `proxy.UserManager` интерфейсы. Замена inbound восстанавливает прежние
  settings при неудачном добавлении; если восстановление невозможно, runtime
  сообщает entrypoint о необходимости завершить процесс. После неудачного
  полного apply runtime также завершается, чтобы Docker заново поднял прежний
  durable `active.json`.
- При restart committed операции становятся pending, потому что backend мог
  ещё не продвинуть active snapshot. Операции сделаны идемпотентными по
  фактическому состоянию Xray: одинаковый существующий account не добавляется
  повторно, отсутствующий пользователь считается уже отозванным, совпавший
  inbound и snapshot не перезапускаются повторно. При компенсации используется
  та же семантика `operation_id + "-rollback"` и revision fence старого
  supervisor.
- Для протоколов runtime выбирает единственный настроенный inbound по enum:
  VLESS, VMess или Hysteria 2. Неоднозначные конфиги с двумя inbound одного
  протокола отклоняются. UUID для VLESS/VMess проверяются в canonical форме,
  поддерживаемый flow ограничен пустым значением или XTLS Vision для VLESS.
  Capabilities теперь сообщают user management как доступный; telemetry и
  probes остаются этапом 5.
- Добавлены unit-тесты для revision persistence/replay/conflict/rollback,
  apply и process restart semantics, input validation, deadline cancellation,
  user operations и fatal recovery. Локальный integration test запускает
  настоящий embedded Xray на временном loopback TCP-порту, проверяет live
  add/remove VLESS пользователя, смену inbound listener и повторные операции.
- Проверки прошли: runtime `go test ./internal/runtime ./cmd/xray-runtime`,
  runtime `go vet`, корневые `go test ./...` и `go vet ./...`; отдельно собран
  исполняемый runtime и проверен CLI preflight на валидном и malformed JSON.
  Production Compose и старый supervisor path не менялись. Проверка реального
  старта контейнера на VDS остаётся за пользователем после этапов 5–7 и push.

### Этап 5. Реализовать status и telemetry через core interfaces

- Читать VLESS/VMess/Hysteria cumulative counters через stats feature и
  сохранять имена/соответствие пользователей за adapter boundary.
- Уточнить наличие/работу `statsUserOnline` и online IP maps отдельно для
  каждого протокола на текущей закреплённой версии. Не считать online-map
  равнозначной точному журналу соединений.
- Возвращать timestamp наблюдения, чтобы Controller рассчитывал текущие
  uplink/downlink rates из дельты cumulative bytes. Определить поведение при
  сбросе counters, рестарте и пропущенном sample.
- Сопоставлять технический Xray user identity с opaque устройством; не
  включать UUID, email-метки и source IP в логи.
- Для недоступных полей возвращать явную unsupported/unavailable семантику,
  а не синтетический online или нулевую скорость.
- Проверить источник source IP: online-map может дать IP и last-seen только
  для протоколов/конфигураций, которые его записывают. Если точные активные
  сессии нужны для UI, а upstream API их не предоставляет, оформить отдельное
  решение о hook/форке вместо молчаливого добавления неустойчивых зависимостей
  от внутренних структур.

**Готово, когда:** контрактные telemetry тесты проверяют значения и отсутствие
данных для каждого протокола; VLESS, VMess и Hysteria отдельно проверены на
реальном Xray runtime, а семантика UI не вводит пользователя в заблуждение.

**Результат этапа 5 от 2026-09-30:**

- Runtime напрямую перечисляет пользователей через `proxy.UserManager` для
  настроенных VLESS, VMess и Hysteria 2 inbound’ов, а затем объединяет roster
  со stats counters `user>>>email>>>traffic>>>{uplink,downlink}` и online map
  `user>>>email>>>online`. В telemetry входят и offline-пользователи с нулём,
  если для них ещё нет counters.
- `traffic_counters`, `online_status` и `source_ip` capabilities выставляются
  только когда в конфиге включён stats app, embedded instance предоставляет
  stats manager, а policy level `0` разрешает соответствующие user stats.
  Если runtime не может прочитать stats feature, RPC возвращает
  `UNAVAILABLE`, а не правдоподобные нулевые значения.
- `online` означает, что Xray online map содержит хотя бы один текущий source
  IP. Источник IP выдаётся только пока он присутствует в map; адреса
  нормализуются и ограничены 32 значениями на пользователя. Последнее
  наблюдение сохраняется runtime в памяти до удаления user из roster или его
  отзыва. История после рестарта остаётся ответственностью backend SQLite.
- Добавлены sampled timestamp и безопасное преобразование счётчиков в
  неотрицательные значения. Скорости не вычисляются runtime: Controller
  продолжает получать cumulative bytes и строить rate по дельте samples.
  Ошибки telemetry наружу обобщены и не включают внутренние данные.
- Реальный embedded Xray integration test проверяет сбор counters, online
  status, IPv4-mapped IPv6 normalization и переход online → offline на VLESS;
  отдельный тест с тремя реальными inbound managers проверяет roster и
  synthetic stats counters/online maps для VLESS, VMess и Hysteria 2.
  Проверены capability gating, offline users, last-seen cache, очистка cache
  после исчезновения/отзыва user, cancellation и безопасная ошибка stats.
- `GOCACHE=/tmp/xray-go-cache go test ./...` и `go vet ./...` внутри
  `xray-runtime` прошли. Интеграционные тесты требуют возможности открыть
  временные loopback TCP/UDP listeners; sandbox запуск был выполнен с
  соответствующим разрешением. Реальный клиентский трафик, статистика после
  рестарта и Controller/UI parity проверяются в этапах 6–7 и на VDS.

### Этап 6. Интеграционные и отказоустойчивые тесты

- Запускать настоящую embedded Xray Instance в изолированных тестах на
  непересекающихся локальных портах; проверять по крайней мере VLESS + REALITY,
  VMess + TLS и Hysteria 2 конфигурации, активные в проекте.
- Проверить user add/remove, shortId exhaustion, inbound replace, counters,
  online maps, shutdown, malformed config, занятые порты и failed startup.
- Добавить сбои на границах `New`, `Start`, apply, persistence/promotion,
  rollback, gRPC timeout/cancellation, клиентский disconnect и restart
  контейнера.
- Проверить, что gRPC ответы/ошибки/логи не содержат конфиг, UUID, ключи,
  пароль, токены или profile URI; проверить корреляцию request/operation IDs
  на backend → Controller → runtime service.
- Запускать race tests, vet, protobuf generation/check, Compose validation и
  multiarch builds.
- Держать текущие repository coverage gates; новые handwritten файлы runtime
  покрыть не менее чем на 90% каждый, если gate текущих supervisor файлов
  остаётся применимым. Исключать строки из метрик только по существующим
  правилам для generated code.

**Готово, когда:** тестовый набор и все текущие coverage gates проходят без VDS;
Docker multiarch build и Compose validation выполняются перед opt-in проверкой
на этапе 7. Полный old/new parity подтверждается на тестовом Compose stack до
перехода к этапу 8.

**Результат этапа 6 от 2026-09-30:**

- Добавлен отдельный CI job для embedded runtime: обычные тесты, race detector
  и per-file coverage gate. Скрипт `scripts/xray-runtime-coverage.sh`
  контролирует каждый handwritten Go-файл в `cmd/xray-runtime` и
  `internal/runtime`; порог по умолчанию — 90%, generated protobuf и тестовые
  файлы в метрику не входят.
- Покрытие по файлам после изменений: CLI `main.go` — 94.3%, revision journal
  — 95.7%, engine — 90.4%, telemetry — 95.7%, service — 91.4%.
- Добавлены тесты для graceful shutdown и принудительной остановки gRPC server,
  ошибок запуска/listener, child-process candidate validation, ошибок
  persistence на границах записи revision journal, runtime lifecycle и
  telemetry, deadlines, отсутствующих inbound/stats и cancellation.
- Spike-конфигурация больше не запускает встроенный Xray API inbound: он не
  нужен runtime, который обращается к core interfaces, и включал upstream
  Commander с race при параллельных Serve/Close. После его удаления полный
  runtime race detector проходит.
- Заодно исправлены два дефекта: Xray `NoopManager` больше не считается
  доступной Stats feature, а диагностические логи embedded runtime редактируют
  IP-адреса вместе с секретами.
- Проверки прошли: `go test -race -count=1 ./...`, `go vet ./...` в модуле
  `xray-runtime`, а также per-file coverage gate с порогом 90%. Проверены
  `git diff --check` и синтаксис GitHub Actions workflow.
- На этом этапе не менялись production Compose и Controller adapter. Docker
  multiarch build, Compose validation и parity всей цепочки выполняются в
  следующем opt-in этапе; ручная проверка клиентского подключения остаётся за
  владельцем VDS.

### Этап 7. Подключить новый adapter к Controller в тестовом Compose профиле

- Добавить новый runtime в отдельный opt-in Compose override; старый supervisor
  остаётся штатным вариантом для rollback. Не запускать оба runtime
  одновременно: они используют одни публичные порты и должны иметь ровно один
  активный путь записи. Для эксперимента использовать отдельный stack или
  изолированную копию volumes/config.
- Реализовать Controller adapter к новому Xray runtime gRPC API. Не менять
  backend HTTP contract, UI API и AWG adapter.
- Переключать целые группы операций только после parity tests; не делать
  двойную запись. Прочтения допускается временно сравнивать в тестовой среде,
  но не выдавать два источника за одно authoritative состояние.
- Проверить восстановление конфигурации и runtime после чистого старта,
  контейнерного restart, повреждённого candidate и восстановленного backup.
- Добавить Doctor checks для embedded core version, gRPC health, активной
  revision, inbound tags, stats capability и runtime state.

**Реализация opt-in пути:**

- `XRAY_ADAPTER=embedded` подключал Controller к типизированному runtime API;
  на момент реализации этапа 7 штатным значением оставался `supervisor`.
- Controller монтирует Xray snapshots только для чтения, проверяет, что путь
  остаётся внутри `/etc/xray`, и передаёт runtime содержимое файла. Пути и JSON
  конфигурации в RPC-логи не попадают.
- Live add/remove пользователей передают revision, если операция создана
  backend и связана с persisted apply-operation. Нулевая revision разрешена
  только для идемпотентной сверки roster после запуска Controller и не меняет
  config revision fence.
- `compose.xray-runtime.yaml` заменял процесс в сервисе `xray` на embedded
  runtime, создавал отдельные token/state volumes и сохранял supervisor как
  production default на время opt-in проверки.
- Embedded core пока закреплён на проверенной версии Xray `26.7.28` из
  `xray-runtime/go.mod`. Build проверяет `XRAY_VERSION` и останавливается при
  несовпадении, чтобы backend не сообщал версию, отличающуюся от встроенного
  core.
- `scripts/xray-runtime-test-stack.sh` задаёт отдельные project name, host ports
  и private subnets по умолчанию. Тестовый стек использует данные из локального
  `.env`, но не использует production named volumes или опубликованные порты.
- До VDS-приёмки embedded runtime штатный путь оставался на supervisor.

Для локальной проверки изолированного embedded стека:

```sh
./scripts/xray-runtime-test-stack.sh up -d --build --wait --wait-timeout 180
./scripts/xray-runtime-test-stack.sh ps
./scripts/xray-runtime-test-stack.sh exec xray-easy /usr/local/bin/xray-easy doctor
```

Web UI будет доступен через SSH tunnel на `http://127.0.0.1:18080`; по
умолчанию тестовый стек публикует Xray TCP/UDP на `18443`, VMess TCP на `19443`
и AmneziaWG UDP на `11234`, если соответствующий профиль включён через
`XRAY_EASY_RUNTIME_PROFILES=awg XRAY_EASY_RUNTIME_AWG_PUBLIC_HOST=<public-ip>`.
По умолчанию AWG выключен для этого Xray-only теста. После теста
остановить контейнеры можно командой
`./scripts/xray-runtime-test-stack.sh down` — не добавляй `-v`, чтобы сохранить
изолированное тестовое состояние до анализа результатов.

Если стандартные тестовые subnets заняты на VDS, перед запуском задай
`XRAY_EASY_RUNTIME_CONTROL_SUBNET` и `XRAY_EASY_RUNTIME_BACKEND_SUBNET` на две
свободные непересекающиеся сети. Тестовые host ports и project name можно
переопределить переменными `XRAY_EASY_RUNTIME_*` из launcher.

**Результат реализации этапа 7 от 2026-09-30:**

- Добавлены adapter и тесты Controller ↔ embedded runtime. Проверены
  authentication, runtime failures, path traversal/symlink rejection, ответы
  с неожиданными revisions/operation IDs, Xray telemetry и нормализация IPv4.
- Runtime capabilities теперь возвращают tag каждого inbound. Controller
  передаёт в Doctor активную revision, список tag-ов и статистическую
  capability; Doctor сверяет поддерживаемые tag-и с `active.json`.
- Coverage: handwritten backend — 90.5% overall, Controller — 92.2%, новый
  `embedded_xray.go` — 90.4%, `doctor.go` — 93.0%. В embedded runtime каждый
  handwritten Go-файл остаётся выше 90%.
- Прошли `go test ./...`, runtime `go test -race -count=1 ./...`, `go vet ./...`
  в обоих Go-модулях и backend/runtime coverage gates.
- Compose test launcher прошёл shell syntax и `docker compose config --quiet`.
  Проверены отдельные test ports/subnets, Controller adapter selection,
  read-only snapshot mount и writable `/etc/xray` volume embedded runtime.
- Docker Buildx собрал runtime и Controller для `linux/amd64` и `linux/arm64`;
  образы не публиковались в registry. Тестовые контейнеры локально не запускались.
- Тогда production Compose оставался на supervisor по умолчанию. Embedded
  проверка была отдельным opt-in стеком.

**VDS-приёмка этапа 7:** владелец VDS подтвердил, что создание, удаление,
блокировка и разблокировка профилей работают, онлайн-статус и статистика
передаются, а Doctor проходит без ошибок. Ранее найденная ошибка Doctor для
проверки Active Xray config была исправлена и подтверждена повторным запуском.
Этого достаточно, чтобы перейти к переключению штатного Compose; отдельные
сценарии чистого восстановления из backup здесь не проверялись.

**Готово, когда:** opt-in Compose stack проходит функциональные и diagnostics
сценарии на VDS; backup restore отдельно не подтверждался.

### Этап 8. Переключить штатный Compose runtime, сохранив rollback

- Сделать новый runtime штатным entrypoint существующего `xray` сервиса,
  сохранив внутренний адрес/порт Controller, внешние опубликованные порты,
  config/data volumes, private control network и secret rotation.
- Сохранить Xray version display, `XRAY_VERSION`/compatibility validation,
  Doctor, backup/restore, logs, probes, IPv6 egress и Hysteria TLS handling.
- Сделать стандартный `compose.yaml` embedded-конфигурацией; удалить больше не
  нужный opt-in override и переключить тестовый launcher на стандартный файл.
- Сохранить отдельный `compose.supervisor-rollback.yaml` и связанные образы,
  контракты, клиенты, токен и тесты до успешной VDS-проверки нового default.
- Обновить installer, `.env.example`, README, troubleshooting и
  implementation/controller/supervisor plans; чётко описать сборку из исходников
  и точное ограничение версии embedded Xray-core.
- Создать и отправить отдельный коммит до ручной проверки штатного Compose на
  VDS. После успешной проверки отдельно выполнить финальный cleanup этапа 9.

**Готово, когда:** локальные проверки стандартного Compose проходят, VDS
запускается на embedded runtime, а supervisor rollback остаётся доступен до
ручной приёмки.

### Этап 9. Удалить supervisor после VDS-приёмки embedded default

- Проверить на VDS запуск и обновление стандартного Compose, подключение
  клиентов, создание/отзыв/блокировку профилей, телеметрию, Doctor, логи и
  restart recovery; отдельно проверить backup/restore, если он нужен для
  релизной приёмки.
- После успешной проверки удалить временный rollback Compose, дочерний Xray
  process, supervisor gRPC contract/client, token/state volumes, Docker build
  stage и тесты, которые нужны только supervisor adapter.
- Удалить генерацию supervisor token из installer и устаревшие переменные из
  `.env.example`; обновить старые планы, README и troubleshooting.

**Готово, когда:** чистая установка и upgrade на VDS используют только embedded
runtime; backend и Controller не содержат supervisor пути и ранее проверенные
сценарии проходят.

## Требования к безопасности и наблюдаемости

- Сервисы runtime и Controller доступны только внутри закрытых Docker networks;
  host ports для внутренних gRPC не публикуются.
- Для backend → Controller и Controller → Xray runtime используются разные
  секреты и независимая аутентификация. Секреты передаются через файлы,
  не через обычные env values, доступные в inspect output.
- На каждом слое сохраняются JSON logs со временем, сервисом, request ID,
  operation ID, revision, методом, протоколом, результатом и длительностью.
  Содержимое запроса/ответа не логируется.
- Секреты, device names и source IP не попадают в логи. Ошибки Xray
  фильтруются перед возвратом через gRPC/HTTP и перед включением в support
  bundle.
- Размеры сообщений, deadlines, status code mapping, replay protection и
  поведение при timeout остаются явными и тестируемыми.

## Порядок выполнения и коммиты

1. Сначала выполнить и записать результаты этапа 1. Если он выявит блокер,
   сначала скорректировать этот план.
2. Реализовывать этапы последовательно. В каждом этапе сначала обновить
   acceptance criteria при необходимости, затем код и тесты, затем отдельный
   коммит.
3. Не объединять переезд runtime, новый gRPC контракт и удаление supervisor в
   один коммит.
4. Для этапов 6–8 сначала завершить локальные gates и создать отдельные
   коммиты, отправляя каждый в `main` перед ручной VDS проверкой. Supervisor
   rollback path удалять только отдельным этапом после приёмки embedded default.

## Критерии завершения всей миграции

- В Compose-контейнере `xray` работает один собственный Go runtime service,
  внутри которого работает Xray-core как библиотека; отдельного дочернего
  Xray process и `xray-supervisor` нет.
- Controller использует новый версионируемый typed Xray runtime contract.
- Backend остаётся единственным источником desired product state; UI и
  публичный HTTP API не меняются.
- Все текущие функции supervisor имеют описанное, проверенное соответствие в
  runtime service или явно сняты из требований с подтверждением пользователя.
- Реально доступные поля status/telemetry документированы по протоколам;
  unsupported source IP/session data не имитируются.
- Тесты, coverage gates, Docker multiarch build, Compose validation и VDS
  acceptance проходят; документация отражает фактическую топологию и
  обслуживание версии Xray-core.

## Справочные материалы

- [Xray API Interface](https://xtls.github.io/en/config/api.html): текущие
  HandlerService/StatsService операции и документированные ограничения.
- [Xray `core.Instance`](https://github.com/XTLS/Xray-core/blob/main/core/xray.go):
  `New`, `GetFeature`, запуск и закрытие instance.
- [Inbound Manager](https://github.com/XTLS/Xray-core/blob/main/features/inbound/inbound.go):
  интерфейс чтения, добавления и удаления inbound handlers.
- [Stats Manager](https://github.com/XTLS/Xray-core/blob/main/features/stats/stats.go):
  counters, online maps и наблюдение IP/last-seen.
- [Xray config builder](https://github.com/XTLS/Xray-core/blob/main/infra/conf/serial/builder.go):
  преобразование конфигурационных файлов в core config.
- [AmneziaWG module integration](../awg-service/README.md) и его
  [`Manager`](../awg-service/internal/control/manager.go): образец собственного
  сервиса над Go-модулем движка.
