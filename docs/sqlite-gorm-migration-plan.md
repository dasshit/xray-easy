# План перехода SQLite-хранилища на GORM

## Цель и границы

Перевести SQLite-хранилище control-plane на GORM, сохранив существующие файлы
БД, поведение транзакций, pure-Go сборку с `CGO_ENABLED=0`, backup/restore и
текущие HTTP/gRPC-контракты. Межсервисный обмен остаётся только через gRPC;
GORM используется внутри процесса, который владеет SQLite.

Миграции схемы также управляются через GORM: описание таблиц задаётся моделями,
эволюция выполняется `Migrator().AutoMigrate`, а нестандартные преобразования
запускаются как упорядоченные миграционные шаги через GORM `Raw`/`Exec` и
транзакции. SQLite-операции без ORM-аналога (`PRAGMA`, `VACUUM INTO`, `ATTACH`)
могут использоваться только как узкие GORM `Raw`/`Exec` шаги; открытие
параллельного SQL-доступа из бизнес-методов не допускается.

## Текущее состояние и ограничения совместимости

- SQLite открывается напрямую через `database/sql` и `modernc.org/sqlite`.
- `internal/store/store.go` совмещает схему, миграции, CRUD, backup/restore,
  сессии, профили, short-ID pool, статистику и audit.
- Таблица `schema_migrations` содержит исторические маркеры 1–6. Версии 3 и 4
  обозначают отложенное заполнение пула REALITY short ID и преобразование
  старых клиентов в `legacy_dual`; это не последовательный migration runner.
- Переход clients к protocol-aware модели требует backup и пересоздания таблицы.
  Этот шаг должен выполниться до добавления GORM недостающих колонок в старую
  таблицу, иначе legacy-клиентам нельзя будет восстановить прежнюю семантику.
- В `RestoreFrom` намеренно сохраняется `apply_revision_sequence`: restore
  старого backup не должен уменьшать выданный runtime revision.
- Timestamp и nullable credentials исторически хранятся как RFC3339Nano TEXT и
  NULL. Модели должны явно сохранять эту форму, пока все чтения не переведены.
- Контейнеры control-plane собираются без CGO. GORM подключается к уже открытому
  `modernc.org/sqlite` `*sql.DB`, поэтому драйвер и параметры WAL/foreign keys/
  busy timeout остаются прежними.

## Целевая архитектура

1. `Store` владеет одним `*gorm.DB`, подключённым к существующему pure-Go
   SQLite pool. Настройка контекста, закрытия, ping и логирования находится в
   одном месте.
2. Внутренние persistence-модели отделены от `internal/domain`; таблицы и
   колонки задаются явными GORM-тегами, включая ключи, индексы, defaults,
   nullable поля и связи.
3. Инициализация схемы идемпотентна. GORM Migrator создаёт и расширяет таблицы;
   версия новых migration steps хранится рядом с историческими маркерами и не
   удаляет/переинтерпретирует версии 1–6.
4. Репозиторные методы используют GORM model API и GORM transactions. `Raw` и
   `Exec` остаются для выборок/обновлений, где нужны SQLite upsert-выражения,
   условные атомарные переходы либо совместимость со старыми snapshot-схемами.
5. Backup, restore и migration snapshot работают на том же connection pool и
   остаются атомарными. На время перехода их SQL остаётся изолированным в
   migration/backup helpers и не смешивается с HTTP или gRPC слоями.

## Этапы реализации

### Этап 0 — инвентаризация и планирование — готово

- [x] Найти все таблицы, версии схемы, транзакционные границы, backup/restore и
  legacy-преобразования.
- [x] Зафиксировать ограничения CGO-free сборки и сохранения gRPC/HTTP границ.
- [x] Описать порядок переноса и критерии готовности.

### Этап 1 — подключение GORM и модели — готово

- [x] Добавить GORM SQLite dialector и подключить его к уже созданному
  `modernc` pool; не менять DSN и PRAGMA на каждой connection.
- [x] Описать private persistence-модели с явными `TableName` и schema tags.
- [x] Сохранить единый connection lifecycle в `Store`; GORM использует тот же
  `*sql.DB`, а не открывает второй SQLite pool.

### Этап 2 — миграционный runner через GORM

- [x] Заменить giant `CREATE TABLE IF NOT EXISTS` migration на `AutoMigrate`
  моделей и упорядоченные идемпотентные шаги.
- [x] Запускать legacy clients table rebuild и преобразование данных через
  GORM context/transaction, создавая прежний pre-migration snapshot до DDL.
- [x] Сохранить legacy marker 1–6 и добавить marker 7 для adoption GORM schema.
- [ ] Обеспечить безопасный повторный запуск после остановки процесса на каждом
  migration step и проверить его на существующих fixtures.
- [ ] Проверить, что GORM не меняет типы/значения старых TEXT timestamps,
  nullable credential columns, индексы и foreign keys.

### Этап 3 — перевод persistence API на GORM

- [x] Перевести admin/session/TOTP/settings/client методы на GORM models,
  `Select`/`Updates`/`Clauses(OnConflict)` и scoped context.
- [x] Перевести short-ID pool, traffic snapshots, apply operations и audit;
  сохранить атомарные операции выделения ID, revision и protocol states.
- [x] Оставить parameterized SQL только в выделенных SQLite-specific helpers и там,
  где он нужен для атомарной условной записи или обратной совместимости.
- [x] Удалить прямое использование `database/sql` из обычных CRUD-методов.
  Остаются pool lifecycle и GORM-backed helpers для SQLite backup/restore и
  атомарных операций, которым нужен pinned connection.

### Этап 4 — проверка совместимости и rollout

- [ ] Проверить новые и старые схемы до/после каждого migration step, включая
  отсутствие потерь клиентов и snapshots при ошибке/повторном запуске.
- [ ] Проверить backup/restore, FK, WAL, parallel writes, CGO-free build и
  gRPC-only связь между backend-сервисами.
- [ ] Выполнить полный набор тестов и проверить заявленный порог покрытия.
- [ ] Документировать порядок rollback и выпускать изменение только после
  подтверждения upgrade-пути на копии production базы.

## Критерии готовности

- Обычные методы `internal/store` работают через GORM; прямой `database/sql`
  остаётся только в тестовых швах или SQLite-specific migration/backup helper.
- Новая база создаётся через GORM Migrator; существующая база проходит
  миграции без потери данных и без снижения revision high-water mark.
- Перезапуск миграции безопасен; ошибка конвертации оставляет исходную схему
  и pre-migration snapshot доступными.
- Проект продолжает собираться с `CGO_ENABLED=0` и использовать modernc SQLite.
- Общение backend-сервисов не меняется: только gRPC между сервисами; HTTP
  остаётся интерфейсом control-plane для веб-панели.
- Полный backend/web набор тестов проходит, а покрытие соответствует порогу
  проекта не ниже 90%.

## Риски и решения

| Риск | Контроль |
| --- | --- |
| `AutoMigrate` добавит `protocol` раньше legacy rebuild | До миграции clients проверять старую схему и выполнить snapshot/rebuild первым |
| Типы времени изменятся при маппинге `time.Time` | На первом этапе хранить значения как TEXT и сохранять RFC3339Nano |
| ORM обновит нулевые значения иначе, чем ручной SQL | Для чувствительных обновлений задавать полный `Select`/`Updates(map)` и тестировать zero values |
| GORM default transactions изменят блокировки/latency | Удерживать явные транзакционные границы; измерить горячие операции до оптимизации |
| Ошибки SQLite будут обёрнуты GORM | Нормализовать `gorm.ErrRecordNotFound` и constraint errors на границе репозитория |
| Переход схемы не пройдёт на CGO-free образе | Перед merge запускать Linux amd64/arm64 сборку с `CGO_ENABLED=0` |

## Прогресс

- Этап 0 завершён.
- Этапы 1–3 реализованы; миграции таблиц выполняются через GORM Migrator,
  а протокольный rebuild, backup/restore и условные state transitions
  выполняются через GORM `Raw`/`Exec` на том же SQLite pool.
- Этап 4 и проверки schema compatibility ещё не выполнены. В текущей оболочке
  отсутствуют `go` и `gofmt`, поэтому тесты, coverage и CGO-free builds пока
  невозможно запускать; до принятия изменений эти проверки обязательны.
