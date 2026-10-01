# План ускорения тестового CI

## Цель

Сократить время обратной связи в GitHub Actions и локального запуска тестов без
ослабления текущих порогов покрытия и без удаления race detector.

## Границы

В план входят:

1. удаление повторного запуска web-тестов;
2. удаление повторного запуска Go-тестов;
3. оптимизация установки npm-зависимостей;
4. настройка файлового кэша и числа workers Vitest;
5. перевод тестов, не использующих DOM, в окружение `node`.

Из плана исключены:

- изменение политики запуска race detector — `race` остаётся совмещённым с
  coverage через `-covermode=atomic`;
- изменение публикации coverage-артефактов.

## Этапы

### 0. Базовые измерения

- Зафиксировать длительность web-job и Go-jobs в GitHub Actions.
- Измерить `npm ci`, web coverage и локальный `vitest doctor`.
- Проверить текущие проценты покрытия.

### 1. Web: один запуск suite

- Удалить отдельный `npm test` из workflow.
- Оставить `npm run test:coverage`, который одновременно выполняет тесты и
  проверяет coverage thresholds.
- Проверить lint, typecheck, coverage и build.

### 2. Go: один запуск suite на модуль

- Удалить отдельные обычные `go test` из jobs backend, AWG и Xray runtime.
- Оставить coverage-скрипты с race detector и `-covermode=atomic`.
- Убедиться, что package/file coverage gates не изменились.

### 3. Web dependencies

- Заменить установку на `npm ci --prefer-offline --no-audit --no-fund`.
- Сохранить `npm ci` и lockfile как источник точных версий.
- Проверить чистую установку на runner.

### 4. Vitest cache и workers

- Включить `fsModuleCache`.
- Сравнить `maxWorkers=4` и `maxWorkers=8` в одинаковом CI-окружении.
- Зафиксировать только вариант с подтверждённым выигрышем.
- Не отключать изоляцию тестов.

### 5. Чистые тесты в Node

- Оставить `jsdom` для компонентов Vue и app harness.
- Перевести тесты domain/application/infrastructure без DOM на `node` через
  per-file environment directive.
- После каждого переноса прогонять файл отдельно и полный suite.

## Проверки результата

```bash
cd web
npm run lint
npm run typecheck
npm run test:coverage
npm run build

cd ..
bash scripts/backend-coverage.sh
bash scripts/awg-coverage.sh
bash scripts/xray-runtime-coverage.sh
```

Критерии успеха:

- тесты каждого suite выполняются один раз;
- race detector и coverage thresholds сохраняются;
- coverage не снижается;
- web build и Go jobs проходят;
- нет зависимости тестов от общего состояния между файлами;
- итоговое время CI уменьшается относительно базового измерения.

## Порядок коммитов

1. `docs: document test acceleration plan`
2. `ci: remove duplicate web test run`
3. `ci: remove duplicate Go test runs`
4. `ci: optimize npm dependency installation`
5. `test(web): enable Vitest module cache`
6. `test(web): tune Vitest worker count`
7. `test(web): run pure tests in node environment`

## Статус выполнения

Все этапы плана реализованы локально и зафиксированы отдельными коммитами.
`maxWorkers: 4` выбран по результату `vitest doctor` на текущем окружении;
после первого CI-прогона его следует сравнить с `maxWorkers: 8` на том же
runner. Race detector и публикация coverage-артефактов намеренно не менялись.
