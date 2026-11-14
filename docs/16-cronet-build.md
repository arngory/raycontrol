# Своя сборка libcronet и naive: раннер, пределы, диск, кэш

Статус: разбор на 2026-11-14. **Ничего не собиралось.** Пометка «замер» — цифра из чужого CI-прогона или из файла,
прочитанного в этот день; «оценка» — пересчёт с замеров. Перед внедрением оценки нужно проверить одной сборкой.

## 1. Коротко

- **Это не сборка всего Chromium.** naive и libcronet собираются из урезанного дерева сетевого стека: 34 799 файлов,
  245,5 МиБ (замер; README апстрима называет это 0,3 % исходников Chromium). Полный Chromium просит от 100 ГБ диска,
  здесь хватает 14 ГБ.
- **Кэш компилятора на 60 ГБ не нужен.** Апстрим держит ccache в 200 МБ на цель, и тёплые сборки на этом работают
  (замер). Всем нашим целям на много ревизий хватит 5–20 ГБ (оценка). Кэш на 60 ГБ поставить можно, но он не
  заполнится: каждая новая версия Chromium сбрасывает его целиком (§7).
- **Достаточная машина:** 8 потоков, 16 ГБ ОЗУ, 60 ГБ диска. С кэшем на 60 ГБ — 110 ГБ диска.
- **Раннер GitHub тоже справляется:** бесплатный раннер публичного репозитория (4 vCPU, 16 ГБ, 14 ГБ диска) собирает
  одну архитектуру Android за 45 минут с нуля (замер).
- **Предлагаемая схема (§5):** выпуски собирать на раннерах GitHub из публичных форков — чистая машина на каждую
  сборку; свой раннер держать для быстрого цикла при переносе патчей, под приватным репозиторием.

## 2. Что собирается и из чего

Цепочка от Chromium до приложения, состояние на 2026-11-14 (всё замер):

| Слой | Что это | Версия |
|---|---|---|
| Chrome stable (Android) | с чем сравнивают отпечаток | 157.0.8103.x; 158.0.8127.36 раскатывается с 12 ноября |
| `klzgrad/naiveproxy` | 92 коммита поверх импорта Chromium | 154.0.8037.49-5 от 22 октября; 151–153 пропущены |
| `SagerNet/naiveproxy` | стек klzgrad + 9 своих коммитов (C API Cronet для Go) | ветка `cronet-go-dev-v154`, коммит `7c64cae` от 3 ноября |
| `SagerNet/cronet-go` | обвязка Go и готовые `libcronet.a` модулями `lib/<os>_<arch>` | `main` на 154; библиотеки пересобраны 3 ноября (ветка `go`, `095cb9e`); последний тег — 150 |
| `arngory/sing-box` (ядро Niko) | `protocol/naive` | модули cronet-go от 12 сентября, Chromium 150.0.7871.63 |

Чего нет в стеке SagerNet на 154: октябрьских коммитов klzgrad — правки проверки сертификатов QUIC, правки падения
после разрыва, масштабирования окна QUIC и BBR, блокировки промежуточных УЦ eMudhra (`23953c9`). Последний коммит
klzgrad в ветке SagerNet — от 12 сентября.

Собираются два разных продукта:

| Продукт | Кому нужен | Команда | Флаги |
|---|---|---|---|
| `libcronet.a` на архитектуру | ядру Niko (cgo) | `go run ./cmd/build-naive --target=android/arm64 build` в cronet-go: `get-clang.sh`, `gn gen`, `ninja cronet_static` | `use_thin_lto=false`, `optimize_for_size=true`, `symbol_level=0`, без PGO |
| бинарь `naive` | эталонный клиент в interop | `./get-clang.sh && ./build.sh` в `src/` naiveproxy | `is_official_build=true`, ThinLTO, PGO (`chrome_pgo_phase=2`), `symbol_level=0` |

Что скачивает сборка (замер по размерам загрузок): clang от Chromium — 56,9 МБ и 6,2 МБ рантайма Android; GN;
профиль PGO — 58–91 МБ на платформу (только для `naive`); Android NDK r24 — 668 МБ; sysroot Debian собирается
скриптом `sysroot_creator.py`; образ Android на 385 МБ нужен только тестам.

Размер результата (замер): `libcronet.a` — 71,0 МБ для arm64, 85,8 МБ для arm, 67,1 МБ для x86_64.

## 3. Замеры времени

Раннеры GitHub, 4 vCPU и 16 ГБ, `ninja -j6`. Время всей задачи, вместе со скачиванием и тестами.

| Цель | С нуля | С тёплым кэшем |
|---|---|---|
| libcronet, android arm64 | 44 мин 45 с | 1,5–4 мин (кэш всего каталога `out/`) |
| libcronet, android arm | 45 мин 27 с | то же |
| libcronet, android x86_64 | 46 мин 01 с | то же |
| libcronet, linux amd64 | 33 мин 59 с | то же |
| naive, linux x64 | 37 мин 02 с (после правки исходников) | 17 мин 48 с |
| naive, android arm64 | 35 мин 39 с | 10 мин 09 с |
| naive, android arm | 19 мин 13 с | 5 мин 39 с |

Источники: прогоны `SagerNet/cronet-go` 41564048437 и 36040530227, `klzgrad/naiveproxy` 39805557879 и 39821354290.

У `naive` тёплая сборка упирается в линковку: ThinLTO заново отрабатывает каждый раз, потому что `build.sh` стирает
`out/`, а ccache линковку не кэширует. У libcronet LTO выключен, поэтому тёплая сборка короткая.

## 4. Сколько нужно ресурсов

- **ОЗУ.** Не меньше 2 ГБ на задачу ninja (оценка; на раннере GitHub выходит 2,7 ГБ на задачу, и этого хватает — замер).
  16 ГБ — `-j8`, 32 ГБ — `-j16`. Ниже 1,5–2 ГБ на задачу ядро начнёт убивать clang на тяжёлых файлах и на линковке
  ThinLTO (оценка). Пик памяти линковки не измерен.
- **Линковка.** С ThinLTO GN сам ставит одну линковку за раз, задать число явно нельзя (выведено из
  `get_concurrent_links.py`, не запускалось).
- **Диск:**

| Что | ГБ |
|---|---|
| Debian, раннер, Go, инструменты | 8 (оценка) |
| два дерева исходников | 1 (замер: 0,25 ГБ каждое) |
| clang, NDK, профили PGO, sysroot, образ Android | 4 (оценка по замеру загрузок) |
| `out/` для libcronet: arm64, arm, x86_64 | 3 (оценка) |
| `out/` для naive: linux x64 и arm64 | 4 (оценка) |
| временные файлы и артефакты | 2 |
| ccache | 20 |
| запас около четверти | 10–20 |
| **Итого** | **около 60** |

С ccache на 60 ГБ итог — около 110 ГБ.

- **Варианты машины** (кроме первой строки — оценка, пересчёт с замеров):

| Вариант | Пределы | libcronet с нуля, одна архитектура | naive с нуля | Тёплая чистая сборка |
|---|---|---|---|---|
| раннер GitHub (замер) | 4 vCPU, 16 ГБ, `-j6` | 45 мин (Android), 25–34 мин (Linux) | 19–37 мин | naive 6–18 мин |
| малый | 8 потоков, 16 ГБ, `-j8` | 20–25 мин | 15–20 мин | libcronet 2–4 мин, naive 4–8 мин |
| средний | 16 потоков, 32 ГБ, `-j16` | 10–14 мин | 8–12 мин | libcronet 1–3 мин, naive 3–5 мин |
| минимум | 4 потока, 8 ГБ, `-j4` | 45–60 мин | 30–40 мин | как у раннера GitHub |

## 5. Где собирать

| Вариант | Цена | Плюсы | Минусы |
|---|---|---|---|
| Раннер GitHub, публичный форк | бесплатно | чистая машина на каждую сборку; аттестации сборки доступны | 45 мин на архитектуру с нуля; кэш `actions/cache` 10 ГБ на репозиторий, неиспользуемое стирается через 7 дней |
| Раннер GitHub, приватный форк | 0,006 $/мин, 2 vCPU и 8 ГБ | исходники закрыты | 80–100 мин на архитектуру (оценка; хватит ли 8 ГБ — не проверено) |
| «Большой» раннер GitHub | от 0,012 $/мин | до 64 ядер | только для организаций на Team или Enterprise |
| Свой раннер | своя машина; минуты бесплатны | постоянный кэш и `out/`, цикл правки 2–4 мин | постоянное состояние — это риск (§6.2) |

**Предложение:**
1. Публичные форки `arngory/naiveproxy` и `arngory/cronet-go` держат исходники и workflow выпуска на раннерах
   GitHub. Выпуск — чистая сборка с нуля, контрольные суммы и аттестация. Три архитектуры Android идут параллельно,
   это 45 минут.
2. Свой раннер подключён к **приватному** репозиторию-сборщику и нужен для цикла «поправил конфликт — пересобрал»
   при переносе патчей на новый Chromium. В выпуск его результат не идёт.

Так постоянный кэш своего раннера не попадает в цепочку доверия выпуска.

## 6. Свой раннер

### 6.1. Пределы по потокам и памяти

- **Потоки ограничивать набором ядер, а не квотой.** ninja 1.12.1 берёт число задач из `sched_getaffinity`, GN читает
  `cpuset.cpus`. Квоту (`CPUQuota=`, `docker --cpus`) на cgroup v2 не видит ни тот, ни другой, и сборка запустит
  задач по числу всех ядер машины. Нужно `AllowedCPUs=` или `--cpuset-cpus`.
- **Пределы ставить на сам юнит раннера.** GN читает `memory.max` своей cgroup; предел на родительском слайсе он не
  увидит.
- **Число задач.** Скрипты апстрима зовут `ninja` без `-j`, при восьми ядрах выйдет 10 задач. Обёртка в `PATH`
  задаёт `-j` и `-l` явно.
- **Docker вместо systemd:** `--cpuset-cpus=0-7 --memory=16g --memory-swap=18g --pids-limit=8192`.

### 6.2. Безопасность

- **Свой раннер нельзя подключать к публичному репозиторию.** Документация GitHub: self-hosted runners «should almost
  never be used for public repositories» — чужой pull request может запустить на нём свой код и закрепиться.
- **Запуск только вручную и по тегу** (`workflow_dispatch`, `push: tags`), у пользователя раннера нет sudo.
- **Одноразовая регистрация** (`--ephemeral`): раннер берёт одну задачу и выходит, systemd регистрирует его заново.
- **Постоянный кэш — граница доверия.** Кто смог записать в ccache, тот подменит объектные файлы следующей сборки.
  Поэтому выпуски собираются не здесь (§5).
- **Подпись и аттестация** — отдельной задачей на раннере GitHub, чтобы ключи не касались сборочной машины.

### 6.3. Установка (Debian 13, от root)

Проверен только синтаксис (`systemd-analyze verify`, `sh -n`); на настоящей машине не запускалось, строки
ужесточения юнита против живой задачи не проверены.

```bash
apt-get update && apt-get install -y --no-install-recommends \
  git curl ca-certificates jq xz-utils unzip zip python3 python3-requests \
  ninja-build ccache pkg-config binutils gnupg gpgv bubblewrap
useradd --system --create-home --home-dir /srv/gha --shell /usr/sbin/nologin ghrunner
install -d -o ghrunner -g ghrunner /srv/gha/runner /srv/gha/_work /srv/gha/bin /srv/ccache
```

`/srv/ccache` — отдельный том (ext4, `noatime`). Версию раннера и её SHA-256 брать со страницы репозитория
Settings → Actions → Runners → New self-hosted runner, архив сверять `sha256sum -c` до распаковки.

```bash
cd /srv/gha/runner
runuser -u ghrunner -- ./config.sh --unattended --url https://github.com/OWNER/REPO \
  --token "$REG_TOKEN" --name naive-builder-1 --labels naive-build --work /srv/gha/_work
```

Обёртка `/srv/gha/bin/ninja` (права 755):

```sh
#!/bin/sh
exec /usr/bin/ninja -j "${NINJA_JOBS:-8}" -l "${NINJA_LOAD:-12}" "$@"
```

`/etc/systemd/system/gha-runner.service`:

```ini
[Unit]
Description=GitHub Actions runner (naive / cronet builds)
After=network-online.target
Wants=network-online.target

[Service]
User=ghrunner
Group=ghrunner
WorkingDirectory=/srv/gha/runner
ExecStart=/srv/gha/runner/run.sh
Restart=always
RestartSec=10
KillMode=control-group
TimeoutStopSec=5min
# Потоки: набор ядер, не квота
AllowedCPUs=0-7
CPUWeight=50
Nice=5
# Память: на самом юните
MemoryHigh=14G
MemoryMax=16G
MemorySwapMax=2G
OOMPolicy=continue
TasksMax=8192
IOWeight=50
LimitNOFILE=65536
# Задачам доступны на запись только рабочий каталог и кэш
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/srv/gha /srv/ccache

[Install]
WantedBy=multi-user.target
```

Для среднего варианта: `AllowedCPUs=0-15`, `MemoryHigh=28G`, `MemoryMax=32G`, `NINJA_JOBS=16`.

`/srv/ccache/ccache.conf`:

```ini
max_size = 20GiB
max_files = 0
compression = true
compression_level = 1
base_dir = /srv/gha/_work
hash_dir = false
compiler_check = content
sloppiness = time_macros,include_file_mtime,include_file_ctime
```

Кэш на 60 ГБ — это одна строка, `max_size = 60GiB`, и том на 60 ГБ больше.

### 6.4. Набросок workflow для libcronet

Живёт в форке cronet-go, подмодуль которого смотрит на наш форк naiveproxy. Не запускался. Действия при внедрении
закрепить по SHA, как в остальных наших репозиториях.

```yaml
name: build-cronet
on:
  workflow_dispatch:
    inputs:
      clean: { description: "Стереть out/ перед сборкой", type: boolean, default: false }
permissions:
  contents: read
concurrency:
  group: naive-builder
  cancel-in-progress: false
env:
  CCACHE_DIR: /srv/ccache
  NINJA_JOBS: '8'
jobs:
  cronet:
    runs-on: [self-hosted, linux, x64, naive-build]
    timeout-minutes: 180
    strategy:
      fail-fast: false
      max-parallel: 1
      matrix:
        include:
          - { target: android/arm64, dir: android_arm64 }
          - { target: android/arm,   dir: android_arm }
          - { target: android/amd64, dir: android_amd64 }
    steps:
      - uses: actions/checkout@<SHA>
        with: { submodules: recursive, clean: false, persist-credentials: false }
      - uses: actions/setup-go@<SHA>
        with: { go-version-file: go.mod }
      - run: echo /srv/gha/bin >> "$GITHUB_PATH"
      - if: inputs.clean
        run: rm -rf naiveproxy/src/out/cronet-*
      - run: ccache -z
      - run: go run ./cmd/build-naive --target=${{ matrix.target }} build
      - run: ccache -s
      - run: go run ./cmd/build-naive --target=${{ matrix.target }} package
      - run: cd lib/${{ matrix.dir }} && sha256sum libcronet.a | tee SHA256SUMS
      - uses: actions/upload-artifact@<SHA>
        with:
          name: cronet-${{ matrix.dir }}
          if-no-files-found: error
          path: |
            lib/${{ matrix.dir }}/
            include/
```

Workflow выпуска на раннерах GitHub отличается тремя вещами: `runs-on: ubuntu-24.04`, запуск по тегу, сборка всегда
с нуля. После сборки — отдельная задача с `actions/attest` и правами `id-token: write`, `attestations: write`.

Бинарь `naive` для interop собирается из форка naiveproxy шагами задачи `linux` апстрима: `working-directory: src`,
`EXTRA_FLAGS='target_cpu="x64"'`, `./get-clang.sh`, `./build.sh`, `sha256sum out/Release/naive`.

## 7. Что сбрасывает кэш и как пересобирать быстро

- **Новая версия Chromium — полный промах:** меняется ревизия clang и почти все заголовки. Кэш от прошлой версии
  бесполезен, поэтому большой кэш не даёт выигрыша.
- **Тоже сбрасывают:** смена флагов сборки, правка широко включаемого заголовка, новый профиль PGO у `naive` (по
  памяти, не проверено).
- **Самый быстрый цикл при переносе патчей — не стирать `out/`** (`clean: false` у checkout). Инструмент cronet-go его
  не трогает, и ninja пересобирает только затронутые файлы. ccache нужен для чистых сборок.
- **ccache или sccache.** Оба кэшируют компиляцию с `-flto=thin`, линковку — ни один. Для постоянного локального
  диска подходит ccache; sccache нужен только с хранилищем вроде S3.

## 8. Как проверять результат

- **Закреп в ядре.** Модули `cronet-go/lib/<os>_<arch>` попадают в `go.sum` ядра: подмена библиотеки после выпуска
  ломает сборку приложения.
- **Контрольные суммы и аттестация** на каждый `libcronet.a`; проверка — `gh attestation verify`. Для публичных
  репозиториев аттестации доступны на любом тарифе, для приватных нужен Enterprise Cloud.
- **Побитного совпадения с апстримом ждать нельзя:** комментарий в самом Chromium говорит, что кэш ThinLTO «can lead
  to non-determinism». У libcronet LTO выключен, воспроизводимость там не проверялась.
- **Тесты перед заменой модулей в ядре:** interop клиента с `rayd naive` и с эталонным `naive`; сравнение ClientHello,
  настроек HTTP/2 и параметров QUIC с настоящим Chrome той же версии. Второго теста пока нет.

## 9. Чего не удалось проверить

- Журналы задач чужих CI недоступны: нет долей попаданий ccache, времени по шагам и пика памяти.
- Ни одной сборки не запускалось: размеры `out/`, распакованных инструментов и все времена для 8 и 16 потоков —
  оценки.
- По памяти, без проверки: учитывает ли ccache профиль PGO, смотрит ли lld на маску ядер, адрес API для токена
  регистрации раннера.
- Версия ninja в Debian 13 не сверена; поведение с cgroup проверено по исходникам 1.12.1.

## 10. Источники

- `klzgrad/naiveproxy`: `README.md`, `.github/workflows/build.yml`, `src/build.sh`, `src/get-clang.sh`,
  `src/build/config/compiler/compiler.gni`, `src/build/toolchain/get_concurrent_links.py`.
- `SagerNet/cronet-go`: `README.md`, `.gitmodules`, `cmd/build-naive/cmd_build.go`, `cmd_package.go`,
  `.github/workflows/naive-build.yml`; ветки `main` и `go`.
- Документация GitHub: github-hosted runners, larger runners, actions runner pricing, limits, dependency caching,
  secure use, self-hosted runners, artifact attestations.
- Руководство ccache; исходники ninja 1.12.1 (`src/util.cc`); `systemd.resource-control`.
- Chromium: `docs/linux/build_instructions.md`; Chromium Dash и VersionHistory API — версии каналов.
