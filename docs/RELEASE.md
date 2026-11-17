# Релизы raycontrol

Правило P-17: после каждого законченного блока — релиз, release notes по одной строке на правку (сначала английские
строки, потом те же на русском), всё собирается из наших исходников.

## Один раз: ключ подписи

Релиз подписывается [minisign](https://jedisct1.github.io/minisign/): подпись покрывает `SHA256SUMS`, а он — архивы.

1. На своей машине (не на сервере и не в CI):
   ```
   minisign -G -W -p raycontrol.pub -s raycontrol.key
   ```
   `-W` — ключ без пароля: он хранится только в секретах GitHub и в вашем офлайн-хранилище.
2. Содержимое `raycontrol.key` целиком — в секрет `MINISIGN_SECRET_KEY` **окружения** `release` (ниже, «Окружения
   выпуска»), не в секреты репозитория. Обе строки: `untrusted comment: …` и строку ключа. Шаг Sign примет и одну
   строку ключа, но перед подписью сверяет публичную часть ключа (`minisign -R`) с закреплённой в
   `internal/release` и `bootstrap.sh` и останавливается, ничего не подписав, если ключ другой или это не ключ
   minisign без пароля; после подписи проверяет её закреплённым ключом.
3. Вторая строка `raycontrol.pub` (начинается с `RW`) — в `PUBKEY` файла `install/bootstrap.sh`, отдельным коммитом.
   До этого bootstrap отказывается работать.
4. `raycontrol.key` — в офлайн-хранилище. Потеря ключа = новый ключ и новый `bootstrap.sh`.

Текущий ключ: ID `A9C7802E23B87A01`, публичная часть
`RWQBergjLoDHqeme5vyIuIRXJLjTj1EF3jR1nlWBVJO3rWxgy9SZj4bD` (уже в `install/bootstrap.sh`). Строка
`untrusted comment` из `.pub` — только подпись к файлу: в `bootstrap.sh` и в `minisign -P` она не нужна.

## Один раз: токен IPinfo

Релиз несёт базу AS для сводки от клиентов — IPinfo Lite (R4-21, CC BY-SA 4.0). Release-workflow скачивает её
токеном из секрета `IPINFO_TOKEN` окружения `release-data`: бесплатный аккаунт на ipinfo.io → токен → секрет
окружения (ниже). Без секрета релиз не собирается. База кладётся в архив без изменений, атрибуция — в `NOTICE`.

## Один раз: окружения выпуска

Секреты релиза — в окружениях GitHub, а не в секретах репозитория: секрет репозитория читает workflow любой ветки,
и ветка `claude/**` с ошибочной или подсунутой правкой workflow унесла бы ключ подписи. Settings → Environments:

- **`release`** — секрет `MINISIGN_SECRET_KEY`. Required reviewers: владелец («Prevent self-reviews» выключен, пока
  других ревьюеров нет). Deployment branches and tags → Selected: тег `v*` и ветка `main` (ручной запуск).
  Каждый релиз ждёт кнопки Approve в Actions (Review deployments) перед подписью.
- **`release-data`** — секрет `IPINFO_TOKEN`. Без ревьюеров (иначе два одобрения на релиз), те же тег `v*` и
  ветка `main`.

Ещё — набор правил на теги (Settings → Rules → Rulesets → New tag ruleset, `v*`): создание, изменение и удаление
запрещены, в обходе только владелец. Окружение пускает любой тег `v*`, а workflow берётся из коммита тега; задача
`release` дополнительно проверяет, что коммит есть в `main`, но защищает правило, проверка ловит ошибку.
Checkout во всех workflow — без сохранённого токена (`persist-credentials: false`); право записи — только у задачи
`release`, где сборочного кода нет.

Задачи `release` и `asn` в `release.yml` ссылаются на эти окружения. После первого релиза через окружения
одноимённые секреты репозитория удаляются.

## Выпуск

1. Файл `.github/release-notes/<тег>.md` (например `v0.2.0.md`) — уже в ветке, из которой выпускается релиз.
2. Тег ставит владелец: набор правил на `v*` (выше) никому больше создавать теги не даёт, ни workflow, ни сессиям
   Claude. Тег — на коммит `main`. Проще всего в вебе: **Releases → Draft a new release → Choose a tag → ввести
   `vX.Y.Z` → Create new tag on publish → Target: `main` → Publish release**. Название и текст можно не заполнять:
   их workflow возьмёт из `.github/release-notes/vX.Y.Z.md`. Галочка **Set as a pre-release** желательна, но не
   обязательна (ниже). Или из консоли, если удобнее:
   ```
   git tag vX.Y.Z <коммит> && git push origin vX.Y.Z
   gh api repos/arngory/raycontrol/git/refs -f ref=refs/tags/vX.Y.Z -f sha=<коммит>
   ```
   Тег сам запускает Release. Страница Releases вместе с тегом публикует пустой выпуск. Первая задача workflow,
   `tag`, удаляет его через несколько секунд (тег остаётся), и дальше workflow публикует настоящий выпуск с
   архивами. На эти секунды пустой выпуск — «latest» (так было с v0.31.0, пока его не удалили руками: `bootstrap.sh`
   не находил архивов); с галочкой pre-release он «latest» не становится вовсе. Выпуск, в котором уже есть файлы,
   `tag` не трогает и останавливается. Руками (Actions → Release → Run workflow, ветка `main`, тег `vX.Y.Z`) —
   только повтор для тега, который уже стоит на этом коммите, например после неудачной публикации; так же работает
   «Re-run failed jobs» в самом запуске. `tag` до CI и до одобрений проверяет, что тег есть и стоит на этом
   коммите; иначе останавливается и говорит, что делать.
3. Workflow прогоняет весь CI (`ci.yml`) на этом коммите и собирает `raycontrol-linux-{amd64,arm64}.tar.gz` (`rayd`,
   `rayspa`, `rayctl`, `xray`, `niko-server`, `slipstream-server`, `ipinfo_lite.mmdb`, `NOTICE`, `VERSIONS`) и, с
   v0.26.0, три архива с одним `rayctl` для машины администратора (ниже), считает
   `SHA256SUMS`, подписывает его (trusted comment `raycontrol vX.Y.Z` — по нему `rayctl update` узнаёт версию) и
   публикует релиз с этими файлами и `SHA256SUMS.minisig`. Пока CI не зелёный, ничего не публикуется: v0.16.0 вышел
   по зелёному прогону пулл-реквеста, а CI на `main`, шедший рядом с релизом, был красным.
4. **«Latest» — только самый старший.** GitHub помечает каждый новый релиз последним (`make_latest` по умолчанию
   `true`), так что бэкпорт v0.25.5, выпущенный после v0.26.1, стал бы `latest`: `bootstrap.sh` поставил бы его, а
   проверки нод — сравнивали бы со старым. Шаг Publish берёт список опубликованных релизов (`gh api --paginate`,
   без черновиков и pre-release, только теги `vX.Y.Z`), и `gh release create` получает `--latest`, только если
   новый тег среди них самый старший по semver, иначе `--latest=false`; если список не получен, релиз не
   публикуется. Релизы до этой правки, помеченные так руками или по умолчанию, ноды всё равно не ослепляют: поиск
   патчей своей минорной идёт и при `latest` старше работающей версии ([spec/node-update-v1.md](spec/node-update-v1.md)
   §1).

`install/bootstrap.sh` берёт последний релиз (или `RAYCONTROL_VERSION`), а сам скрипт по README скачивается из `main`:
пока код не слит в `main`, скачивайте `bootstrap.sh` из рабочей ветки.

**`MIN_VERSION` в `bootstrap.sh`** — самый старый релиз, который скрипт ставит. Версию он читает из trusted comment
подписи, как и `rayctl update`: запрошенная `RAYCONTROL_VERSION` должна совпасть, а релиз старше `MIN_VERSION` не
ставится, даже если зеркало отдаст его как последний. Поверх базы ноды релиз старше того, что на ней стоит
(`rayd version`), скрипт не ставит и отсылает к `rayctl update -version` (или `RAYCONTROL_VERSION=<установленная>`);
если `rayd` релиза не называет (нет его, не запускается, сборка без номера), — релиз до `OVERLAP_VERSION` (v0.31.0).
Возврат — дело `rayctl` (копия базы, а на версию до v0.31.0 — новые данные смен в пути, R4-43); в `bootstrap.sh`
старых релизов проверки нет. С `-check` скрипт в этих случаях выходит с 1. Проверка — `test/install/bootstrap-guard.sh`
(его запускает `test/install/minisig.sh`). Поднимать `MIN_VERSION`:
- когда скрипт начинает вызывать команду `rayctl`, которой нет в старых релизах;
- когда релиз закрывает дыру, чтобы зеркало не могло подсунуть уязвимый.

Поднимать — после того как релиз опубликован: иначе между слиянием в `main` и релизом `bootstrap.sh` из `main` будет
отказывать.

## Отозвать релиз

Подписанный `vX.Y.Z` отозвать нельзя: подпись minisign над его `SHA256SUMS` верна навсегда, списка отзыва у
`rayctl` и `bootstrap.sh` нет. Снять его можно только с раздачи:

1. **Удалить файлы релиза** (ассеты: архивы, `SHA256SUMS`, `SHA256SUMS.minisig`) на странице релиза или
   `gh release delete-asset vX.Y.Z <файл>`. Тогда GitHub отвечает на них 404: поиск патчей нод (auto, `-update-check`,
   `rayctl update -check`) считает номер пропущенным и переступает через один — исправление выпускается следующим
   номером, `vX.Y.(Z+1)`. 404 от GitHub окончателен, зеркала при этом не спрашиваются.
2. **Если это был `latest`** — пометить последним предыдущий: `gh release edit vX.Y.(Z-1) --latest` (или сразу
   выпустить исправление: Release-workflow пометит его сам). Иначе `releases/latest/download/…` отвечает 404, и
   `rayctl update`, `bootstrap.sh` и проверки нод не знают последнего релиза.
3. **Зеркала** (ghfast.top, gh-proxy.com, свои из `RAYCONTROL_MIRRORS`) могут ещё какое-то время отдавать
   закешированные файлы. Спрашивают их, только когда GitHub не ответил, так что за сетью, где GitHub недоступен,
   `rayctl update -version vX.Y.Z` (и `RAYCONTROL_VERSION=vX.Y.Z bash bootstrap.sh`) может поставить снятый релиз.
   Против этого — только новый релиз и, если снятый опасен, `MIN_VERSION` в `bootstrap.sh` (выше); `rayctl update`
   без `-version` более старый, чем стоит, не ставит.
4. **Пометка pre-release не прячет релиз.** Поиск патчей спрашивает файлы по тегу
   (`releases/download/vX.Y.Z/SHA256SUMS`), а GitHub отдаёт файлы pre-release так же; меняется только `latest`.
   Снять — только удалением файлов.

## Проверка вручную

```
minisign -Vm SHA256SUMS -P <публичный ключ>
sha256sum -c SHA256SUMS --ignore-missing
```

## `rayctl` для macOS и FreeBSD

С v0.26.0 релиз несёт ещё три архива: `rayctl-darwin-arm64.tar.gz`,
`rayctl-darwin-amd64.tar.gz` и `rayctl-freebsd-amd64.tar.gz`. В каждом — `rayctl` и `VERSIONS` (тег и коммит): это
`rayctl` для машины администратора — удалённое управление (`-remote`), `knock`, `probe`. Нода остаётся на Linux;
команды, которые действуют на самом сервере, там отказывают одной строкой (таблица — `cmd/rayctl/where.go`).

- **Сборка.** Job `rayctl` Release-workflow: кросс-компиляция с Linux, без cgo, тем же toolchain из `go.mod`. Тот же
  набор на каждом коммите собирает job `rayctl` в CI: там же `go vet` и компиляция тестов `rayctl` и пакетов, которые
  он импортирует, под darwin (под freebsd — только тесты самого `rayctl`). Собранное под macOS и FreeBSD в этих job
  не запускается.
- **Запуск на macOS.** Отдельный workflow `rayctl on macOS` (`.github/workflows/macos.yml`, job `rayctl (macOS,
  run)`) собирает и запускает `rayctl` на runner с macOS и гоняет тесты отказов, прав файла устройства и терминала, не
  дольше 15 минут: при изменениях кода `rayctl` и `internal/`, раз в неделю и вручную. В CI его нет с v0.31.0: runner
  с macOS часто не появляется, и job, снятый в ожидании, красил весь прогон CI, хотя ничего не падало. Release-workflow
  его не ждёт. Сборку и компиляцию тестов под darwin CI делает с Linux на каждом коммите (job `rayctl`). На FreeBSD
  `rayctl` не запускается нигде.
- **Подпись.** Те же `SHA256SUMS` и подпись minisign, что у архивов ноды: проверяется теми же двумя командами
  (на macOS — `shasum -a 256 --ignore-missing -c SHA256SUMS`). Бинарник для macOS не подписан сертификатом Apple и
  не нотаризован; что с этим делать пользователю — в [руководстве](10-quickstart-debian13.md), §7.
- **Ноды лишних строк не замечают.** `rayctl update` берёт из `SHA256SUMS` строку с полным именем своего архива,
  `bootstrap.sh` ищет её `grep`-ом; оба куска кода одинаковы во всех релизах с v0.2.0, а сам файл остаётся намного
  меньше 64 КиБ, которые читает `rayctl`. Проверяют это `TestSumsOfOtherArchives` (`internal/release`),
  `test/install/minisig.sh` (строка из самого `bootstrap.sh`) и строка CI `upgrade (handoff)`, чей подписанный
  релиз тоже перечисляет архивы `rayctl`. Имена архивов ноды заморожены по-прежнему (ниже).
- **Список архивов** — переменная `ARCHIVES` в job `release`: суммы и публикация идут по ней, а не по шаблону
  имён, так что релиз без одного из архивов не выйдет.

## Data plane

Релиз raycontrol несёт data plane в том же архиве и под той же подписью: Xray, собранный из закреплённого коммита
форка, и niko-server из релиза в [`arngory/niko-server`](https://github.com/arngory/niko-server/releases); его тег —
`NIKO_SERVER_TAG` в `deploy/versions.env`. niko-server сверяется с SHA-256, закреплёнными там же
(`scripts/niko-server.sh`). Версии и коммиты компонентов — в файле `VERSIONS` архива. `rayctl install -dataplane`
кладёт их в `/usr/local/libexec/raycontrol/` через журнал установки. Обновление версий — отдельный коммит в
`deploy/versions.env` (новые хеши) и новый релиз.

## Обновление ноды

`rayctl update` берёт последний релиз (`-version vX.Y.Z` — конкретный) и проверяет подпись тем же ключом, что
bootstrap. Версию он читает из подписанного комментария (`raycontrol vX.Y.Z` — его ставит Release-workflow), и
на более старую `latest` не откатывает. Текущие бинарники сохраняются для отката, а база — копией при остановленном
`rayd` (`/var/lib/raycontrol-install/previous/`, только root). Если нода после обновления не отвечает, бинарники и
база возвращаются сами (решение R4-12). У скачивания своё время (до 30 минут на всю команду), у перезапуска и
отката — своё (5 минут), так что медленная сеть не съедает откат. `rayctl update -rollback` вручную возвращает
базу, только если обновление сдвинуло её схему: всё, что поменялось после обновления, тогда теряется, поэтому
команда спрашивает (`-yes` — без вопроса). `rayd` не запускается на базе, схема которой новее его собственной. Без доступа к GitHub и зеркалам: скачайте `SHA256SUMS`,
`SHA256SUMS.minisig` и архив своей архитектуры в каталог и выполните `rayctl update -from <каталог>`.

### Передача обновления rayctl нового релиза (v0.19.0+)

С v0.19.0 `rayctl update` на ноде только проверяет релиз и отдаёт обновление `rayctl` самого релиза:

1. проверка как прежде: подпись minisign над `SHA256SUMS` закреплённым ключом, версия из trusted comment, SHA-256
   архива; пока не проверено, из архива ничего не запускается;
2. из архива достаётся один `rayctl` (`release.ExtractFile`: остальное пропускается, будь то каталоги, незнакомые
   имена или сколько угодно файлов); рядом в свой подкаталог каталога обновления
   (`/var/lib/raycontrol-install/update-*/handoff`, 0700) ложатся `SHA256SUMS`, подпись и архив;
3. `<каталог>/rayctl update -from <каталог> -version vX [-yes] [-force]` с `RAYCONTROL_UPDATE_FROM=<версия ноды>` и
   `RAYCONTROL_UPDATE_HANDOFF=1`; вопрос «Type yes» задаёт уже он. Он проверяет релиз ещё раз своим ключом,
   распаковывает архив своим кодом, ставит, применяет, ждёт data plane и при сбое откатывается; для отката
   записывает версию ноды, а не свою.

Без передачи (как до v0.19.0): релиз не новее ноды (`-version` на старую, `-force` на ту же: откатывает тот, кто знает
более новое состояние ноды), `-rollback`, `-local`, уже переданное обновление, `-no-handoff`, и когда `rayctl` релиза не
запустился вовсе (noexec, не та архитектура). Обрывать дочерний процесс по таймауту команды родитель не может: его
перезапуск и откат идут своим временем.

**Что заморожено** — на это полагаются все `rayctl` с передачей: имя архива `raycontrol-linux-<arch>.tar.gz`, tar+gzip,
`rayctl` на верхнем уровне, подпись minisign над `SHA256SUMS` с `raycontrol vX.Y.Z`, команда
`update -from DIR -version V [-yes] [-force]` и две переменные (`-force` передаётся с v0.21.0, если его дал оператор), а с relay-update-remote-v1 и третья,
`RAYCONTROL_UPDATE_NO_RELAYS=1`: так `-no-relays` доходит до `rayctl` релиза, который обновляет и пишет статус. Для обновления по запросу
([spec/node-update-v1.md](spec/node-update-v1.md)) ещё `RAYCONTROL_UPDATE_RESULT=<файл>`: `rayctl`, который сделал
обновление, пишет туда JSON `{"state": "done"|"rolled_back"|"failed", "version", "release", "error", "untouched",
"reason"}` (`release` — релиз, который ставили; `untouched` — сбой до того, как на ноде что-то поменялось; `reason` —
код места сбоя из [spec/relay-update-remote-v1.md](spec/relay-update-remote-v1.md) §3.6: слово из строчных латинских
букв и `_`, до 32 байт; незнакомый читающему код — не ошибка). Тоже между версиями: файлы
`/var/lib/raycontrol-update/status.json` (`id`, `state`, `from`, `to`, `target`, `release`, `by`, `kind`, `error`,
`untouched`, `reason`, `unfinished`, `no_relays`, `held`, `requested`, `started`, `ended`: итог пишет `rayctl` прежней версии, читает
rayd новой; `kind` — `remote`, `auto`, `local`, на relay — `exit`) и `policy.json` (`remote`, `auto`, `window`), флаги
юнитов `update -request`, `update -request-ended` и, на relay, `update -request-recover`. `reason` и `unfinished`
(только в статусе: обновление relay не кончилось, нужен root на нём) необязательны: прежние `rayctl` их не пишут, и итог
или статус без них читается как «кода нет». `no_relays: true` — у ручного `rayctl update -no-relays` на ноде (вид
`local`, `by: "rayctl on the node"`): выход не называет эту версию своим relay; поля нет — relay идут за обновлением
([spec/relay-update-remote-v1.md](spec/relay-update-remote-v1.md) §11 п. 1). На relay с v0.28.0 ещё
(relay-update-remote-v1 §4): юнит одного релиза запускает `rayctl` другого, `rayd relay` одной версии пишет то, что
читает `rayctl` root другой, а runner, `ExecStopPost` и откат при загрузке находят то, что оставил `rayctl` релиза.
Поэтому заморожены имена юнитов `raycontrol-relay-update.path`, `raycontrol-relay-update.service` и
`raycontrol-relay-recover.service` (их включают и выключают по имени `rayctl update remote` и установка relay, копия
обновления помнит их состояния); путь запроса `/var/lib/rayd-relay/update-request` (JSON запроса ноды, вид `exit`);
метка `/var/lib/raycontrol-install/previous/relay.unfinished` (`state`, `from`, `to`, `by`: сами откатывают только
обновление с `by: "exit"`); откат, который они запускают, — `update -rollback -yes` установленного `rayctl` с
`RAYCONTROL_RELAY_ROLLBACK_BY_RUNNER=1` (тогда статус пишет runner); статус relay — 0640 с группой `rayd`, его читает
`rayd relay`. И `units` в ответе `GetDeployment`: `rayctl` без передачи (`-no-handoff`, `rayctl` релиза не запустился)
берёт оттуда юниты после обновления; `files` и `users` уйдут из ответа (apply-plan-v1, решение 2). Откат ниже v0.21.0 запускает apply старого
`rayctl`, а тот ставит план rayd как есть: иного apply у старой версии нет (apply-plan-v1 §3.5). Всё остальное (раскладка, имена, число файлов, новые
транспорты, способ установки) с v0.19.0 можно менять без ступеней. CI проверяет передачу строкой `upgrade (handoff)`:
это дерево как v0.0.1 обновляется до себя же как v0.0.2, подписанного одноразовым ключом (сборка с тегом
`releasetest` берёт ключ из `RAYCONTROL_TEST_RELEASE_KEY`; в Release-workflow тега нет —
`TestReleaseBuildHasNoTestKey`).

### Со старых версий: ступени

Обновление делает **уже установленный** `rayctl`: он скачивает, проверяет и распаковывает архив нового релиза, ставит
бинарники и запускает `rayctl apply` нового релиза, который доставит то, чего старый не знал. Поэтому важно, какой
архив старый `rayctl` вообще примет.

| `rayctl` на ноде | что он принимает | как обновиться до последнего |
|---|---|---|
| v0.19.0 и новее | только `rayctl` из архива, остальное читает `rayctl` релиза (передача) | `rayctl update` |
| v0.15.0–v0.18.x | любые обычные файлы с простыми именами (`[A-Za-z0-9._-]`, без каталогов), не больше 64 | `rayctl update` |
| v0.10.0–v0.14.x | только свой список: `rayd rayspa rayctl xray niko-server VERSIONS ipinfo_lite.mmdb NOTICE`; с v0.16.0 в архиве есть `slipstream-server`, и такой `rayctl` отказывает: `unexpected "slipstream-server" in the archive` | в два шага, ступень — v0.15.0: `rayctl update -version v0.15.0`, затем `rayctl update` |

CI проходит оба пути: job `upgrade (latest)` — с последнего релиза на текущую сборку, `upgrade (v0.10.2)` — с самого
старого релиза, который ставит `bootstrap.sh` (`MIN_VERSION`), через ступень v0.15.0. Ступень там ставит настоящий
подписанный архив (`rayctl update -from`), так что старый `rayctl` распаковывает его сам, как с GitHub. До этого CI
проверял только обновление с последнего релиза, и путь с v0.10 сломался незаметно.

### Формат архива: правила для новых компонентов

- **Новый транспорт** со своим бинарником — новый файл в архиве (`tar` в `release.yml`) и строка в `nodeBinaries`
  (`cmd/rayctl/update.go`; бинарник data plane ставится в `/usr/local/libexec/raycontrol`). `rayctl` v0.15.0+ сам
  кладёт незнакомые ему файлы во временный каталог, а `rayctl apply` нового релиза их ставит (`RAYCONTROL_UPDATE_STAGE`).
  `TestArchiveMembersInstalled` (cmd/rayctl) не даст выпустить файл, который `rayctl update` не ставит;
  `TestArchiveFiles` (internal/release) требует записать новый файл в `release.FilesSince` с релизом, где он
  появился, а в заметках этого релиза — «v0.15.0 first» для нод старше v0.15.0.
- **Формат не меняется**: архив плоский, обычные файлы, простые имена, не больше 64, `rayctl` и `VERSIONS` всегда
  есть, имя `raycontrol-linux-<arch>.tar.gz`, подпись — minisign над `SHA256SUMS` с trusted comment
  `raycontrol vX.Y.Z`. Это читают все `rayctl` с v0.15.0 и `bootstrap.sh`.
- **Если формат всё же нужно поменять**: для нод на v0.19.0+ раскладку архива можно менять свободно (передача), кроме
  замороженного выше. Ноды v0.15–v0.18 распаковывают архив сами: для них ступень — последний релиз в старом формате
  (v0.19.x). Замороженное меняется только через ступень: сначала выпуск, `rayctl` которого понимает и старое, и новое,
  и только следующий — в новом. Ступень записывается в таблицу выше и в заметки, а в матрицу job `upgrade` —
  строка «через ступень».
