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
2. Содержимое `raycontrol.key` целиком — в секрет репозитория `MINISIGN_SECRET_KEY`
   (Settings → Secrets and variables → Actions).
3. Вторая строка `raycontrol.pub` (начинается с `RW`) — в `PUBKEY` файла `install/bootstrap.sh`, отдельным коммитом.
   До этого bootstrap отказывается работать.
4. `raycontrol.key` — в офлайн-хранилище. Потеря ключа = новый ключ и новый `bootstrap.sh`.

Текущий ключ: ID `A9C7802E23B87A01`, публичная часть
`RWQBergjLoDHqeme5vyIuIRXJLjTj1EF3jR1nlWBVJO3rWxgy9SZj4bD` (уже в `install/bootstrap.sh`). Строка
`untrusted comment` из `.pub` — только подпись к файлу: в `bootstrap.sh` и в `minisign -P` она не нужна.

## Выпуск

1. Файл `.github/release-notes/<тег>.md` (например `v0.2.0.md`) — уже в ветке, из которой выпускается релиз.
2. Запуск, один из двух:
   - **из GitHub** (основной способ; из сессий Claude пушить теги нельзя): Actions → Release → Run workflow → выбрать
     ветку (обычно `main`) и ввести тег `vX.Y.Z`. Workflow сам создаст тег на этом коммите вместе с релизом;
     существующий тег он не перезаписывает;
   - **тегом**: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Workflow собирает `raycontrol-linux-{amd64,arm64}.tar.gz` (`rayd`, `rayspa`, `rayctl`, `xray`, `niko-server`,
   `VERSIONS`), считает `SHA256SUMS`, подписывает его (trusted comment `raycontrol vX.Y.Z` — по нему `rayctl update`
   узнаёт версию) и публикует релиз с этими файлами и `SHA256SUMS.minisig`.

`install/bootstrap.sh` берёт последний релиз (или `RAYCONTROL_VERSION`), а сам скрипт по README скачивается из `main`:
пока код не слит в `main`, скачивайте `bootstrap.sh` из рабочей ветки.

## Проверка вручную

```
minisign -Vm SHA256SUMS -P <публичный ключ>
sha256sum -c SHA256SUMS --ignore-missing
```

## Data plane

Релиз raycontrol несёт data plane в том же архиве и под той же подписью: Xray, собранный из закреплённого коммита
форка, и niko-server из релиза `vX.Y.Z` в [`arngory/niko-server`](https://github.com/arngory/niko-server/releases) (сейчас `v0.6.1`). niko-server
сверяется с SHA-256, закреплёнными в `deploy/versions.env` (`scripts/niko-server.sh`). Версии и коммиты компонентов —
в файле `VERSIONS` архива. `rayctl install -dataplane` кладёт их в `/usr/local/libexec/raycontrol/` через журнал
установки. Обновление версий — отдельный коммит в `deploy/versions.env` (новые хеши) и новый релиз.

## Обновление ноды

`rayctl update` берёт последний релиз (`-version vX.Y.Z` — конкретный) и проверяет подпись тем же ключом, что
bootstrap. Версию он читает из подписанного комментария (`raycontrol vX.Y.Z` — его ставит Release-workflow), и
на более старую `latest` не откатывает. Текущие бинарники сохраняются для отката; если нода после обновления не
отвечает, они возвращаются сами (решение R4-12). Без доступа к GitHub и зеркалам: скачайте `SHA256SUMS`,
`SHA256SUMS.minisig` и архив своей архитектуры в каталог и выполните `rayctl update -from <каталог>`.
