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
3. Workflow собирает `raycontrol-linux-{amd64,arm64}.tar.gz` (`rayd`, `rayspa`, `rayctl`), считает `SHA256SUMS`,
   подписывает его и публикует релиз с этими файлами и `SHA256SUMS.minisig`.

`install/bootstrap.sh` берёт последний релиз (или `RAYCONTROL_VERSION`), а сам скрипт по README скачивается из `main`:
пока код не слит в `main`, скачивайте `bootstrap.sh` из рабочей ветки.

## Проверка вручную

```
minisign -Vm SHA256SUMS -P <публичный ключ>
sha256sum -c SHA256SUMS --ignore-missing
```

## Data plane

niko-server — подписанные релизы `niko-server-vX.Y.Z` в `arngory/niko` (сейчас `niko-server-v0.1.1`), Xray собирается из
закреплённого коммита форка; версии — в `deploy/versions.env`. Оба ставятся в `/usr/local/bin`.
`rayctl apply` не включает юниты, чьих бинарников нет на хосте, и пишет об этом. Автоматическая загрузка data plane —
этап R4 (`rayctl update`).
