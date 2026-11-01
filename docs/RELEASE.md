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

## Выпуск

1. Файл `.github/release-notes/<тег>.md` (например `v0.2.0.md`) — уже в ветке, которая идёт в релиз.
2. Тег на коммите `main`: `git tag v0.2.0 && git push origin v0.2.0`.
3. Workflow `Release` собирает `raycontrol-linux-{amd64,arm64}.tar.gz` (`rayd`, `rayspa`, `rayctl`), считает `SHA256SUMS`,
   подписывает его и публикует релиз с этими файлами и `SHA256SUMS.minisig`.

## Проверка вручную

```
minisign -Vm SHA256SUMS -P <публичный ключ>
sha256sum -c SHA256SUMS --ignore-missing
```

## Data plane

niko-server и Xray собираются из закреплённых коммитов (`deploy/versions.env`) и ставятся в `/usr/local/bin`.
`rayctl apply` не включает юниты, чьих бинарников нет на хосте, и пишет об этом. Автоматическая загрузка data plane —
этап R4 (`rayctl update`).
