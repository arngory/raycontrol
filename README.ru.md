# raycontrol

[English](README.md) | Русский

Управление самодостаточной прокси-нодой на одном Linux-хосте. Data plane — [niko-server](https://github.com/arngory/niko-server);
raycontrol хранит пользователей, устройства и ключи, пишет конфиги, ведёт файрвол со SPA, ротирует ключи, отдаёт
подписанную подписку и API для клиента [Niko](https://github.com/arngory/niko). Все порты закрыты для тех, кто не
постучался.

Выпуски: [последний](https://github.com/arngory/raycontrol/releases/latest), подписаны minisign.

## Установка

Любой современный Linux с systemd (CI ставит на Debian 12/13, Ubuntu 24.04, Rocky Linux 9/10). От root, из SSH-сессии:
её адрес сохраняет доступ по SSH.

```
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh -host <публичный адрес> -domain <домен> -services reality,dnstt
```

Скрипт проверяет подпись выпуска и хост, ставит всё и закрывает порты, кроме SPA, DNS-туннелей и SSH с вашего адреса.
С консоли провайдера `rayspa teardown` снова открывает хост.

Пошагово, с голого сервера до пакета для клиента: [docs/guide/quickstart-debian13.md](docs/guide/quickstart-debian13.md).
Все команды: [docs/guide/cheatsheet.md](docs/guide/cheatsheet.md).

## Работа

```
rayctl status
rayctl user add -services reality -expires 30d   # печатает имя нового пользователя
rayctl device invite <пользователь> phone        # одноразовое приглашение для приложения Niko
rayctl update                                    # новейший проверенный выпуск, откат при сбое
rayctl uninstall                                 # всё как было до установки
```

## Сборка

Go — как в `go.mod`:

```
go build ./cmd/...
go test ./...
```

`scripts/gen.sh` заново генерирует код API из `api/proto`.

## Ещё

- [docs/README.md](docs/README.md): устройство, решения и спецификации.
- [CONTRIBUTING.md](CONTRIBUTING.md): ветки, проверки и выпуски.
- [docs/RELEASE.md](docs/RELEASE.md): как выходит и проверяется выпуск.

Лицензия: GPL-3.0, см. [LICENSE](LICENSE).
