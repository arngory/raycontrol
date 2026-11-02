# Шпаргалка

Все команды — на ноде, от root или от члена группы `raycontrol`; `install`, `apply` и `uninstall` — только root.
`-json` перед командой даёт машинный вывод (`rayctl -json status`). Пошаговая установка —
[10-quickstart-debian13.md](10-quickstart-debian13.md).

## Установка и удаление

| Команда | Что делает |
|---|---|
| `bash bootstrap.sh -host IP -domain D -cloudflare-token-file F` | поставить ноду: зависимости, подписанный релиз, `rayctl install` |
| `rayctl install -host IP [-domain D] [-admin A] [-cloudflare-token-file F]` | то же без bootstrap (бинарники уже в `/usr/local/bin`) |
| `rayctl apply` | поставить то, что нужно новым сервисам: пользователи, юниты, файлы |
| `rayctl uninstall [-yes] [-keep-state] [-keep-dns] [-purge-packages]` | убрать всё по журналу установки, записи в Cloudflare тоже |
| `rayspa teardown` | с консоли провайдера: снять периметр, если SPA и SSH недоступны |

## Состояние и диагностика

| Команда | Что делает |
|---|---|
| `rayctl status` | версия, нода, число пользователей, сервисов, устройств, порты SPA сейчас |
| `rayctl service list` | сервисы; для REALITY — когда сменились ключи и когда следующая смена |
| `rayctl audit [-n 50]` | журнал действий администратора |
| `rayctl report [-o F] [-logs warning\|info\|none] [-since 24h]` | очищенный отчёт для issue, ничего не отправляет |
| `rayctl probe [-carrier udp\|tcp\|auto] [-redact] @bundle` | проверить ноду снаружи, как клиент |
| `journalctl -u rayd -u rayspa -u 'niko-*' -f` | журналы ноды |
| `systemctl status rayd rayspa 'niko-*'` | состояние юнитов |
| `nft list table inet raycontrol` | периметр; цепочка `early` — отброшенное до сборки фрагментов |

## Пользователи и устройства

| Команда | Что делает |
|---|---|
| `rayctl user add [NAME] -services a,b [-expires 30d\|2026-12-31] [-limit 50G]` | без имени — непрозрачный `u-xxxx-xxxx` |
| `rayctl user list` | пользователи |
| `rayctl user services NAME a,b` | какие сервисы доступны |
| `rayctl user enable\|disable\|del NAME` | включить, отключить, удалить |
| `rayctl device add USER NAME [-role admin] [-o F]` | пакет устройства `rcdev1:…` — один раз, на экран или в файл 0600 |
| `rayctl device list [USER]` | устройства |
| `rayctl device revoke ID` | отозвать: SPA и подписка для него закрываются |

## Сервисы

| Команда | Что делает |
|---|---|
| `rayctl service add reality reality` | REALITY с self-steal на своём сайте-приманке |
| `rayctl service add dnstt dns` · `rayctl service add masterdns mdns` | DNS-туннели (резервный канал) |
| `rayctl service enable\|disable\|del NAME` | включить, выключить, удалить |
| `rayctl service set site answer=404\|403\|silent\|pages` | что сайт отвечает тем, кого отклонил REALITY; потом `rayctl apply` |
| `rayctl service set reality rotate_sni=false` | не менять имя REALITY при ротации |
| `rayctl service rotate reality [-now]` | новые ключи (и имя) REALITY: через срок публикации или сразу |

## DNS (Cloudflare)

| Команда | Что делает |
|---|---|
| `rayctl dns` | провайдер, нужные записи, проблемы (чужие записи, проксирование) |
| `rayctl dns cloudflare [-token-file F]` | подключить Cloudflare; без файла токен спрашивается без эха |
| `rayctl dns sync` | привести зону в порядок сейчас (rayd делает это сам) |
| `rayctl dns remove [-keep-records]` | удалить записи raycontrol и забыть провайдера |

## Доступ администратора

| Команда | Что делает |
|---|---|
| `rayctl admin` | адреса, которым SSH открыт без SPA |
| `rayctl admin 198.51.100.7 2001:db8::/48` | заменить список |

## Отдать подписку клиенту

```bash
rayctl user add -services reality,dns -expires 90d
```

```bash
rayctl device add u-k3f9-x2qa phone -o /root/phone.bundle
```

Передать `/root/phone.bundle` по доверенному каналу, клиент импортирует его в Niko, потом:

```bash
shred -u /root/phone.bundle
```

Подписку клиент берёт сам по пакету. Смены UUID и ключей REALITY приходят в ней заранее (`next`).

## Сроки ротации (флаги `rayd serve`)

| Флаг | По умолчанию | Что |
|---|---|---|
| `-cred-period` / `-cred-lead` / `-cred-grace` | 30 д / 3 д / 2 д | UUID пользователей: срок, публикация заранее, приём старого |
| `-reality-period` / `-reality-prepare` | 90 д / 1 д | ключи и имя REALITY; время на сертификат нового имени |
| `-spa-tcp` | true | TCP-носитель SPA; `false`, если хватает UDP |
| `-acme-directory` | Let's Encrypt | CA; пусто — без сертификатов |
