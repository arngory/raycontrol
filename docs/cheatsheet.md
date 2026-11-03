# Шпаргалка

Все команды — на ноде, от root или от члена группы `raycontrol`; `install`, `apply`, `update`, `uninstall`,
`backup` и `restore` — только root.
`-json` перед командой даёт машинный вывод (`rayctl -json status`). Пошаговая установка —
[10-quickstart-debian13.md](10-quickstart-debian13.md).

## Установка и удаление

| Команда | Что делает |
|---|---|
| `bash bootstrap.sh -host IP -domain D -cloudflare-token-file F [-services reality,dnstt,masterdns]` | поставить ноду: зависимости, подписанный релиз с data plane, `rayctl install`, сервисы |
| `rayctl install -host IP [-domain D] [-admin A] [-cloudflare-token-file F] [-services …\|none] [-dataplane DIR]` | то же без bootstrap; `-dataplane` — каталог с проверенными `xray` и `niko-server` |
| `rayctl apply` | поставить то, что нужно новым сервисам: пользователи, юниты, файлы |
| `rayctl update [-check] [-version vX.Y.Z] [-from DIR] [-yes]` | обновить ноду до проверенного релиза; при сбое — сам откат |
| `rayctl update -rollback` | вернуть бинарники, которые заменило последнее обновление |
| `rayctl uninstall [-yes] [-keep-state] [-keep-dns] [-purge-packages]` | убрать всё по журналу установки, записи в Cloudflare тоже |
| `rayspa teardown` | с консоли провайдера: снять периметр, если SPA и SSH недоступны |

## Резервная копия

| Команда | Что делает |
|---|---|
| `rayctl backup [-o F] [-passphrase-file P]` | вся нода (ключи, пользователи, сервисы, сертификаты, токен DNS) одним файлом 0600 под фразой; хранить вне ноды |
| `rayctl restore -i F [-passphrase-file P] [-yes]` | вернуть копию на этой ноде; прежняя база остаётся в `/var/lib/raycontrol/rayd.db.before-restore` |
| `rayctl install -host NEW …` → `rayctl restore -i F -host NEW` | перенести ноду на новый хост; записи DNS обновятся, устройствам — новые бандлы |

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
| `rayctl metrics [-o /var/lib/node_exporter/textfile/raycontrol.prom]` | счётчики в формате Prometheus: только числа, без имён и адресов |

## Пользователи и устройства

| Команда | Что делает |
|---|---|
| `rayctl user add [NAME] -services a,b [-expires 30d\|2026-12-31] [-limit 50G]` | без имени — непрозрачный `u-xxxx-xxxx` |
| `rayctl user list` | пользователи |
| `rayctl user services NAME a,b` | какие сервисы доступны |
| `rayctl user export NAME [-o F]` | ссылки пользователя, как в подписке (и следующие, если ждёт смена); в них учётные данные, вызов попадает в аудит; работают только с адреса, который открыл SPA |
| `rayctl user enable\|disable\|del NAME` | включить, отключить, удалить |
| `rayctl device add USER NAME [-role admin] [-o F]` | пакет устройства `rcdev1:…` — один раз, на экран или в файл 0600 |
| `rayctl device list [USER]` | устройства |
| `rayctl device revoke ID` | отозвать: SPA, подписка и API для него закрываются; неиспользованное приглашение — отозвать |
| `rayctl device invite USER NAME [-role admin] [-ttl 24h] [-o F]` | одноразовое приглашение `rcinv1:…`: клиент сам регистрирует устройство через API (нужен сервис `api`) |

## Удалённое администрирование (R3)

| Команда | Что делает |
|---|---|
| `rayctl service add api api` → `rayctl apply` | включить удалённый API: свой порт за SPA, mTLS |
| `rayctl device invite admin laptop -role admin` | на ноде: приглашение для устройства администратора |
| `rayctl remote enroll -o laptop.rcdev rcinv1:…` | на своей машине: новый ключ, SPA, регистрация; файл устройства 0600 |
| `rayctl -remote laptop.rcdev status` | любая команда `status`, `user`, `service`, `device`, `audit`, `admin`, `dns`, `metrics` через API |
| `rayctl -remote laptop.rcdev remote rotate` | новый клиентский ключ, старый перестаёт работать |

## Сервисы

| Команда | Что делает |
|---|---|
| `rayctl service add reality reality` | REALITY с self-steal на своём сайте-приманке |
| `rayctl service add hy2-masq hy2-masq` · `rayctl service add hy2-obfs hy2-obfs` | Hysteria2: оба на UDP 443 за фронтом — с маскировкой и в salamander |
| `rayctl service add doh doh` | DoH для клиентов на TCP 443 (после REALITY) |
| `rayctl service add naive naive` | NaiveProxy (HTTP/2) на TCP 443 (после REALITY); потом `rayctl apply` |
| `rayctl service add yggdrasil ygg` | Yggdrasil: прямой TLS-линк на TCP 443 за фронтом (после REALITY), трафик идёт в `inner`; потом `rayctl apply` |
| `rayctl service add dnstt dns` · `rayctl service add masterdns mdns` | DNS-туннели (резервный канал) |
| `rayctl service add api api` | удалённый API для устройств-администраторов и регистрации по приглашениям |
| `rayctl service enable\|disable\|del NAME` | включить, выключить, удалить |
| `rayctl service set site answer=404\|403\|silent\|pages` | что сайт отвечает тем, кого отклонил REALITY; потом `rayctl apply` |
| `rayctl service set reality rotate_sni=false` | не менять имя REALITY при ротации |
| `rayctl service set hy2-masq up_mbps=500` | потолок серверного Brutal на соединение: нода шлёт клиенту не быстрее min(500 Мбит/с, темп клиента); `down_mbps` — потолок отдачи клиента; `0` — без потолка |
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
