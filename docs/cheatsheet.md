# Шпаргалка

Все команды — на ноде, от root или от члена группы `raycontrol`; `install`, `apply`, `update`, `uninstall`,
`backup` и `restore` — только root.
`-json` перед командой даёт машинный вывод (`rayctl -json status`). Пошаговая установка —
[10-quickstart-debian13.md](10-quickstart-debian13.md).

## Установка и удаление

| Команда | Что делает |
|---|---|
| `bash bootstrap.sh -remove-v0 -host IP …` · `rayctl legacy [-remove]` | убрать прежний raycontrol (v0, `ray.sh`) перед установкой: копия в `/root`, затем только его следы; `-purge-v0-packages` — и его пакеты (R4-26) |
| `rayctl knock @bundle` | только SPA: открыть службы устройства своему адресу; с аварийным пакетом — SSH, затем `ssh` (R4-27) |
| `rayctl check [-host A] [-domain D] [-services a,b]` · `bash bootstrap.sh -check …` | годится ли хост: обязательное (без него установка откажет) и желательное; ничего не меняет (R4-24) |
| `bash bootstrap.sh -host IP -domain D -cloudflare-token-file F [-services reality,dnstt,masterdns]` | поставить ноду: зависимости, подписанный релиз с data plane, `rayctl install`, сервисы |
| `rayctl install -host IP [-domain D] [-admin A] [-cloudflare-token-file F] [-services …\|none] [-dataplane DIR]` | то же без bootstrap; `-dataplane` — каталог с проверенными `xray` и `niko-server` |
| `rayctl apply` | поставить то, что нужно новым сервисам: пользователи, юниты, файлы |
| `rayctl update [-check] [-version vX.Y.Z] [-from DIR] [-yes]` | обновить ноду до проверенного релиза; при сбое — сам откат |
| `rayctl update -rollback` | вернуть бинарники, которые заменило последнее обновление |
| `rayctl uninstall [-yes] [-keep-state] [-keep-dns] [-purge-packages]` | убрать всё по журналу установки, записи в Cloudflare тоже |
| `rayctl admin <ваш IP> [прежние адреса…]` | с консоли провайдера: пустить свой адрес к SSH без SPA (список заменяется целиком) |
| `systemctl stop rayspa && rayspa teardown` | с консоли: снять периметр целиком, пока rayspa не запустится снова (при работающем rayspa таблица возвращается за секунды) |

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
| `rayctl probe [-carrier udp\|tls\|tcp\|auto] [-redact] @bundle` | проверить ноду снаружи, как клиент; `auto` — UDP, ClientHello, голый TCP |
| `journalctl -u rayd -u rayspa -u 'niko-*' -f` | журналы ноды |
| `systemctl status rayd rayspa 'niko-*'` | состояние юнитов |
| `nft list table inet raycontrol` | периметр; цепочка `early` — отброшенное до сборки фрагментов |
| `rayctl metrics [-o /var/lib/node_exporter/textfile/raycontrol.prom]` | счётчики в формате Prometheus: только числа, без имён и адресов |

## Сводка от клиентов (необязательно, R4-21)

| Команда | Что делает |
|---|---|
| `rayctl summary on\|off` | принимать отчёты клиентов о сетях (клиенты шлют только с согласия пользователя) и давать подсказки о порядке профилей |
| `rayctl summary [-days 7]` | сети, где не меньше 10 отчётов: что работает, потери UDP, скорость; остальное — одной суммой; базы AS и их даты |
| `rayctl summary api ipinfo [-token-file F]` · `rayctl summary api none` | API ipinfo для адресов, которых нет в базах: спрашивает по сети /24 или /48, не по адресу |
| `rayctl summary db F.mmdb` · `rayctl summary db -remove` | своя база AS (IPinfo Lite своим токеном, GeoLite2 ASN своим ключом) впереди базы из релиза; root, на ноде |
| `rayctl probe -report '{"v":1,…}' @bundle` | отправить отчёт как клиент (probe-v1 §6), для проверки |

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
| `rayctl service set ygg peers=tls://host:443,quic://203.0.113.9:443` → `rayctl apply` | публичные пиры Yggdrasil, до 8 (по умолчанию нет; `quic` — только по IP; лучше разные операторы и `tls`/`quic`/`wss`): нода видна в сети Yggdrasil, клиенты получают пиры как запасной путь; `peers=none` — выключить |
| `rayctl service cert site -chain chain.pem -key key.pem` | свой сертификат сайта вместо ACME (свой CA, другой ACME-клиент, тестовый CA): для REALITY, hy2-masq, naive, DoH и Yggdrasil под сайтом; должен покрывать все имена сайта |
| `rayctl service rotate reality [-now]` | новые ключи (и имя) REALITY: через срок публикации или сразу; с `-now` прежние ключи сразу перестают работать, иначе принимаются ещё `-cred-grace` |

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
| `-cred-period` / `-cred-lead` / `-cred-grace` | 30 д / 3 д / 2 д | UUID пользователей: срок, публикация заранее, приём старого; `-cred-grace` — и приём прежних ключей REALITY (R4-19) |
| `-reality-period` / `-reality-prepare` | 90 д / 1 д | ключи и имя REALITY; время на сертификат нового имени |
| `-spa-tcp` | true | TCP-носитель SPA; `false`, если хватает UDP |
| `-acme-directory` | Let's Encrypt | CA; пусто — без сертификатов |
| `-run` | `/run/niko` | каталог сокетов и копий секретов data plane |
| `-supervise` · `-xray` · `-niko-server` | выкл. | без systemd (CI, контейнеры): data plane — дочерние процессы rayd под его пользователем; не для ноды (R4-22, `test/supervise/run.sh`) |

## Relay (relay-v1)

```
rayctl relay add msk 198.51.100.20   # адрес relay (IPv4) доходит до портов сервисов без SPA, но не до SSH
rayctl relay bundle -o msk.bundle msk   # пакет для хоста relay: новый сертификат и ключи SPA, прежние не работают;
                                        # SSH relay: его список, у нового — адрес этой SSH-сессии (или -admin)
rayctl relay set -admin 203.0.113.9 msk   # адреса для SSH хоста relay (и -ssh-port), без нового пакета
rayctl relay list
rayctl relay remove msk   # потерянный relay: только remove отнимает у его адреса порты сервисов
```

На хосте relay (пакет скопировать туда и только туда — в нём ключ):

```
sudo bash bootstrap.sh -relay msk.bundle   # rayspa, пересылка ядром к выходу; SSH — с адресов администратора relay
```
