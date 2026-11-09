# Шпаргалка

Все команды — на ноде, от root или от члена группы `raycontrol`; `install`, `apply`, `update`, `uninstall`,
`backup`, `restore`, `egress block|allow` и `conn-limit on|off` — только root.
`-json` перед командой даёт машинный вывод (`rayctl -json status`). Пошаговая установка —
[10-quickstart-debian13.md](10-quickstart-debian13.md).

## Установка и удаление

| Команда | Что делает |
|---|---|
| `bash bootstrap.sh -remove-v0 -host IP …` · `rayctl legacy [-remove]` | убрать прежний raycontrol (v0, `ray.sh`) перед установкой: копия в `/root`, затем только его следы; `-purge-v0-packages` — и его пакеты (R4-26) |
| `rayctl knock @bundle` | только SPA: открыть службы устройства своему адресу; с аварийным пакетом — SSH, затем `ssh` (R4-27) |
| `rayctl check [-host A] [-domain D] [-services a,b]` · `bash bootstrap.sh -check …` | годится ли хост: обязательное (без него установка откажет) и желательное; ничего не меняет (R4-24) |
| `bash bootstrap.sh -host IP -domain D -cloudflare-token-file F [-services reality,dnstt,masterdns,slipstream]` | поставить ноду: зависимости, подписанный релиз с data plane, `rayctl install`, сервисы |
| `rayctl install -host IP [-domain D] [-admin A] [-cloudflare-token-file F] [-services …\|none] [-dataplane DIR]` | то же без bootstrap; `-dataplane` — каталог с проверенными `xray` и `niko-server` |
| `rayctl apply` | поставить то, что нужно новым сервисам: пользователи, юниты, файлы |
| `rayctl update [-check] [-version vX.Y.Z] [-from DIR] [-yes]` | обновить ноду до проверенного релиза; при сбое — сам откат. С v0.15.0: юниты data plane, которые работали до обновления, должны заработать снова (иначе откат); файлы релиза, которых прежняя версия не знает, ставит новый rayctl; в конце — DNS-туннели, у которых режимы слабее, чем у нового сервиса |
| `rayctl update -rollback` | вернуть бинарники, которые заменило последнее обновление |
| `rayctl update remote on\|off` | с v0.19, только root: admin-устройства могут обновлять ноду через API (StartUpdate) — только на подписанный релиз новее ноды; по умолчанию выкл. Политика — файл root `/var/lib/raycontrol-update/policy.json`, rayd его только читает ([`spec/node-update-v1.md`](spec/node-update-v1.md)) |
| `rayctl update auto patch [-window 03:00-05:00]` / `auto off` | с v0.19, только root: rayd сам обновляется на патч-версии своей минорной в окне (время ноды, окно не короче 30 мин); раз в ~6 ч спрашивает GitHub; по умолчанию выкл. После отката эту версию больше не просит; после сбоя до изменений на ноде (скачивание) — через сутки |
| `rayctl update status` | политика обновлений, последний релиз, последнее обновление по запросу; журнал самого обновления — `journalctl -u raycontrol-update` |
| `rayctl update -version v0.15.0` → `rayctl update` | нода на v0.10–v0.14: в два шага, их `rayctl` не берёт архив с новыми файлами (`unexpected "slipstream-server"`); [RELEASE.md](RELEASE.md) |
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
| `rayctl node name "Амстердам"` (`""` — убрать) | имя ноды: клиенты показывают его рядом с адресом со следующей подписки; до 48 символов, без управляющих и невидимых. При установке — `bootstrap.sh … -name "Амстердам"` |
| `rayctl node note "До 1 Гбит/с, торренты нельзя 🙏"` (`""` — убрать) | описание ноды для пользователей: клиенты показывают его со следующей подписки; одна строка, до 200 символов, эмодзи и любые письменности, без управляющих, невидимых и символов смены направления |
| `rayctl status` | версия, нода (и её имя), число пользователей, сервисов, устройств, порты SPA сейчас, политика выхода (`egress`); циклы rayd, `dns-zone <сервис>` — самопроверка зоны туннеля; `conn-limit` — кто упёрся в предел соединений за 15 мин (`u<id>` и сервис), `conntrack` — таблица от 70 %, страж за сутки, отбросы ядра |
| `rayctl service list` | сервисы; для REALITY — когда сменились ключи и когда следующая смена |
| `rayctl audit [-n 50]` | журнал действий администратора |
| `rayctl debug on [-for 30m]` / `off` / `show` | окно отладки: rayd, rayspa и data plane пишут подробно, с адресами клиентов; закрывается само (до суток); службы data plane перезапускаются |
| `rayctl egress` | политика выхода ноды (с v0.21): что закрыто, для кого, действует ли; root видит и счётчики правил |
| `rayctl egress block\|allow bittorrent` | только root, на ноде: закрыть или открыть BitTorrent на всех профилях сразу, в ядре (рукопожатие, uTP, UDP-трекеры, DHT; зашифрованный по TCP проходит). Действует через 1–2 с, data plane не перезапускается. Нода, где были сервисы Xray, после обновления держит BitTorrent закрытым ([`spec/egress-policy-v1.md`](spec/egress-policy-v1.md)) |
| `rayctl egress block\|allow smtp` | только root, на ноде: закрыть или открыть TCP 25 на всех профилях; 465 и 587 (почта в телефоне) открыты. По умолчанию открыт |
| `rayctl conn-limit` | пределы соединений (с v0.24): включены ли, их числа, таблица conntrack (занято, `max`, отбросы), страж (включён ли, переключения, отказы, вычищено), кто упёрся за 15 мин; root видит и отброшенное пределом на адрес |
| `rayctl conn-limit on\|off` | только root, на ноде: пределы на пользователя в naive (TCP: 1024 сразу, 30 новых/с, неудачные dial в долг; журнал пар UDP; ответ `429`) и предел новых входящих TCP и UDP на адрес, здесь и на relay ноды. По умолчанию включены. Действует за секунды, naive не перезапускается. Размер таблицы, `notrack` DNS-туннелей и страж остаются всегда ([`spec/conn-limit-v1.md`](spec/conn-limit-v1.md)) |
| `rayctl report [-o F] [-logs warning\|info\|debug\|none] [-since 24h] [-id ID]` | очищенный отчёт для issue, ничего не отправляет; `-logs debug` — со строками `-debug`, один `-id` на прогон |
| `rayctl probe [-carrier udp\|tls\|tcp\|auto] [-redact] @bundle` | проверить ноду снаружи, как клиент; `auto` — UDP, ClientHello, голый TCP |
| `journalctl -u rayd -u rayspa -u 'niko-*' -f` | журналы ноды |
| `systemctl status rayd rayspa 'niko-*'` | состояние юнитов |
| `nft list table inet raycontrol` | периметр; цепочка `early` — отброшенное до сборки фрагментов, `egress` — политика выхода, `in_rate` — предел новых входящих на адрес, `conn_guard` — страж conntrack (пуста, пока он выключен) |
| `sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max` | таблица conntrack: `apply` ставит размер по памяти (65 536–262 144) и сроки SYN_SENT 30 с, FIN_WAIT 30 с, TIME_WAIT 60 с — только больше размер и только меньше сроки, чем были (`/etc/sysctl.d/90-raycontrol-conntrack.conf`) |
| `rayctl metrics [-o /var/lib/node_exporter/textfile/raycontrol.prom]` | счётчики в формате Prometheus: только числа, без имён и адресов |

## Сводка от клиентов (необязательно, R4-21)

| Команда | Что делает |
|---|---|
| `rayctl summary on\|off` | принимать отчёты клиентов о сетях (клиенты шлют только с согласия пользователя) и давать подсказки о порядке профилей |
| `rayctl app-mirror on\|off` · `rayctl app-mirror` | обновления Niko через ноду (с v0.18, по умолчанию выключено): нода раз в ~6 ч берёт с GitHub последний релиз и pre-release, проверяет подпись minisign Niko и SHA-256 и отдаёт своим устройствам на порту подписки; там, где GitHub недоступен, клиент без VPN узнаёт о новой версии и скачивает её с ноды. `on` хочет 1 ГиБ свободного места; `off` удаляет скачанное. Без аргумента — что держит и когда проверяла ([`spec/app-update-v1.md`](spec/app-update-v1.md)) |
| `rayctl summary [-days 7]` | сети, где не меньше 10 отчётов: что работает, потери UDP, скорость; остальное — одной суммой; базы AS и их даты |
| `rayctl summary api ipinfo [-token-file F]` · `rayctl summary api none` | API ipinfo для адресов, которых нет в базах: спрашивает по сети /24 или /48, не по адресу |
| `rayctl summary db F.mmdb` · `rayctl summary db -remove` | своя база AS (IPinfo Lite своим токеном, GeoLite2 ASN своим ключом) впереди базы из релиза; root, на ноде |
| `rayctl probe -payload @bundle` | ещё и payload подписки в JSON отдельной строкой после `payload ` (с учётными данными, как `-links`) |
| `rayctl probe -report '{"v":1,…}' @bundle` | отправить отчёт как клиент (probe-v1 §6), для проверки |
| `rayctl probe -dns [-resolver system,google,udp:IP] @bundle` | DNS-туннели из подписки глазами этой машины: делегирование у родителя, фронт и бэкенд ноды (опрос с печатью и меткой этого устройства), зоны через резолвер машины или `-resolver` — то же, что `rayctl dns check` с ноды, но из сети администратора |

## Пользователи и устройства

| Команда | Что делает |
|---|---|
| `rayctl user add [NAME] -services a,b [-expires 30d\|2026-12-31] [-limit 50G [-period monthly\|none] [-reset-day 1]]` | без имени — непрозрачный `u-xxxx-xxxx`; `-limit` — лимит трафика (ниже) |
| `rayctl user list` | пользователи; `USED` — расход периода из лимита (`12.0G/50G`, `(over)` — снят) |
| `rayctl user limit NAME 50G\|off [-period monthly\|none] [-reset-day N]` | лимит трафика (с v0.22): `up + down` на стороне назначений за период — месяц с дня N (1–28, 00:00 UTC) или `none` (всё время пользователя). Достиг — снят со всех профилей, как просроченный, до сброса или поднятого лимита; подписка остаётся (`profiles: []`, `exhausted`). Первый лимит на ноде включает счёт: `inner` и REALITY перезапустятся один раз ([`spec/traffic-limit-v1.md`](spec/traffic-limit-v1.md)) |
| `rayctl user usage [NAME]` | расход, лимит, период, начало, сброс, состояние (отстаёт до минуты) |
| `rayctl user reset-usage NAME` | обнулить текущий период сейчас; снятый вернётся в течение секунд |
| `rayctl user services NAME a,b` | какие сервисы доступны |
| `rayctl user lan NAME on\|off` | локальная сеть устройств пользователя через Yggdrasil (с v0.23, [`spec/lan-v1.md`](spec/lan-v1.md)): устройства видят друг друга по адресам Yggdrasil — через ноду или напрямую в одной Wi-Fi. Нужен сервис Yggdrasil у пользователя. В сети только устройства, которые сами показали себя в клиенте (столбец `LAN` в `device list`); пароль и список соседей получают только они. `on` ещё раз — новый пароль; отзыв устройства тоже меняет пароль. Без `on\|off` — показать. Через ноду работает с niko-server v0.16.0 |
| `rayctl user export NAME [-o F]` | ссылки пользователя, как в подписке (и следующие, если ждёт смена); в них учётные данные, вызов попадает в аудит; работают только с адреса, который открыл SPA |
| `rayctl user enable\|disable\|del NAME` | включить, отключить, удалить |
| `rayctl device add USER NAME [-role admin] [-o F]` | пакет устройства `rcdev1:…` — один раз, на экран или в файл 0600 |
| `rayctl device list [USER]` | устройства; `LAN` — показало ли устройство себя в локальной сети пользователя (последний заголовок клиента; в сети оно, когда у пользователя `user lan on`) |
| `rayctl device revoke ID` | отозвать: SPA, подписка и API для него закрываются; неиспользованное приглашение — отозвать |
| `rayctl device invite USER NAME [-role admin] [-ttl 24h] [-o F \| -qr] [-pin] [-format rcinv1]` | одноразовое приглашение, с v0.14 по умолчанию короткое `RCINV2:…` (QR вдвое меньше, Niko 1.35+): клиент сам регистрирует устройство через API (нужен сервис `api`); `-qr` рисует QR в терминале; `-pin` — ещё PIN из 6 цифр, сообщить другим каналом; `-format rcinv1` — длинное `rcinv1:…` для Niko старше 1.35 |

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
| `rayctl service add slipstream slip [-settings '{"zone":"s.example.net"}']` → `rayctl apply` | slipstream (с v0.16, [`spec/slipstream-v1.md`](spec/slipstream-v1.md)): DNS-туннель поверх QUIC с multipath, за DNS-фронтом. Зона — до 20 символов (иначе пакет QUIC Initial не влезет в запрос): своя — `zone`, без неё — случайная в домене ноды (если домен длиннее 16 символов, задайте свою). Каждый запрос несёт метку dnsauth-v2 устройства, фронт проверяет её до сервера; опций нет, ключ сервера (P-256) клиенты закрепляют, ротации нет. Ссылку берут Niko 1.37+, более старые пропускают строку |
| `rayctl service set slip max_connections=512` · `device_connections=2` | пределы slipstream (с v0.17): соединений на сервис (16–1024, по умолчанию 256) и на одно устройство (1–16, по умолчанию 4; сверх любого из пределов уступает соединение устройства, молчащее дольше 5 с). `0` — по умолчанию. Сервер перезапускается. Сколько это людей — [`14-capacity.md`](14-capacity.md) |
| `rayctl service add api api` | удалённый API для устройств-администраторов и регистрации по приглашениям |
| `rayctl service enable\|disable\|del NAME` | включить, выключить, удалить |
| `rayctl service set site answer=404\|403\|silent\|pages` | что сайт отвечает тем, кого отклонил REALITY; потом `rayctl apply` |
| `rayctl service set reality rotate_sni=false` | не менять имя REALITY при ротации |
| `rayctl service set naive icmp=on\|off` → `rayctl apply` | ping и трассировка через naive (с v0.21, [`spec/icmp-v1.md`](spec/icmp-v1.md)): echo клиента шлёт нода со своих ICMP-сокетов; в ссылке `icmp=1`. По умолчанию выключено. `apply` перезапускает naive и, если `net.ipv4.ping_group_range` не покрывает группы data plane (9100–9179), расширяет его (`/etc/sysctl.d/10-raycontrol-icmp.conf`: идёт первым, файлы дистрибутива и администратора после него при загрузке побеждают); `rayctl check` и `apply` предупреждают, если сокеты не откроются |
| `rayctl service set hy2-masq up_mbps=500` | потолок серверного Brutal на соединение: нода шлёт клиенту не быстрее min(500 Мбит/с, темп клиента); `down_mbps` — потолок отдачи клиента; `0` — без потолка |
| `rayctl service set dns auth=optional\|required\|off` | dnsauth-v1: метка устройства в каждом запросе dnstt ([`spec/dnsauth-v1.md`](spec/dnsauth-v1.md)); `required` — только когда все клиенты её ставят (Niko 1.27+). Новый dnstt-сервис создаётся с `required` (v0.13.0), прежние остаются как были — `rayctl service list` показывает `auth … (open: …)`. Без `required` ключ не нужен: любой, кто знает зону (она видна в делегировании), а при `seal=required` — любой со ссылкой, может занять места рукопожатий dnstt (128), и новые сессии будут ждать; память нода держит в пределах и так (niko-server v0.10.0, нагрузочный тест) |
| `rayctl service set dns seal=optional\|required\|off` | dnsseal-v1: обвязка dnstt запечатана ключом зоны ([`spec/dnsseal-v1.md`](spec/dnsseal-v1.md)); ключ уходит в ссылку; `optional` берёт и открытые запросы, `required` — только когда все клиенты запечатывают (с v0.13, Niko 1.35+). Новый dnstt-сервис с v0.14 создаётся с `optional` |
| `rayctl service set mdns seal=… auth=…` | masterdns (с v0.14, niko-server v0.11.0): `seal` — ответы запечатаны ключом сервиса (mdseal-v1, [`spec/mdseal-v1.md`](spec/mdseal-v1.md)), `auth` — метка устройства в каждом запросе, сессия привязана к устройству ([`spec/dnsauth-masterdns.md`](spec/dnsauth-masterdns.md)); `optional` — для тех клиентов, что умеют, `required` — когда умеют все. Новый masterdns-сервис создаётся с `optional` для обоих |
| `rayctl service set dns auth_hint=required` (`optional` — по умолчанию, `off`) | dnsauth-v2 ([`spec/dnsauth-v2.md`](spec/dnsauth-v2.md)): ключ устройства находится по подсказке в метке, без перебора. `optional` берёт и метки v1 перебором, как раньше; `required` — только v2 (мусор с верной обёрткой ничего не стоит ноде), когда все клиенты подписывают по v2; только при `auth=required`. Подписка говорит клиентам, какую версию брать (`dnsauth.v`) |
| `rayctl service set dns spare_zones=2` (или `=a.example.net,b.example.org`, `=none`) → `rayctl apply` | запасные зоны DNS-туннеля, до 4 ([`spec/dnszones-v1.md`](spec/dnszones-v1.md)): число — случайные зоны в домене ноды, как основная (уже заданные остаются); список — свои (для чужих доменов делегирование заводит оператор, Cloudflare — если токен покрывает зону). Нода делегирует, обслуживает и проверяет каждую, как основную (`rayctl status`: `dns-zone dns <зона>`). Зоны не совпадают и не вкладываются друг в друга ни внутри сервиса, ни между сервисами. Для dnstt и masterdns |
| `rayctl service set dns zone=<запасная>` → `rayctl apply` | запасная зона становится основной, прежняя основная уходит: только запасная — она у клиентов уже есть; прежнюю они теряют со следующей подпиской |
| `rayctl service rotate dns [-now]` | новый ключ печати сразу, в подписке с этого момента; прежний нода принимает ещё `-cred-grace` (2 дня), с `-now` — не принимает (ключ утёк): клиенты без новой подписки не получают ничего, пока её не обновят. Второй сброс в пределах срока снимает ключ до прежнего. Заодно меняется ключ самопроверки ноды (строка `node-check` в ключах dnsauth всех dnstt-сервисов). `rayctl service list` показывает режим, дату ключа и срок прежнего |
| `rayctl service set ygg lan_relay=50` | потолок связи устройство—устройство через ноду в локальной сети (`user lan`), Мбит/с на пользователя: без настройки 20, `0` — только напрямую в одной Wi-Fi; эти байты идут в лимит трафика. Бэкенд перезапускается сам. Только с niko-server v0.16.0: более старый отвергает настройку, и Yggdrasil не поднимется |
| `rayctl service set ygg peers=tls://host:443,quic://203.0.113.9:443` → `rayctl apply` | публичные пиры Yggdrasil, до 8 (по умолчанию нет; `quic` — только по IP; лучше разные операторы и `tls`/`quic`/`wss`): нода видна в сети Yggdrasil, клиенты получают пиры как запасной путь; `peers=none` — выключить |
| `rayctl service cert site -chain chain.pem -key key.pem` | свой сертификат сайта вместо ACME (свой CA, другой ACME-клиент, тестовый CA): для REALITY, hy2-masq, naive, DoH и Yggdrasil под сайтом; должен покрывать все имена сайта |
| `rayctl service rotate mdns [-now]` | новый ключ сервиса masterdns сразу, в подписке с этого момента; прежний бэкенд принимает ещё `-cred-grace` (сессии на нём идут дальше), с `-now` — нет (его сессии закрываются). Файл ключей перечитывается без перезапуска. `rayctl service list` показывает дату ключа и срок прежнего |
| `rayctl service rotate reality [-now]` | новые ключи (и имя) REALITY: через срок публикации или сразу; с `-now` прежние ключи сразу перестают работать, иначе принимаются ещё `-cred-grace` |

## DNS

| Команда | Что делает |
|---|---|
| `rayctl dns` | провайдер, нужные записи, проблемы (чужие записи, проксирование) |
| `rayctl dns cloudflare [-token-file F]` | подключить Cloudflare; без файла токен спрашивается без эха |
| `rayctl dns sync` | привести зону в порядок сейчас (rayd делает это сам) |
| `rayctl dns remove [-keep-records]` | удалить записи raycontrol и забыть провайдера |
| `rayctl dns check [-now]` | зоны туннелей с ноды: делегирование у серверов родителя, фронт и бэкенд, проба dnsprobe-v1 через Google, Cloudflare, Quad9 (EDNS, 0x20, выход резолвера); без `-now` — последняя проверка rayd, `-now` — сейчас, не чаще раза в 30 с. Зону slipstream — как dnstt (вершина и пробы фронта), без опроса сервера |
| `rayctl dns check -resolver nsdi,yandex` | то же через другие резолверы (`msk-ix`, `system`, `udp:IP`, `tcp:IP`); российские нода сама не спрашивает, их отказ — только предупреждение |

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
| `-dns-check` · `-dns-check-resolvers` | 1 ч ±10 % · `google,cloudflare,quad9` | самопроверка DNS-зон с ноды; `0` — только `rayctl dns check -now` |
| `-update-check` | `0` (выкл.) | искать новый релиз так часто, не чаще раза в час (±10 %): нода берёт подписанный SHA256SUMS последнего релиза только с github.com — он видит адрес ноды (зеркала — только у `rayctl update`); итог — строка `update` в `rayctl status`, новая версия — один раз в журнал. Только у релизных сборок (vX.Y.Z), независимо от `-dns-check` |
| `-run` | `/run/niko` | каталог сокетов и копий секретов data plane |
| `-supervise` · `-xray` · `-niko-server` | выкл. | без systemd (CI, контейнеры): data plane — дочерние процессы rayd под его пользователем; не для ноды (R4-22, `test/supervise/run.sh`) |

## Relay (relay-v1)

```
rayctl relay add msk 198.51.100.20   # адрес relay (IPv4) доходит до портов сервисов без SPA, но не до SSH
rayctl relay bundle -o msk.bundle msk   # пакет для хоста relay: новый сертификат и ключи SPA, прежние не работают;
                                        # SSH relay: его список, у нового — адрес этой SSH-сессии (или -admin);
                                        # порт замера relay (TCP и UDP) — открыть в файрволе провайдера relay
rayctl relay set -admin 203.0.113.9 msk   # адреса для SSH хоста relay (и -ssh-port), без нового пакета
rayctl relay list   # с портом замера (PROBE)
rayctl relay remove msk   # потерянный relay: только remove отнимает у его адреса порты сервисов
```

На хосте relay (пакет скопировать туда и только туда — в нём ключ):

```
sudo bash bootstrap.sh -relay msk.bundle   # rayspa, пересылка ядром к выходу; SSH — с адресов администратора relay;
                                           # rayd relay — точка замера relay (если её нет, relay работает и без неё)
journalctl -u rayd-relay                   # точка замера relay: поток от выхода, отчёты
```
