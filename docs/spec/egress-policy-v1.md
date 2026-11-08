# egress-policy-v1: BitTorrent и SMTP (порт 25) — одна политика на ноду

Статус: **черновик** (2026-11-08). Сервер — raycontrol v0.21.0 (номер предварительный: v0.20.0 занята naive UoT).
niko-server (v0.14.0), форк Xray (`a4a3dff`) и Niko не меняются.

Зачем:
- Сейчас BitTorrent режет только выход Xray, по сниффингу открытого рукопожатия (`internal/render/render.go:1215`).
  Hysteria2 и naive его пропускают. Порт 25 открыт везде ([15-traffic](../15-traffic.md) §1).
- Спам на порт 25 и торренты — частые причины жалоб хостеру и чёрных списков для адреса ноды.
- Нужен один выключатель на ноду, одинаковый для всех профилей. Как всё новое, он выключен по умолчанию.

Главное решение: **оба запрета — в ядре**, в цепочке output периметра, по UID процессов data plane (9100–9179).
Не в Xray, niko-server и naive по отдельности (почему — §4).

## 1. Политика

```
rayctl egress                          # политика, где действует, счётчики (root)
rayctl egress block bittorrent|smtp
rayctl egress allow bittorrent|smtp
```

- **Одна на ноду, не на пользователя.** Ядро не знает пользователя: все пользователи профиля идут через один процесс
  и его UID. И жалоба, и чёрный список приходят на адрес ноды.
- Хранится в `settings` базы: ключи `egress_bittorrent`, `egress_smtp`, значение `on`. Нет ключа — выключено.
- Меняют root и группа `raycontrol` через локальный сокет, как `rayctl app-mirror`. Удалённого метода в v1 нет.
  Каждая смена — в аудит (`egress.set`).
- Применяет rayspa: rayd кладёт политику в снимок периметра, rayspa переписывает одну цепочку (§3). Data plane не
  перезапускается, соединения не рвутся, действует через 1–2 с.
- **Прежнее правило Xray входит в выключатель.** Из конфигов Xray уходят правило `protocol: bittorrent → block` и
  сниффинг, который нужен только ему (`render.go:1198`, `1440`). Почему:
  - иначе «выключено» значило бы «выключено везде, кроме REALITY и inner»;
  - ядро ловит всё, что ловил Xray, и больше (§2);
  - со сниффингом Xray ждёт первых байт клиента до 200 мс перед dial (`app/dispatcher/default.go:391-419` форка):
    без него быстрее начинаются SMTP 587, IMAP 143, POP3 110, где первым говорит сервер (вывод из кода, замерить).
- **Обновление не ослабляет ноду.** Миграция на v0.21.0 ставит `egress_bittorrent=on` там, где уже были сервисы
  Xray (`inner`, `reality`): торренты там резались и раньше, теперь режутся и на Hysteria2 и naive. Новая установка —
  оба выключены. Об этом строка в заметках к релизу и в `rayctl status`.
- Нода `rayd serve -supervise`: data plane идёт под UID rayd, правило его не видит. `rayctl egress` пишет
  «не действует (supervised)». С защитой `to_node` сейчас так же.

## 2. Где и что ловится

Трафик пользователей уходит в интернет только из процессов с UID 9100–9179: фронт 9100 (`render.go:40`), сервисы
9110–9179 (`internal/store/ports.go:57`). Yggdrasil и DNS-туннели выходят через `inner` (`render/yggdrasil.go:151`,
niko-server `nikoserver/backend.go:43`, slipstream `--target-unix`, `render.go:998`), то есть через тот же Xray.
rayd (9190: DoH ноды, пробы) в диапазон не входит: трафик пользователей он не несёт.

| Профиль | Процесс | SMTP 25 | BitTorrent | BT по UDP: что дальше |
|---|---|---|---|---|
| REALITY | Xray `reality` | ядро | ядро | Xray получает EPERM и, по коду, закрывает UDP-сессию целиком (`proxy/freedom/freedom.go:645-648` форка) |
| inner: Yggdrasil, dnstt, masterdns, slipstream | Xray `inner` | ядро | ядро | так же |
| Hysteria2 (masq, obfs) | niko-server | ядро | ядро | ошибку отправки не смотрит: теряется одна датаграмма (`nikoserver/hysteria.go:304`) |
| naive (HTTP/2, HTTP/3, UoT) | `rayd naive`, свой UID (`internal/deploy/deploy.go:415-445`) | ядро | ядро | UoT: так же, поток живёт (`internal/naive/uot.go`, `send`: поток закрывает только `net.ErrClosed`) |
| relay | — | на выходе | на выходе | relay шлёт только к выходу через DNAT (`internal/perimeter/firewall.go:128-147`), правило не нужно |

Ловится одинаково на всех профилях, в каждом пакете:
- **SMTP:** TCP на порт 25, IPv4 и IPv6.
- **BitTorrent по TCP:** сегмент начинается с `\x13BitTorrent protocol` (открытое рукопожатие BEP 3).
- **uTP:** ST_SYN (BEP 29): первый байт 0x41, `timestamp_difference` 0, полезная нагрузка 20 байт (libtorrent) или
  30 (с битами расширений, как у µTorrent и в тесте форка Xray). Заголовок uTP открыт: SYN ловится и с MSE внутри.
- **UDP-трекер:** connect BEP 15 — 0x41727101980, action 0.
- **DHT:** запрос BEP 5 начинается с `d1:ad2:id20:` (bencode требует порядка ключей; так пишут libtorrent и
  jech/dht — вывод).

Не ловится нигде, и обещать этого нельзя:
- **зашифрованный BitTorrent по TCP (MSE/PE)**: после TCP-рукопожатия — случайные байты. qBittorrent и Transmission
  шифрование по умолчанию допускают, а libtorrent при `pe_enabled`, похоже, сначала пробует его (вывод по
  документации, не проверено). Значит, обмен с пирами по TCP в основном проходит;
- трекеры по HTTPS и HTTP (строка запроса не на постоянном месте), PEX внутри потоков, WebTorrent (WebRTC);
- BitTorrent внутри другого туннеля через профиль (WireGuard поверх Hysteria2).

Итог: нет DHT и UDP-трекеров, uTP не устанавливается, открытое рукопожатие сбрасывается. Магнет-ссылки без
HTTPS-трекеров почти не находят пиров; торрент с HTTPS-трекером идёт по TCP с шифрованием. Это помеха и меньше
поводов для жалоб, а не запрет.

## 3. Правила ядра

В таблице `raycontrol` (`internal/perimeter/firewall.go:251`), после правил `to_node`:

```
chain output {
	...                                         # to_node, как сейчас (firewall.go:253-255)
	meta skuid 9100-9179 jump egress            # GuardUIDs
}
chain egress {                                  # rayspa пишет целиком: flush + правила политики
	tcp dport 25 counter reject with tcp reset comment "smtp"
	meta l4proto tcp @ih,0,8 0x13 @ih,8,128 0x426974546f7272656e742070726f746f @ih,136,24 0x636f6c counter reject with tcp reset comment "bittorrent-tcp"
	meta l4proto udp @th,64,8 vmap { 0x00 : jump bt_tracker, 0x41 : jump bt_utp, 0x64 : jump bt_dht }
}
chain bt_tracker { @th,64,64 0x41727101980 @th,128,32 0 counter drop comment "bittorrent-tracker"; }
chain bt_utp { udp length { 28, 38 } @th,128,32 0 counter drop comment "bittorrent-utp"; }
chain bt_dht { @th,64,96 0x64313a6164323a696432303a counter drop comment "bittorrent-dht"; }
```

- **Без `ct state new`.** Первое же сравнение (`tcp dport 25`) отпускает все прочие пакеты, conntrack не нужен.
  `ct state new` лишь оставил бы жить соединения на 25, открытые до включения, а «включено» значит «сразу».
- **Цена.** На пакет data plane — сравнение UID, переход и 2–3 сравнения. Замер (Linux 6.18, nft 1.0.9, loopback,
  UDP 1200 байт под UID 9100): sendto ~1,9 мкс, с цепочкой +0,05–0,3 мкс, на уровне шума замера. Пакеты к клиентам
  (QUIC, REALITY) тоже идут через цепочку, но они зашифрованы и не совпадают.
- **IPv4 и IPv6.** Таблица `inet`, в правилах нет `ip`/`ip6`: одно правило на оба семейства.
- **`@th` и `@ih`.** UDP — смещения от `@th` (заголовок всегда 8 байт), это работает на любом ядре. TCP — от `@ih`:
  заголовок TCP переменной длины. На 6.18/1.0.9 `@ih` работает; Debian 12 и Rocky 9 (ядро 5.14) — проверить в
  CI `install`. Где нет — два правила по `tcp doff 5` и `tcp doff 8` со смещениями от `@th`.
- **TCP — reset, не drop.** При drop процесс ждёт ответа на SYN до своего тайм-аута dial: у naive и Hysteria2 это 10 с
  (`internal/naive/naive.go:108`, `nikoserver/hysteria.go:205`), и приложение всё это время висит. С reset процесс
  сразу получает ECONNREFUSED (25) или ECONNRESET (рукопожатие BT). Клиент видит ошибку, как для любого
  недоступного назначения: naive сбрасывает поток ([naive-uot-v1](naive-uot-v1.md) §4), Hysteria2 закрывает поток
  (`nikoserver/hysteria.go:213-221`), Xray закрывает подпоток VLESS. Точный вид ошибки в приложении зависит от
  TUN-стека Niko (вывод). Пир при сбросе рукопожатия получает TCP-соединение без данных.
- **UDP — drop:** через прокси сбрасывать нечего. Процесс получает EPERM на sendto (что дальше — таблица §2).
- **Ложные срабатывания:**
  - порт 25 конечным пользователям почти не нужен: это обмен между почтовыми серверами. Клиенты отправляют почту
    через 587 (STARTTLS) и 465 (TLS, RFC 8314). Многие хостеры и так закрывают 25 наружу;
  - **465 и 587 открыты.** Там отправка со входом в свой ящик, и спам с них — дело почтового провайдера и его
    лимитов. Закрыть их — сломать почту в телефоне и в Thunderbird;
  - рукопожатие BT, трекер и DHT — 12–20 постоянных байт в начале: в зашифрованном потоке это 2⁻⁹⁶ и меньше;
  - uTP SYN — слабое место: DNS-запрос ровно в 20 байт, без EDNS, с ID 0x4100 (имя из двух букв, `co.`)
    совпадает (проверено). Это 1/65 536 таких запросов, обычные длиннее и с EDNS. WireGuard handshake initiation
    (первый байт 0x01), QUIC Initial, DNS с EDNS и uTP ST_DATA не совпадают (проверено).

## 4. Почему не в процессах

- **Xray** ловит открытое рукопожатие и uTP SYN (`app/dispatcher/sniffer.go:41,43` форка), трекеры и DHT — нет. По
  UDP смотрит только первый пакет сессии: один `Dispatch` на сессию (`common/mux/server.go:232`). Теста на
  правило сейчас нет.
- **niko-server** (Hysteria2) не сниффит: соединяется сам, мимо роутера sing-box (`nikoserver/hysteria.go:204-307`).
  Понадобились бы проверка первых 20 байт потока, проверка каждой датаграммы, счётчики через `stats_socket` и
  параметр `options.block_bittorrent`. Конфиг читается с `DisallowUnknownFields` (`nikoserver/config.go:299-301`),
  поэтому raycontrol сначала закрепляет новый релиз (v0.15.0) в `deploy/versions.env`, и только потом render пишет
  поле в `backend.json` (`render.go:1555-1566`). `sniff.UTP` из sing-box (`common/sniff/bittorrent.go:56`) брать
  нельзя: он принимает любой тип пакета uTP, и WireGuard handshake initiation (148 байт, `01 00 00 00 …`) проходит
  у него как uTP (проверено). Это отрезало бы WARP, который [15-traffic](../15-traffic.md) §2 советует вести через
  Hysteria2. Строгая проверка ST_SYN форка Xray (`common/protocol/bittorrent/bittorrent.go:34`) так не ошибается.
- **naive.** В `go.mod` нет ни sing, ни sing-box, а пакет `sniff` тянет `adapter` и `constant`, то есть весь
  sing-box в rayd. Нужен свой разбор, строк 60. CONNECT: первые 20 байт выгрузки на лету, уже после dial (ждать
  байт клиента нельзя: при протоколах, где первым говорит сервер, клиент молчит). UoT: каждый пакет в `send`
  (`internal/naive/uot.go`).
- **SMTP** в процессах проще (в Xray — одно правило `port: 25`), но мест всё равно три.

Итого: три реализации в двух репозиториях и релиз niko-server, а Xray всё равно смотрит только первый пакет сессии.
Ядро — одно место, каждый пакет, и новый процесс data plane попадает под правило по UID сам. Плата: `@ih` нужна от
ядра, политики «на пользователя» нет, supervised-ноды не охвачены.

## 5. Изменения по компонентам

raycontrol:
- store: два ключа `settings` и миграция из §1. API `node/v1`: `GetEgress`, `SetEgress {bittorrent, smtp}`
  (локальный сокет), аудит `egress.set`. rayctl: `rayctl egress`; счётчики показывает только root, как ранние
  отбросы в `rayctl metrics` (`cmd/rayctl/backup.go:204`).
- `perimeter.proto`: `Snapshot.egress = 12`, `message Egress { bool smtp = 1; bool bittorrent = 2; }`; rayd
  заполняет его в `internal/api/perimeter.go:79`.
- perimeter: в `Ruleset` — переход в `egress` и пустые цепочки; `Firewall.SetEgress(smtp, bittorrent)` — `flush
  chain` и правила одной транзакцией nft. Gate применяет политику по снимку и после восстановления таблицы
  (`internal/perimeter/gate.go:268`, `:570`). На relay не применяется: data plane там нет.
- hostcheck (`rayctl check`) и `rayctl egress block` прогоняют цепочку через `nft -c`, как сейчас `Ruleset`
  (`internal/hostcheck/hostcheck.go:213`). Ядро её не берёт — отказ с причиной.
- render: у Xray нет `sniffing` и правила `bittorrent` (`render.go:1199`, `1203`, `1215`, `1440`). Конфиг Xray от
  политики больше не зависит: Xray перезапускается один раз, при обновлении.
- [15-traffic](../15-traffic.md) §1: вместо «BitTorrent режет только Xray» — ссылка сюда.

naive, niko-server (остаётся v0.14.0) и форк Xray — без изменений, у Xray меняется только конфиг. Niko — ничего не
обязательно. Если будет поле в подписке (§9), клиент может показать в сведениях о ноде «закрыты: BitTorrent,
SMTP (25)» и объяснить по нему, почему не качает торрент.

## 6. Счётчики и журналы

- Только счётчики правил nft, по `comment`: `raycontrol_egress_blocked_packets_total{rule="smtp|bittorrent-tcp|
  bittorrent-utp|bittorrent-tracker|bittorrent-dht"}` и `…_bytes_total`. Для TCP пакет ≈ попытка, для UDP —
  датаграмма.
- Ни адресов, ни портов назначения, ни пользователей. В правилах нет `log`, и в окне отладки тоже: строка журнала
  несла бы адрес назначения (P3, [09-observability](../09-observability.md) §2).

## 7. Тесты

- **perimeter** (CI `perimeter`, настоящий nft в network namespace): `TestNetnsEgress` рядом с
  `TestNetnsDataPlaneToNode` (`internal/perimeter/netns_test.go:741`), сокеты под UID через `dialAs` и `sendUDPAs`
  (`:857`, `:839`):
  - политика выключена — проходит всё;
  - `smtp`: 25 по IPv4 и IPv6 — ECONNREFUSED; 465 и 587 проходят; UID 0 проходит;
  - `bittorrent`: рукопожатие — ECONNRESET, пир данных не получает; трекер, uTP SYN (20 и 30 байт), DHT — EPERM, не
    доставлены; WireGuard initiation, QUIC Initial, DNS с EDNS, uTP ST_DATA, HTTP — доставлены;
  - счётчики растут; после `flush ruleset` цепочка возвращается из снимка.

  Эти векторы уже прогнаны вручную (Linux 6.18, nft 1.0.9, netns, UID 9100 и 9150): всё как в списке; IPv6 там не
  было.
- **xray** (CI `xray`, под `unshare -n` от root): `inner` из render (уже без сниффинга), pinned niko-server
  (Hysteria2) и `rayd naive` (CONNECT и UoT) идут под UID из 9110–9179. Назначение — адрес из 198.51.100.0/24 на
  dummy-интерфейсе, этой сети нет в `privateNets` (`render.go:1159`). На каждый профиль: 25 отказывает быстрее 1 с;
  рукопожатие BT сброшено, HTTP идёт; после uTP SYN у Xray UDP-сессия закрыта, у Hysteria2 и naive следующая
  датаграмма доходит.
- **render** (модульный): у Xray нет `sniffing` и правила `bittorrent`; снимок несёт политику. Тесты пробы через
  туннель (`ThroughXray`) должны пройти без сниффинга: имя пробы приходит назначением, а не из SNI (вывод).
- **install** (CI `install`: Debian 12/13, Ubuntu 24.04, Rocky 9/10): `rayctl egress block bittorrent` и `smtp`
  загружаются. Это же проверка `@ih` на каждом ядре.

## 8. Версии

- raycontrol v0.21.0 (номер предварительный): `rayctl egress`, цепочка `egress`, `Snapshot.egress`, Xray без
  сниффинга и правила BitTorrent, миграция `egress_bittorrent=on` для нод с Xray, метрики §6.
- niko-server v0.14.0, Xray `a4a3dff`, Niko — без изменений.
- Нода до v0.21.0: `rayctl egress` нет, BitTorrent режет только Xray, как в [15-traffic](../15-traffic.md).

## 9. Открытые вопросы владельцу

1. Миграция: держать BitTorrent закрытым при обновлении (предложено, §1) или честное «выключено» для всех и строка
   в заметках к релизу?
2. Нужен ли удалённый метод для admin-устройства, как `StartUpdate` в [node-update-v1](node-update-v1.md)?
3. Поле в подписке `egress: {"block": ["bittorrent", "smtp"]}`, чтобы Niko показывал политику?
4. Supervised-ноды: оставить без политики или на них одних вернуть правила в Xray?
5. Другие порты: в v1 только 25. 6881–6889 не закрываем: BitTorrent давно ходит на случайных портах.
