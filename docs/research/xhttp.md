# XHTTP на ноде и relay, CDN как вид relay

Статус: **исследование** на 2026-11-19, для предварительного v0.36.0 (R4-50, E-6). Решения владельца 2026-11-19 — в §8.3,
остальное открыто. Прочитан код: raycontrol `6e8f0e2` (v0.33.0-49); niko-server `01b59f0`; форк Xray `9f1cb15` (ветка
`raycontrol/v26.11.9`). По файлам XHTTP, VLESS и `transport_method.go` он отличается от пина `46b58d4` из
`deploy/versions.env` только тестом `proxy/vless/inbound/userconns_transport_test.go` (короткий путь сокета). Только чтение, возможно, устарело:
форк ядра клиента `arngory/sing-box` `34eaa8c` (2026-11-02) и Niko `bb322e1` (2026-11-06). Текущее ядро клиента новее
(`688d100`, [names-v1](../spec/names-v1.md)), его возможности XHTTP спрашиваются отдельно (§8.4). **Ничего не
запускалось**: ни Xray, ни замеров через CDN.

Обозначения. Ссылки `путь:строка` без префикса — raycontrol. `xray:` — форк Xray, `niko-server:` — фронт, `sing-box:` и
`niko:` — клиент. Короткие имена: `hub.go`, `config.go`, `dialer.go`, `xpadding.go` — `xray:transport/internet/splithttp/`;
`inbound.go` — `xray:proxy/vless/inbound/`; `render.go`, `sub.go`, `server.go` — `internal/render/`, `internal/sub/`.
«(вывод)» — не проверено ни кодом, ни источником. «по выдаче поиска» — страница не открывалась,
сведения из выдачи. «нет данных» в таблицах — не нашёл, не догадка.

## 1. Итог на одной странице

| № | Что | Где | Размер | Когда |
|---|---|---|---|---|
| 1 | **Форма A: XHTTP поверх REALITY.** Свой сервис со своим именем за фронтом (PROXY v2), режим `stream-one`, XMUX у клиента. Это «REALITY с mux», и через relay он идёт как REALITY | нода, клиент | S–M | v0.36.0 (предварительно; владелец, 2026-11-19) |
| 2 | **Форма B: XHTTP на своём имени с настоящим сертификатом.** TLS завершает новый `rayd xhttp`, как у naive и DoH. Секретный путь (лучше — токен устройства в пути) проксируется в Xray по unix-сокету (h2c). Остальным — ответ сайта | нода, клиент | M | v0.37.1 (владелец, 2026-11-19; с v0.37.0 сдвинута 2026-11-24) |
| 3 | **CDN как вид relay.** Только для формы B. Отдельный профиль для проверок (владелец, 2026-11-19). Без SPA и без замера. Источник для CDN — relay (адрес выхода CDN не видит) или выход. Доступ к источнику: подсети CDN, отдельный порт, секретный заголовок, где можно — mTLS. Режим по умолчанию — `packet-up` | нода, relay, клиент | L | после замеров (их владелец попробует устроить), не раньше v0.37.1 |
| 4 | Подписка через CDN не ходит. Её берут напрямую, через relay или **внутри туннеля** (имя замера → эндпоинт подписки на loopback). Это уже работает | — | 0 | есть |

Главное:
- **Содержимое CDN не видит.** У ссылок VLESS Encryption с ML-KEM-768 (`sub.go:776-795`). Сервер делает рукопожатие
  шифрования до чтения заголовка VLESS (`xray:proxy/vless/inbound/inbound.go:288-292`). CDN, который завершает TLS,
  видит HTTP-запросы с шифротекстом: ни UUID, ни назначений, ни данных. Видит он метаданные (§5.3).
- **CDN не лечит заморозку TCP, если CDN сам под ней.** В 2025 году её описывали как ~16 КБ, по замеру 2026-11 она
  считает пакеты: ~25 дома, ~8 на мобильном (§5.6). Cloudflare резали с 2025-06-09
  ([блог Cloudflare](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/)). В
  замере 2026-11-05/06 (один город) все 36 попыток к сайтам на Cloudflare прошли, дома и на мобильном
  ([Habr 1104904](https://habr.com/ru/articles/1104904/)). Счётчик пакетов идёт на соединение, а XMUX держит
  соединения долго: под счётчиком XHTTP напрямую к зарубежному адресу не поможет (вывод).
- **Кандидаты CDN** (§6): Cloudflare — по возможностям лучший и уже знаком ноде (DNS, токен). Amazon CloudFront — второй
  международный. Отечественный (Selectel, Yandex Cloud CDN) — только опыт для режима белых списков, с правовым риском.
  Пропускают ли их адреса белые списки, никто не мерил.
- **Мешает в нашем коде** (§3.4, §5.2): сайт не стоит за фронтом напрямую (до него доходят только через REALITY); naive и DoH
  требуют `X25519MLKEM768`, а большинство CDN к источнику так не ходят; в периметре нет набора «подсети CDN на один
  порт»; relay-v1 заморожен, и `relays[]` без `spa` старый клиент не поймёт; рендер строит процесс Xray на сервис; учёт
  трафика знает только `inner` и `reality` (§3.4); тесты форка не покрывают XHTTP; у клиента нет `downloadSettings`.
- **Решение владельца 2026-11-24:** формы A и B — в v0.37.1; v0.37.0 — память и ревью протоколов (roadmap).
- **Решения владельца 2026-11-19** (§8.3): форма A — предварительно v0.36.0, форма B — v0.37.0; CDN — отдельный профиль
  для проверок, на его участках CDN допустим TLS без PQ, если VLESS Encryption с ML-KEM идёт из конца в конец и нет
  лишних накладных расходов; замеры из российских сетей владелец попробует устроить; порядок профилей в подписке не
  меняется (REALITY первым).

## 2. XHTTP в нашем форке Xray: что важно дальше

- **Сервер.** Слушает TCP или unix-сокет. С TLS или REALITY оборачивает слушатель, иначе принимает открытый HTTP/1.1 и
  h2c (`xray:transport/internet/splithttp/hub.go:530-583`). На unix-сокете без TLS он годится за нашим собственным
  прокси. HTTP/3 — только свой UDP-сокет в quic-go (`hub.go:469-527`). Принять датаграммы от udpmux (режим `packet`,
  наш IPC) он не может (вывод).
- **PROXY v2** на любом транспорте даёт `sockopt.acceptProxyProtocol` (`xray:transport/internet/system_listener.go:180-182`):
  форма A встаёт за фронт так же, как REALITY.
- **Проверки в `ServeHTTP`:**
  - чужой `host` или путь — пустой `404` (`hub.go:97-107`);
  - неверный паддинг — `400` (`hub.go:145-151`); пустой паддинг неверен всегда (`xray:.../xpadding.go:307-310`);
  - всякий ответ после проверки host и пути, и `400` тоже, несёт `Access-Control-Allow-Origin` (`*`, если в запросе нет
    `Origin`, иначе его значение) и `X-Padding` (`xray:.../config.go:99-131`, `hub.go:110`, `:128`);
  - поток вниз (GET, `stream-one`) ещё несёт `X-Accel-Buffering: no`, `Cache-Control: no-store` и, без `noSSEHeader`,
    `Content-Type: text/event-stream` (`hub.go:352-370`).
- **Режимы.** `stream-one` — один POST в обе стороны. `stream-up` — потоковый POST вверх и GET вниз. `packet-up` — GET
  вниз и POST-пакеты вверх с номером. Клиент в `auto` выбирает `packet-up`, под REALITY — `stream-one`, а под REALITY
  с `downloadSettings` — `stream-up` (`xray:.../dialer.go:332-340`). В
  [обсуждении 4113](https://github.com/XTLS/Xray-core/discussions/4113) написано, что TLS h2 в `auto` даёт `stream-up`.
  Код этой версии говорит иначе. Аплинк методом GET возможен только в `packet-up` (`xray:infra/conf/transport_method.go:389-390`),
  с данными в заголовках или cookie. Это важно для отечественных CDN: у Yandex и VK POST по умолчанию закрыт и открывает
  его поддержка, у Selectel — сам владелец ресурса (§6.1).
- **Ресурсы до аутентификации.** Сессия XHTTP заводится по id из запроса (`hub.go:184-187`). Она живёт 30 с без GET
  (`hub.go:57-95`) и копит до `scMaxBufferedPosts` (30) пакетов по `scMaxEachPostBytes` (1 МБ) (`xray:.../config.go:140-168`).
  Это не предел памяти: тело POST читается в память до постановки в очередь (`hub.go:290-303`), а при полной очереди
  запрос ждёт (`xray:.../upload_queue.go:40-52`). Сессия держит 30 МБ в очереди и ещё по 1 МБ на каждый ждущий запрос,
  пока её не снимет таймер 30 с. Всё это до рукопожатия VLESS Encryption и до UUID. Пределы пользователя (conn-limit-v1) это не считают: у них ключ —
  пользователь после аутентификации. Кто знает путь, тот и тратит память (вывод из кода).
- **Keepalive.** Только ответ на `stream-up` шлёт паддинг раз в `scStreamUpServerSecs` (20–80 с). И то лишь когда в
  запросе есть любой непустой `Referer` (туда клиент кладёт паддинг) или принят паддинг obfs (`hub.go:220-233`). CDN,
  который срезает `Referer`, без obfs выключает и его. Поток вниз (GET) пустых данных не шлёт. CDN с тайм-аутом простоя
  рвёт простаивающий туннель (§5.5).
- **XMUX** — только у клиента. Если в конфиге нет ни одного поля `xmux`, ставится `maxConnections` 3,
  `hMaxRequestTimes` 600–900, `hMaxReusableSecs` 1800–3000 (`transport_method.go:459-469`). Если задано хоть одно поле,
  остальные теряют умолчания ([4113](https://github.com/XTLS/Xray-core/discussions/4113); в коде — проверка
  `c.Xmux == (XmuxConfig{})`). Значит, рендер должен задавать все поля. В 4113 умолчание названо `maxConcurrency`
  16–32; код этой версии говорит иначе.
- **Паддинг XHTTP.** По умолчанию 100–1000 байт (`xpadding.go:179-188`). Клиент кладёт его в query заголовка `Referer`
  с ключом `x_padding` (`config.go:301-320`). Имена постоянные: это подпись, видимая CDN. CloudFront по умолчанию
  `Referer` удаляет (§6.1). Без `Referer` сервер ищет `x_padding` в query самого URL (`xpadding.go:256-266`), но клиент по
  умолчанию его туда не кладёт: ответ — `400`. Режим `xPaddingObfsMode` задаёт свои место, ключ и заголовок.
- **Vision.** Пользователя с `flow: xtls-rprx-vision`, пришедшего без flow, не пускают с командой TCP и с Mux без XUDP;
  команду UDP пускают (`inbound.go:619-623`). С VLESS Encryption Vision работает и поверх не-RAW транспорта: соединение —
  `encryption.CommonConn`, splice выключен (`inbound.go:596-612`). Автор Xray для CDN советует связку «VLESS Encryption +
  XTLS Vision + XHTTP XMUX» ([PR 5067](https://github.com/XTLS/Xray-core/pull/5067)). Тезис вводных «XHTTP — без Vision»
  верен только без шифрования. У нас шифрование есть везде. Значит, у сервиса XHTTP два варианта клиентов: с Vision
  поверх VLESS Encryption или без flow. Клиент: Vision поверх XHTTP с шифрованием — да по коду, подтвердит interop
  (§8.4, п. 3). Свой inbound нужен в обоих случаях: у XHTTP другой транспорт.
- **VLESS Encryption.** У нас `mlkem768x25519plus.native.600s.<seed>` на сервере и `...native.0rtt.<ключ>` в ссылке
  (`render.go:1392-1399`). По [PR 5067](https://github.com/XTLS/Xray-core/pull/5067):
  - `native` — не случайный вид, видны признаки открытого ключа и заголовок, похожий на запись TLS 1.3;
  - `xorpub` убирает признаки ключей, `random` даёт вид случайных байт;
  - 0-RTT защищён от повтора: сервер помнит ключи 10 минут. Билет живёт до перезапуска сервера или до срока из
    конфига: при `600s` — случайно 300–600 с (`xray:proxy/vless/encryption/server.go:271-276`);
  - паддинг рукопожатия — только у 1-RTT.

## 3. Как устроены формы на ноде

### 3.1. Форма A: XHTTP поверх REALITY

```
клиент ─TLS(REALITY, своё имя)─▶ фронт tcpmux ─PROXY v2, unix─▶ Xray: REALITY → h2c → XHTTP → VLESS(+ML-KEM) → выход
                                             (чужой ClientHello → REALITY → сайт, как сейчас)
```

| | Что |
|---|---|
| Фронт | Своё имя → бэкенд `proxy-v2`, как у REALITY (`niko-server:nikoserver/tcpfront.go:160-161`, `:187-216`). Неизвестное имя по-прежнему уходит в первый REALITY (`render.go:998`) |
| Xray | Новый вид сервиса (например, `xhttp-reality`), свой процесс: рендер строит процесс Xray на сервис (`xrayFile`, `render.go:1460-1467`). Второй inbound в процессе бывает только у REALITY в период перекрытия ключей (`render.go:1730-1732`). Inbound — как `realityInbound` (`render.go:1738-1764`), но `network: "xhttp"`, `xhttpSettings` с путём и `mode: "stream-one"`. Свои ключи REALITY, ML-DSA-65, зерно ML-KEM, shortId. Цель — сайт (self-steal), имя — под сертификатом сайта (R2-12, R4-7). Клиенты — с Vision поверх VLESS Encryption или без flow (§2); клиент по коду умеет Vision, выбор — после interop (§8.4, п. 3) |
| Режим | `stream-one` (так выбирает и `auto`). `downloadSettings` не нужен |
| XMUX | В ссылке (`extra.xmux`) — все поля явно: `maxConnections` 1–2, `hMaxRequestTimes` и `hMaxReusableSecs` — диапазоны из случайных параметров установки (architecture.md, «Случайные параметры установки»), `hKeepAlivePeriod` 0 (Chrome, 45 с; `dialer.go:248-249`, `xray:common/net/net.go:20`). Поток h2 у сервера ограничен 250 стримами (Go по умолчанию; у Xray — если не задан `h2Params`, `hub.go:559-576`) |
| Паддинг | `xPaddingObfsMode` со случайными для установки заголовком и ключом. Паддинг VLESS Encryption — как сейчас |
| UDP | VLESS UDP и XUDP через ту же сессию. Без flow команда UDP разрешена, с Vision — только через XUDP (`inbound.go:589-594`). Клиент по умолчанию шлёт UDP поверх XHTTP обычным запросом VLESS, XUDP — только с `packetEncoding=xudp` в ссылке (§8.4): с Vision ссылка должна его нести (вывод). Head-of-line, как у REALITY; совет из [traffic.md](../design/traffic.md) §2 (отклонять QUIC) в силе |
| Relay | L4: TCP 443 к выходу ([relay-v1](../spec/relay-v1.md) §2). Имя relay — в `serverNames` (names-v1 §7) |
| Цена | Мала: тот же путь, что REALITY. Ротация ключей и имени по R4-7 — та же машина, но второй экземпляр |

Что даёт по сравнению с REALITY + Vision: mux (R4-50) без смены маскировки. Вместо соединения TCP на каждое
проксируемое соединение — 1–2 долгих соединения h2. Чего не даёт: защиты от счётчика пакетов на соединение (§5.6).

### 3.2. Форма B: XHTTP на своём имени, TLS в `rayd`

```
клиент или CDN ─TLS(своё имя, сертификат сайта)─▶ фронт tcpmux ─fd─▶ rayd xhttp ─┬─ путь/токен верен → h2c, unix → Xray: XHTTP → VLESS(+ML-KEM)
                                                                                  └─ иначе → ответ сайта (404 / 403 / silent)
клиент ─QUIC(своё имя)─▶ фронт udpmux ─packet─▶ rayd xhttp (h3, internal/h3serve) ─▶ тот же прокси
```

| | Что |
|---|---|
| Фронт | Имя → `fd`, как naive и DoH (`render.go:841-880`, `niko-server:nikoserver/tcpfront.go:154-159`). QUIC — `packet`, как naive-quic |
| TLS и HTTP | Тот же код, что у сайта, naive и DoH: `site.HTTPServer` (одинаковые SETTINGS h2 для всех имён, `internal/site/http2.go:44-68`), сертификат сайта с перечитыванием. Для CDN — TLS как у сайта (TLS 1.2+, любая группа, `internal/site/server.go:74-80`): CDN почти везде ходит к источнику без ML-KEM. Исключение — Cloudflare: [он предлагает X25519MLKEM768, если источник умеет](https://blog.cloudflare.com/automatic-key-exchange-for-origins/). Постквант даёт VLESS Encryption; TLS без PQ на участках CDN допустим только в профиле CDN (§8.3, Р1) |
| Доступ | Секретный путь на сервис или, лучше, **токен устройства в пути**, как у DoH с v0.27.0 (R4-37): `rayd` проверяет токен, срезает его и шлёт запрос в один внутренний путь Xray. Утечка пути — отзыв одного устройства. До Xray доходят только держатели токена, а это и есть защита ресурсов до аутентификации (§2) (вывод) |
| Прокси | `httputil.ReverseProxy` с `FlushInterval: -1`, к Xray по h2c на unix-сокете. Тело запроса не буферизуется. Ответы Xray `4xx` (`400` паддинга, `404` пути) заменяются ответом сайта: знающий путь зонд не отличит XHTTP по кодам (вывод) |
| Xray | Свой процесс, inbound XHTTP без TLS на unix-сокете (`hub.go:530-583`), VLESS с `decryption`, клиенты без flow |
| Режим | Напрямую — `auto` (у клиента это `packet-up`) или `stream-up`. Через CDN — `packet-up` (§5.1) |
| XMUX | Как в форме A. Для CDN — свой набор в ссылке края (§5.1) |
| Пин | Напрямую — `niko-pin` по [cert-pin-v1](../spec/cert-pin-v1.md), как у naive: сервис отвечает сертификатом сайта. Через CDN — без пина: TLS кончается на CDN (§5.3) |
| Relay | L4, как naive. Имя relay × сервис — по names-v1 §9 п. 2 |
| Цена | Новый процесс `rayd xhttp` (или ветка в `rayd naive`), рендер, ссылки, тесты |

Чем B хуже naive напрямую: у naive клиент — настоящий Chromium (cronet), у XHTTP — свой клиент ядра. Клиент подтвердил
uTLS только для REALITY; какой отпечаток TLS у XHTTP с обычным TLS — вопрос §8.4, п. 10 (вывод: не Chromium). Своя
ценность B — **CDN**. Напрямую B нужен как запасной путь и для проверки источника без CDN.

### 3.3. Другие формы

| Форма | Вывод |
|---|---|
| XHTTP на секретном пути самого сайта (через fallback REALITY: фронт → REALITY → сайт → Xray) | Не делать. Три копии байтов. REALITY становится входом трафика CDN. Имя сайта (оно же SNI REALITY) попадает в настройки CDN: CDN знает имя и адрес REALITY. Сайт живёт с `PrivateNetwork=yes` (R2-12), unix-сокет ему доступен, но смысла нет |
| Xray сам завершает TLS (XHTTP + TLS в Xray, бэкенд `proxy-v2`) | Проще кода, но: TLS и SETTINGS h2 не те, что у сайта, naive и DoH (у нас они выровнены, `cmd/rayd/h2alike_test.go`); свой перечитыватель сертификата; на чужой путь — `404` Xray, а не ответ сайта. Только если B окажется дорогим |
| XHTTP/3 в Xray (`alpn: h3`) | Автор Xray: «目前不建议你这样做» — пока не советует, лучше за настоящим Nginx или Caddy ([4113](https://github.com/XTLS/Xray-core/discussions/4113)). Нам и не нужно: h3 даёт `rayd` формы B на том же quic-go, что naive-quic и DoH3 (их QUIC выровнен, `TestQUICNamesLookAlike`) |
| `downloadSettings`: вверх и вниз разными путями (например, вверх через relay, вниз через CDN) | Сильный инструмент против заморозки, если CDN вниз не мёрзнет. Но у клиента нет: «we don't support asymmetric transport» (`sing-box:transport/v2rayxhttp/client.go:299-301`), Niko выкидывает поле с предупреждением (`niko:.../fmt/v2ray/XHTTP.kt:102-105`). Вопрос клиенту (§8.4) |
| `cloudflared` (туннель Cloudflare) на выходе | Вид доступа к источнику, а не форма (§5.2) |

### 3.4. Что меняется в нашем коде

- **Рендер.** Новый вид в `XrayKinds` (`render.go:500`), ветки в `XrayUsers` и `XrayTags` (`render.go:521-531`,
  `:1664-1672`). Клиенты — без flow (`xrayClients(m, s, "")`) или с `RealityFlow`, если interop подтвердит Vision поверх
  XHTTP (§2, §8.4 п. 3). Тот же выбор — в синхронизации пользователей: `flow` берётся по виду сервиса
  (`internal/live/live.go:371-374`). `inbound` для формы A — на основе `realityInbound`, для B —
  на unix-сокете без TLS. Маршрут фронта: A — `proxy-v2`, B — `fd` и `packet`. Конфиг `rayd xhttp`: путь Xray, токены,
  ответ сайта.
- **Ссылки** (`internal/sub`). `vless://…?type=xhttp&security=reality|tls&path=…&mode=…&extra=<JSON>`. Niko уже читает
  `type=xhttp`, `mode` и `extra` с известными ядру ключами (`niko:.../fmt/v2ray/XHTTP.kt:7-35`, `V2RayFmt.kt:255`).
  Строгий разбор подписки (R4-31, `TestLinksForStrictClient`) надо проверить на `type=xhttp`.
- **Замер через туннель.** Новый вид — в `ProbeTunnels` (`sub.go:222`). Правило имени замера в Xray уже стоит в
  `xrayFile` (`render.go:1478-1485`).
- **Пределы соединений.** Пользовательские пределы форка работают по пользователю внутри процесса. Реестр — один на
  процесс ([conn-limit-v1](../spec/conn-limit-v1.md) §3.3). Новый процесс — новый бюджет пользователя, как у пары
  `inner` и REALITY сейчас. Каждая сессия XHTTP — своё соединение VLESS, и пределы считают его, как соединение REALITY
  (вывод). XMUX уменьшает только входящие TCP. Новое — ресурсы до аутентификации (§2): в B их держит токен `rayd`, в
  A — REALITY.
- **Учёт трафика.** В Xray без изменений: счётчики пользователя — в диспетчере, по полезной нагрузке, независимо от
  транспорта (`xray:app/dispatcher/default.go:163-208`). Заголовки, паддинг и кадры h2 в счёт не идут, как и сейчас
  ([traffic-limit-v1](../spec/traffic-limit-v1.md) §1). **В `rayd` — изменение:** источники счётчиков перечислены по видам
  (`internal/traffic/traffic.go:83-97`, `Processes`): случаи `inner` и `reality`, ветки по умолчанию нет. Новый вид без
  своего случая не читается вовсе, и лимит трафика (traffic-limit-v1 §2.1) на нём не действует. Нужен случай для
  каждого нового вида, тест на это и строка в traffic-limit-v1 §2.1.
- **Отзыв пользователя.** `RemoveUser` форка закрывает «сырое» соединение. Для XHTTP это сессия (`splitConn`):
  `UnwrapRawConn` её не разворачивает (`xray:proxy/proxy.go:691-720`). Сессия закрывается, а соединение h2 XMUX живёт до
  простоя, уже без потоков (вывод). Тесты форка (`userconns_transport_test.go`) XHTTP не покрывают, их нужно добавить.
- **Периметр** — только для CDN (§5.2).

### 3.5. Relay

Обе формы — TCP 443, relay-v1 их пересылает без изменений (ядро, DNAT). Через relay на 443 доступен и QUIC, а значит
h3 формы B. Свои имена relay — по names-v1 §9 п. 2 (v0.35.0). Ключей на relay нет, как и прежде.

### 3.6. Отпечатки: против REALITY + Vision

| | REALITY + Vision | Форма A | Форма B напрямую | Форма B через CDN |
|---|---|---|---|---|
| Что видит наблюдатель на пути | SNI нашего имени, TLS к адресу ноды | то же | SNI своего имени, TLS к адресу ноды | SNI имени на CDN, TLS к адресу CDN |
| Соединения | TCP на каждое проксируемое соединение | 1–2 долгих h2 (XMUX) | так же | так же, до края CDN |
| TLS в TLS | Vision паддит рукопожатия | без Vision видны длины внутренних рукопожатий; с Vision поверх VLESS Encryption — паддинг есть (§2) | так же | так же, но видит это и CDN |
| Активный зонд | REALITY отдаёт сайт | так же | ответ сайта (`404` по умолчанию), как у naive и DoH | то же, через CDN |
| Журналы CT | имя под сертификатом сайта | так же | так же (wildcard прячет имя, R4-42) | имя на CDN — в CT CDN |
| Адрес ноды | виден | виден | виден | скрыт за CDN или relay |
| Счётчик пакетов на соединение (§5.6) | мёрзнет | мёрзнет, и долгий XMUX хуже | мёрзнет | зависит от CDN |

Общее для XHTTP: постоянные имена (`x_padding`, `X-Padding`, CORS `*` на запрос без `Origin`, `text/event-stream`) видны тому, кто снял TLS:
CDN или прокси владельца. Для CDN их убирает режим obfs. Сообщения на ntc.party о том, что XHTTP + REALITY разом
перестал работать у всех провайдеров, есть по выдаче поиска, но страница из сессии не открылась (сайт закрыт сетью
сессии). Это не свидетельство.

### 3.7. Тесты в CI

- **Модульные:** рендер (golden) обеих форм, ссылки и строгий разбор, набор CDN в периметре, токены `rayd xhttp`.
- **Задача `xray` в `ci.yml`** (уже собирает форк и niko-server, `XRAY_BIN`, `.github/workflows/ci.yml:118-176`). По
  образцу `TestRealitySelfStealWithXray` (`internal/xrayapi/xray_test.go:511`): настоящий фронт, сервер и клиент Xray.
  - A: `stream-one`; отказ без REALITY уходит сайту.
  - B: `packet-up`, `stream-up`, `stream-one`, h1 и h2, h3 через udpmux; неверный путь или токен — ответ сайта.
  - Клиенты с Vision поверх VLESS Encryption и без flow (§2).
  - Пользователь: добавлен, удалён (сессия закрыта), предел, счётчики трафика (новый вид в `traffic.Processes`, §3.4).
- **Эмулятор CDN** в тесте: обратный прокси на Go, который ведёт себя как CDN:
  - h1 к источнику;
  - буферизует тело запроса целиком;
  - срезает `Referer` и меняет `User-Agent`, как CloudFront по умолчанию;
  - рвёт ответ после N с простоя;
  - добавляет секретный заголовок или клиентский сертификат.

  Ожидается: `packet-up` работает, `stream-up` при буферизации висит, keepalive спасает только `stream-up`.
- **relay:** `test/relay/e2e.sh` (три пространства имён) — A и B через relay; эмулятор CDN с relay в роли источника.
- **Interop с Niko:** `raycontrol-interop.yml` клиента, как для REALITY и naive.
- **Ночная проверка на настоящем CDN** — по образцу идеи из [review.md](review.md) (ночная задача с токеном Cloudflare).
  Нужны секреты; решение владельца.

## 4. Почему именно так: ответы на вводные

- «Ссылки несут VLESS Encryption, CDN не увидит VLESS». Подтверждено: `sub.go:776-795` (REALITY), `render.go:1392-1399`.
  Рукопожатие — до заголовка VLESS (`inbound.go:288-292`). Ограничения: `native` узнаваем (PR 5067), метаданные
  видны (§5.3).
- «hub.go принимает HTTP/1.1 и h2c на unix-сокете, ~530-567». Да, `hub.go:530-583`.
- «dialer.go:333-339 выбирает stream-one под REALITY». Да, `dialer.go:332-340`.
- «Умолчания XMUX». Да, `transport_method.go:462-469`; в 4113 написано иное (§2).
- «Vision только с raw TLS/REALITY». Только без VLESS Encryption (§2).
- «Cloudflare рвёт ответ без данных через 100 с». Так в [4113](https://github.com/XTLS/Xray-core/discussions/4113), по
  опыту автора. Документация Cloudflare: Proxy Read Timeout — 125 с, у Enterprise до 6000 с
  ([524](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/)).
- «С 2025-06-09 Cloudflare режут до ~16 КБ, задеты Hetzner, DigitalOcean, OVH». Да
  ([блог Cloudflare](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/)). Новее (§5.6):
  - замер 2026-11-05/06: заморозка идёт по числу пакетов (~25 дома, ~8 у Билайна и МТС), а не байтов; целиком
    заморожены сети OVH, Hetzner, DigitalOcean, Vultr, Scaleway, M247 и другие; адреса Cloudflare в этот раз прошли
    ([Habr 1104904](https://habr.com/ru/articles/1104904/),
    [пересказ Men Today](https://www.mentoday.ru/technics/news/11-11-2026/saity-zagrujayutsya-napolovinu-v-rossii-nachalas-blokirovka-zarubejnyh-hostingov-celymi-podsetyami/));
  - тред [net4people 490](https://github.com/net4people/bbs/issues/490) — с 2025-06-27 по октябрь 2026.

## 5. CDN как вид relay

### 5.1. Как ложится на relay-v1

[relay-v1](../spec/relay-v1.md) заморожен. Relay в нём — L4-узел со своим SPA и замером. Клиент берёт ту же ссылку,
меняет хост на relay и стучится к нему (§4). CDN другой:

| | relay-v1 | край CDN |
|---|---|---|
| Уровень | L4, TLS сквозной до выхода | L7, TLS кончается на CDN |
| SPA | своё | нет: CDN не стучится |
| Замер `probe-v1` | свой эндпоинт | нет; замер — через туннель (имя замера) |
| Пины | сквозные | `niko-pin` неприменим; сервер удостоверяет ключ ML-KEM в `encryption` ссылки (вывод) |
| Профили | REALITY, Hysteria2, naive | только форма B (XHTTP с TLS). naive CDN не проводит: CONNECT не поддерживается ([naive-sni-rotation.md](naive-sni-rotation.md), §4) |
| Ссылка | та же, хост — relay | другой хост, SNI и `Host`; путь и `encryption` те же; режим `packet-up` и свой `xmux` |

Варианты в подписке:
1. **Отдельный профиль** со своей полной ссылкой (хост — имя на CDN, без `niko-pin`) и пометкой края для показа.
   Старый клиент видит обычную строку `type=xhttp`. Клиенту нужен только разбор XHTTP. Рекомендую начать так.
   **Владелец 2026-11-19:** путь через CDN — отдельный профиль для проверок. Порядок профилей в подписке не меняется:
   REALITY первым, XHTTP и край — после него.
2. **Вид relay в подписке.** Новые записи (`edges[]` или `relays[]` с `kind: "cdn"`) и `profiles[].via`. Они идут только
   клиенту, который заявил `X-Raycontrol-Features: cdn`, по образцу names-v1 §4. Старый клиент, увидев `relays[]` без
   `spa`, начал бы стучаться в никуда (вывод). Это даёт детектору белых списков (relay-v1 §5) выбирать край как relay.
   Поле `path` в отчёте замера — новое значение `cdn`.

Набросок второго варианта (для обсуждения с клиентом):

```json
"edges": [{"id": "e1", "kind": "cdn", "host": "static.example.net", "alpn": ["h2", "http/1.1"],
           "xhttp": {"mode": "packet-up", "extra": {"xmux": {"maxConnections": "2-4", "...": "…"}}}}],
"profiles": [{"svc": 7, "name": "xhttp", "link": "vless://…type=xhttp&security=tls…", "via": ["r1"], "edges": ["e1"]}]
```

Через край идут только профили формы B. DNS-туннели, Yggdrasil, REALITY, Hysteria2 и naive — нет.

### 5.2. Доступ к источнику

Источник закрыт SPA, а CDN стучаться не умеет. Варианты:

| Вариант | Как | Плюсы | Минусы |
|---|---|---|---|
| Подсети CDN | Набор подсетей CDN, без SPA | просто; у CDN есть списки: Cloudflare, [управляемый список CloudFront для источников](https://aws.amazon.com/blogs/networking-and-content-delivery/limit-access-to-your-origins-using-the-aws-managed-prefix-list-for-amazon-cloudfront) (по выдаче поиска), метки служб Azure ([FAQ](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq)) | Подсети общие для всех клиентов CDN. Cloudflare прямо пишет, что общий сертификат AOP доказывает лишь «coming from the Cloudflare network» ([AOP](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)). Значит, порт открыт любому, у кого есть аккаунт этого CDN (вывод). Списки меняются |
| + отдельный порт | Подсети CDN пускаются только на свой порт источника. На нём только `rayd xhttp` (B), а не 443 со всеми именами | Через CDN нельзя прощупать REALITY, naive и остальное | Порт задаётся в CDN: Cloudflare — Origin Rules, «Destination port», на всех тарифах ([Origin Rules](https://developers.cloudflare.com/rules/origin-rules/)); CloudFront — 80, 443 или 1024–65535 ([Origin settings](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesOrigin.html)). gRPC Cloudflare требует источник на 443 ([gRPC](https://developers.cloudflare.com/network/grpc-connections/)): с отдельным портом gRPC отпадает (§7.1, п. 4). Порт сам по себе — отпечаток (вывод) |
| + секретный заголовок | CDN добавляет заголовок, `rayd` сверяет его до всего остального | Есть почти везде: CloudFront — «Add custom header», Cloudflare — Transform Rules ([совет Cloudflare](https://developers.cloudflare.com/learning-paths/prevent-ddos-attacks/advanced/prevent-external-connections/)) | Секрет — в настройках CDN и на каждом запросе. Это ровно то, что CDN и так видит |
| + mTLS от CDN | CDN предъявляет клиентский сертификат, `rayd` требует его на этом имени | Сильнее всего | Cloudflare: AOP per-hostname или zone со своим сертификатом. CloudFront — с 2026-01: сертификат клиента импортируется в ACM, проверяет его источник ([origin mTLS](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-mtls-authentication.html), [анонс](https://aws.amazon.com/about-aws/whats-new/2026/01/amazon-cloudfront-mutual-tls-for-origins), по выдаче поиска). Фраза «CloudFront drops the request» на [странице поведения](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html) — о случае без настроенного mTLS. У остальных — нет данных |
| Туннель вендора (`cloudflared`) | Источник сам подключается к Cloudflare. Входящего порта нет | SPA не меняется | Чужой бинарник и аккаунт на выходе. Исходящие к Cloudflare видны сети выхода. AOP с туннелем несовместим. gRPC через туннель — только для частных подсетей, «Public hostname deployments are not currently supported» ([gRPC](https://developers.cloudflare.com/network/grpc-connections/)). Как туннель передаёт потоковое тело XHTTP — нет данных |
| **Relay как источник** | Источник для CDN — адрес relay. Relay пускает подсети CDN на порт края и делает DNAT к выходу. Выход пускает relay, как сейчас (`relay4`, `relay_ports`, `internal/perimeter/firewall.go:206-208`, `:294-295`) | CDN не знает адреса выхода. TLS сквозной до выхода. Relay ключей не держит. Потерю relay лечит `rayctl relay remove` | Лишний хост и хоп. Адрес relay известен CDN. Нужен новый вид пересылки в снимке relay: публичный порт для подсетей, без SPA |

Рекомендация: **relay как источник + отдельный порт + подсети CDN + секретный заголовок**. mTLS — где CDN умеет
(Cloudflare, CloudFront). Цена отдельного порта у Cloudflare — без gRPC (§7.1, п. 4).
`cloudflared` — только если владелец согласен на чужой бинарник на выходе.

Что нужно в периметре (вывод):
- набор `cdn4`/`cdn6` с `flags interval` и набор портов `cdn_ports`, по образцу `integ4` (`firewall.go:203-205`, `:301-302`);
- предел на адрес: в `in_limit` 50 SYN/с на IPv4 (conn-limit-v1.md:448) задушит край CDN, через который идут сотни
  клиентов. Нужен свой предел или исключение, как у relay (conn-limit-v1.md:475-477);
- откуда брать подсети. Списки `cdn-<провайдер>.txt` из rules-v1 по спецификации в nftables не идут («nftables ноды ...
  их пропускают», rules-v1.md:111-113) и описывают подсети края. Подсети, из которых CDN ходит к источнику, бывают
  другими (у CloudFront — отдельный список). Нужен свой подписанный список «подсети CDN к источнику» или поле в
  rules-v1.

### 5.3. Что видит CDN

| Видит | Не видит |
|---|---|
| адрес клиента, его TLS ClientHello и SETTINGS h2 | UUID: он внутри VLESS Encryption |
| имя на CDN, путь (секрет или токен), id сессий и номера пакетов | назначения, DNS, содержимое |
| время, размеры и число запросов и ответов, паддинг | ключи: AEAD не подделать, повтор 0-RTT отбивается ([PR 5067](https://github.com/XTLS/Xray-core/pull/5067)) |
| все заголовки, в том числе секретный | — |
| шифротекст VLESS Encryption; в `native` по нему узнаётся VLESS Encryption ([PR 5067](https://github.com/XTLS/Xray-core/pull/5067)) | — |
| адрес источника (выхода, или relay в рекомендуемом варианте) | адрес выхода — если источник relay |

Отсюда (вывод):
- CDN — участник с полными метаданными. Отечественный CDN подчиняется российскому праву (§6.3).
- Для профиля края — `xorpub` или `random` в VLESS Encryption, если клиент их умеет (§8.4).
- Подделка сертификата на участке «клиент — CDN» (модель угроз names-v1 §1) даёт противнику ровно то же, что видит CDN:
  ключ ML-KEM в `encryption` удостоверяет выход.

### 5.4. Подписка

Через CDN подписка не идёт: CDN увидел бы `X-Raycontrol-Device`, токен `RC1` и ответ. Пути у неё уже есть:
- напрямую или через relay за SPA;
- **внутри туннеля**. Клиент обращается к имени замера, Xray ведёт его к эндпоинту подписки на loopback
  (`render.go:1478-1485`, probe-v1 §1.1). Подписка на loopback обслуживается, только без подсказок (`internal/sub/server.go:448`).
  У CDN тогда — лишь шифротекст VLESS Encryption, внутри которого TLS с пином.

Для режима, когда работает только CDN, этого достаточно (вывод). Новый вид сервиса — в `ProbeTunnels`.

### 5.5. Отказы

| Отказ | Что видит клиент | Что делать |
|---|---|---|
| CDN закрыл аккаунт или сервис (ToS) | край не отвечает | другой путь: напрямую, relay, другой край; несколько CDN |
| Адреса CDN режут или морозят в стране клиента | соединение замирает (не рвётся) после ~25 пакетов, на мобильном ~8 (§5.6) | детектор пути; край — не единственный путь |
| Простой потока вниз дольше тайм-аута CDN: GET без данных, keepalive в Xray нет (§2) | простаивающее соединение приложения рвётся | брать CDN с длинным тайм-аутом или договориться; keepalive внутри VLESS Encryption — вопрос к Xray (§8.5) |
| CDN буферизует тело запроса | `stream-up` и `stream-one` висят | `packet-up` по умолчанию |
| CDN срезает заголовки (CloudFront по умолчанию — `Referer`) | `400` паддинга; keepalive `stream-up` тоже выключен (§2) | переслать `Referer` политикой запроса к источнику, где CDN это умеет (CloudFront — да); иначе `xPaddingObfsMode` с заголовком, который CDN пропускает |
| CDN кеширует GET (CloudFront кеширует GET и HEAD всегда, [поведение](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html)) | ломаются сессии (вывод) | политика без кеша; Xray и так шлёт `no-store` |
| Подсети CDN к источнику сменились | край не открывается | обновлять список по расписанию, по образцу ротации |
| Отказ relay-источника | край не открывается | несколько relay-источников в CDN (группа источников) |
| Предел запроса CDN меньше `scMaxEachPostBytes` | `413` от CDN (вывод; пределы тела у CDN — §6.1) | меньший `scMaxEachPostBytes` у края |
| h1 к источнику и много сессий | много TCP от одного адреса CDN, срабатывает предел на адрес | §5.2, свой предел для набора CDN |

### 5.6. Россия: заморозка и белые списки

- **Заморозка.** Счётчик идёт по пакетам на соединение TCP: ~25 пакетов дома и ~8 у Билайна и МТС. Соединение не
  рвётся, а замирает. 30 коротких соединений прошли, одно длинное — нет. UDP не задет
  ([Habr 1104904](https://habr.com/ru/articles/1104904/), 2026-11-05/06, один город).
  - Cloudflare резали с 2025-06-09
    ([блог Cloudflare](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/)),
    а в этом замере он прошёл 36 из 36.
  - ECH к Cloudflare режется с ноября 2024 ([naive-sni-rotation.md](naive-sni-rotation.md), §2).
  - Белые списки бывают по SNI и по подсетям ([net4people 490](https://github.com/net4people/bbs/issues/490)).
- **Белые списки мобильной сети.**
  - Тезис «адреса Yandex Cloud в белом списке» автор статьи сам назвал мифом: Yandex.Cloud — другая AS, чем Яндекс, и ВМ
    под белыми списками режутся. Cloudflare, по его словам, на мобильном под белыми списками не работает
    ([Habr 1021160](https://habr.com/ru/articles/1021160/), апрель 2026).
  - Про края отечественных CDN в белых списках данных нет. Это главный вопрос для замера.
- **Отечественные облака против прокси.** Способ через Yandex API Gateway «забанили» после публикации. ВМ Yandex Cloud
  «быстро сносят», у VK Cloud «сложная верификация» ([Habr 1027276](https://habr.com/ru/articles/1027276/)).

## 6. Сравнение CDN

Отмечено «нет данных», где источник не нашёлся. Большинство пустых клеток закрывается вопросом в поддержку или
пробным аккаунтом. Это работа этапа 0 (§7.2).

### 6.1. Техника

| CDN | HTTP/2 к источнику | Поток ответа | Тело запроса | Тайм-ауты | gRPC / WebSocket |
|---|---|---|---|---|---|
| **Cloudflare** | да, по умолчанию на всех тарифах; иначе h1 ([h2 to origin](https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/)). X25519MLKEM768 к источнику, если он умеет ([блог](https://blog.cloudflare.com/automatic-key-exchange-for-origins/)) | `response_body_buffering`: standard (по умолчанию) или none ([2026-01-27](https://developers.cloudflare.com/changelog/2026-01-27-body-buffering-settings/)); пускает ли standard поток без задержки — не сказано | `request_body_buffering`: standard (по умолчанию), full, none (там же); тарифы не указаны; предел размера — нет данных | Proxy Read Timeout 125 с, Enterprise до 6000 с ([524](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/)); простой ~100 с по опыту ([4113](https://github.com/XTLS/Xray-core/discussions/4113)); простой соединения h2 к источнику — 900 с, Proxy Idle Timeout — 900 с ([пределы соединений](https://developers.cloudflare.com/fundamentals/reference/connection-limits/)) | gRPC на всех тарифах: источник на 443, TLS, h2 по ALPN, `application/grpc` ([gRPC](https://developers.cloudflare.com/network/grpc-connections/)); WS — есть (используется в [Habr 1021160](https://habr.com/ru/articles/1021160/), документация не открывалась) |
| **Fastly** | только экспериментальный gRPC-бэкенд в Compute: «support for gRPC is under ongoing development» ([GrpcBackend](https://www.fastly.com/documentation/reference/compute/sdks/rust/fastly/experimental/trait.GrpcBackend/)); иначе нет данных | нет данных | нет данных | между байтами — по умолчанию 15 с, 0–600 с; между POP при щите — по настройкам каждого POP (там же, [between_bytes](https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/bereq-between-bytes-timeout/)) | WS — продукт: выключен по умолчанию, оплата за минуты соединения, без щита и NGWAF, сертификат источника публичный ([WebSockets](https://docs.fastly.com/products/websockets)) |
| **Akamai** | опция «HTTP/2 Edge to Origin» ([gRPC](https://techdocs.akamai.com/property-mgr/docs/google-rpc)) | двунаправленные потоки gRPC — по контракту (там же) | нет данных | простой — системные пределы, через аккаунт-менеджера (там же) | gRPC по контракту; WS есть, несовместим с gRPC (там же) |
| **CloudFront** | нет: «forwards requests to your custom origin using HTTP/1.1»; gRPC — h2 из конца в конец ([поведение](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html), [gRPC](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-using-grpc.html)) | chunked — по мере прихода (поведение) | GET с телом — `403`; если заголовок не переслать политикой, `Referer` удаляется, `User-Agent` заменяется на `Amazon CloudFront` (поведение) — по умолчанию ломает паддинг XHTTP | ответ и пауза между пакетами — 30 с по умолчанию, квота 1–120 с ([Origin settings](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesOrigin.html)); простой WS — 10 мин (по выдаче поиска) | gRPC: POST, HTTPS, мимо REC и Origin Shield (gRPC); WS — да (поведение: `Upgrade`) |
| **Google Cloud CDN** (внешний ALB) | да: HTTP, HTTPS, HTTP/2 ([backend service](https://docs.cloud.google.com/load-balancing/docs/backend-service)) | до тайм-аута отдаются заголовки и сколько успело тела ([request distribution](https://docs.cloud.google.com/load-balancing/docs/https/request-distribution)) | нет данных | тайм-аут сервиса — **весь обмен**, по умолчанию 30 с, фактически до 86 400 с (там же) | WS: активный не ограничен тайм-аутом, но до 24 ч (там же); gRPC — нет данных |
| **Azure Front Door** | нет, кроме gRPC (превью): «Routes without gRPC enabled use HTTP/1.1» ([FAQ](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq)) | нет данных | нет данных | keep-alive клиента 90 с, заголовки — 5 с (FAQ); ответ источника — нет данных | gRPC — превью (FAQ); WS — нет данных |
| **Gcore** | нет данных | нет данных | нет данных | `proxy_read_timeout` — между чтениями, 1–30 с, выше — только Enterprise ([тайм-ауты](https://docs.gcore.com/cdn/cdn-resource-options/general/customize-connection-and-read-timeouts)) | WS — переключатель ресурса (по выдаче поиска, [WS](https://docs.gcore.com/cdn/cdn-resource-options/websockets-allow-permanent-connections-with-the-origin)) |
| **Bunny.net** | нет данных | SSE без настройки, отдаёт «as soon as your origin writes it» ([SSE](https://bunny.net/docs/cdn/server-sent-events)) | нет данных | начало ответа — 60 с; простой потока — около 2 мин (SSE) | WS — переключатель зоны (по выдаче поиска) |
| **CDN77** | нет данных | нет данных | нет данных | нет данных | нет данных |
| **KeyCDN** | нет данных | нет данных | нет данных | нет данных | нет данных |
| **Yandex Cloud CDN** | нет данных | нет данных | POST, PUT, PATCH, DELETE закрыты, открывает поддержка по описанию задачи ([решение проблем](https://yandex.cloud/ru/docs/cdn/troubleshooting)) | источник должен ответить за 5 с (там же); между байтами — нет данных | WS — через поддержку, с описанием задачи и объёма (там же; [release notes](https://docs.yandex.cloud/int/en/cdn/release-notes.md)) |
| **VK Cloud CDN** | есть страница «HTTP/2 support», содержание не видно ([концепции](https://cloud.vk.ru/docs/en/networks/cdn/concepts)) | нет данных | по умолчанию только GET и HEAD, остальное — через поддержку ([методы](https://cloud.vk.ru/docs/en/networks/cdn/instructions/manage-cdn/http-headers)) | нет данных | нет данных |
| **Selectel CDN** | нет данных | нет данных | GET, HEAD, OPTIONS; POST включается в панели сам ([методы](https://docs.selectel.ru/en/cdn/content/http-methods.md)) | нет данных | нет данных |
| **NGENIX**, **CDNvideo**, **EdgeCenter** | нет данных | нет данных | нет данных | нет данных | нет данных |
| Казахстан, другие страны СНГ | не исследовано | | | | |

Закрыты, не рассматривать: Edgio — с 2025-01-15; StackPath ушёл из CDN в 2023 и затем закрылся (по выдаче поиска,
[DCD](https://www.datacenterdynamics.com/en/news/stackpath-to-close-down-liquidate-assets/)).

### 6.2. Доступ, условия, достижимость, право

| CDN | Доступ к источнику | Аккаунт | Условия (ToS) | Достижимость из России | Правовой риск |
|---|---|---|---|---|---|
| **Cloudflare** | подсети; AOP: общий, зоны, имени ([AOP](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)); заголовок; Tunnel; порт — Origin Rules | бесплатный тариф; ограничения KYC не нашёл | CDN не на Enterprise: за «a disproportionate percentage of pictures, audio files, or other large files» могут «disable or limit» ([Service-Specific Terms](https://www.cloudflare.com/service-specific-terms-application-services/)); про прокси пункта нет | с 2025-06-09 — первые 16 КБ ([блог](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/)); 2026-11: 36 из 36 прошли ([Habr 1104904](https://habr.com/ru/articles/1104904/)); на мобильном под белыми списками — нет ([Habr 1021160](https://habr.com/ru/articles/1021160/)) | компания США; российское право — через блокировку провайдерами |
| **Fastly** | нет данных | бесплатный аккаунт разработчика (2024: ~200 ГБ, 2 млн запросов), теперь нужна карта ([блог Fastly](https://quic.fastly.com/blog/its-free-instant-and-yours-fastlys-free-developer-accounts-are-here)) | нет данных | нет данных | США |
| **Akamai** | нет данных | контракт через продажи (вывод) | нет данных | нет данных; фронтинг в 2023 был возможен ([relay-entry-v1](../spec/relay-entry-v1.md) §7.6) | США |
| **CloudFront** | свои заголовки; список подсетей к источнику; VPC origins; mTLS к источнику с 2026-01 ([origin mTLS](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-mtls-authentication.html)) | аккаунт AWS; с 2022-03-08 новые регистрации из России и Беларуси закрыты ([TechCrunch](https://techcrunch.com/2022/03/10/amazon-microsoft-and-google-have-suspended-cloud-sales-in-russia)) | нет данных | нет данных | США |
| **Google Cloud CDN** | нет данных | новых клиентов в России нет (TechCrunch) | нет данных | нет данных о CDN; адреса Google Cloud прошли замер 2026-11 ([Habr 1104904](https://habr.com/ru/articles/1104904/)) | США |
| **Azure Front Door** | метка `AzureFrontDoor.Backend`; Private Link на Premium; фронтинг блокируется ([FAQ](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq)) | продажи в России приостановлены в 2022 (TechCrunch) | нет данных | нет данных | США |
| **Gcore** | нет данных | нет данных | нет данных | нет данных | Люксембург (вывод, не проверялось) |
| **Bunny.net** | нет данных | нет данных | в [AUP](https://bunny.net/acceptable-use/) нет пунктов о прокси и VPN; живые трансляции — с письменного согласия | нет данных | ЕС (Словения, вывод) |
| **CDN77**, **KeyCDN** | нет данных | нет данных | нет данных | нет данных | ЕС (Чехия, Швейцария, вывод) |
| **Yandex Cloud CDN** | нет данных | карта для проверки (по [Habr 1027276](https://habr.com/ru/articles/1027276/), о Functions) | в [AUP](https://yandex.ru/legal/cloud_aup) (редакция с 2026-09-07) нет пункта о прокси; п. 8.1 — приостановка, если использование «по мнению Яндекса» нарушает закон. На деле — блокировка способа через API Gateway ([Habr 1027276](https://habr.com/ru/articles/1027276/)) | края в белых списках — нет данных; ВМ Yandex Cloud режутся ([Habr 1021160](https://habr.com/ru/articles/1021160/)) | **высокий**: российское право. Идентификация клиентов хостинга (Госуслуги, карта, телефон, СБП) — с 2023-12-01 (по выдаче поиска); в июле 2026 Минцифры обсуждало обязательную ЕСИА, чтобы «за каждым выделенным IP-адресом стоял конкретный пользователь» ([Men Today](https://www.mentoday.ru/life/news/11-07-2026/mincifry-hochet-sdelat-obyazatelnoi-identifikaciyu-pokupatelei-hostingov-cherez-gosuslugi/)). Все метаданные (§5.3) — у стороны под российским правом |
| **VK Cloud CDN** | нет данных | «сложная верификация» (о ВМ, [Habr 1027276](https://habr.com/ru/articles/1027276/)) | нет данных | нет данных | **высокий**, как выше |
| **Selectel CDN** | нет данных | нет данных | нет данных | нет данных | **высокий**, как выше |
| **NGENIX**, **CDNvideo**, **EdgeCenter** | нет данных | контракт (вывод) | нет данных | CDNvideo предлагают как возможно разрешённый при белых списках — мнение в [issue](https://github.com/kort0881/russia-whitelist/issues/20) (по выдаче поиска) | **высокий**, как выше |

### 6.3. Что из этого следует

- **Cloudflare** — первый: у него подтверждено больше всего нужного XHTTP, а PQ к источнику — только у него. Есть:
  - h2 к источнику; gRPC на любом тарифе (`stream-up`), но источник gRPC — только на 443 (§7.1, п. 4);
  - управляемая буферизация тел;
  - mTLS к источнику со своим сертификатом, порт источника на любом тарифе, PQ к источнику;
  - бесплатный тариф.

  Против: достижимость из России меняется (2025 — режут, 2026-11 — проходит); под белыми списками не работает;
  ToS про «disproportionate» большие файлы.
- **CloudFront** — второй международный, и разрыв меньше, чем казалось: mTLS к источнику у него тоже есть (с 2026-01),
  так что «отдельный порт + mTLS» доступен у обоих. Плюсы: зрелый, свои заголовки, выбор порта, mTLS к источнику,
  gRPC h2 из конца в конец. Минусы: h1 к источнику вне gRPC, 30 с без данных по умолчанию, `Referer` по умолчанию
  срезается, PQ к источнику не найден, регистрация из России закрыта.
- **Отечественный CDN** — единственная надежда на режим белых списков. Но:
  - пропускают ли края белые списки — не мерил никто; замеры владелец попробует устроить (2026-11-19);
  - POST и WS по умолчанию закрыты у Yandex и VK, а открывает их поддержка по описанию задачи. Selectel открывает POST
    сам. Без POST остаётся `packet-up` с GET-аплинком (§2);
  - у Yandex источник должен ответить за 5 с;
  - правовой риск высокий, практика — снос.
- **Gcore** и **Bunny** — запасные: WS и потоки есть, тайм-ауты короткие (Gcore ≤ 30 с между чтениями), остальное не
  известно.

## 7. Рекомендация и план

### 7.1. Рекомендация

1. **XHTTP — двумя сервисами, по очереди.** Сначала форма A (mux для REALITY, R4-50), предварительно в v0.36.0; затем B
   (источник для CDN) в v0.37.0 — решение владельца 2026-11-19. Оба — своим процессом Xray, со своими учётными данными
   (G-2), своим зерном ML-KEM. Flow: клиент по коду умеет Vision поверх XHTTP с VLESS Encryption (§8.4, п. 3). Если
   interop это подтвердит — клиенты с Vision (паддинг внутренних рукопожатий, §3.6), иначе без flow.
2. **CDN — отдельным профилем для проверок, после замеров, не раньше v0.37.0** (вместе с формой B; владелец,
   2026-11-19). Порядок:
   - замерить из российских сетей (дом, мобильный, белые списки) пробный край каждого кандидата; замеры владелец
     попробует устроить («сложно, но попробуем»);
   - профиль края — отдельной строкой подписки (§5.1, вариант 1), после REALITY: порядок профилей не меняется. Вид relay
     (`edges[]`) — позже и только с клиентом.

   Первый кандидат — Cloudflare: у него больше всего нужного (§6.3), и нода уже работает с его DNS (names-v1 §2). Но
   для CDN нужен **отдельный домен**. Под доменом ноды запись `*.<домен>` без проксирования ведёт на ноду (names-v1 §2),
   и имя края под тем же доменом связало бы край с адресом ноды (вывод).
3. **Источник для CDN** — relay, отдельный порт, подсети CDN и секретный заголовок; mTLS там, где CDN умеет: Cloudflare
   и CloudFront (§5.2).
4. **Режим через CDN** — `packet-up`, `xPaddingObfsMode`, `scMaxEachPostBytes` под предел CDN. `stream-up` — только для
   CDN, где замер показал потоковое тело. У Cloudflare это выбор:
   - **gRPC**: поток вверх есть, но источник gRPC — только на 443
     ([gRPC](https://developers.cloudflare.com/network/grpc-connections/)). У relay-источника 443 — пересылка к фронту
     выхода со всеми именами (relay-v1 §2), и CDN пришлось бы пускать туда: прощупать через CDN можно REALITY и прочее;
   - **отдельный порт** без gRPC: `packet-up` всегда, `stream-up` — только если `request_body_buffering: none` на замере
     даёт поток ([2026-01-27](https://developers.cloudflare.com/changelog/2026-01-27-body-buffering-settings/)).

   Рекомендую отдельный порт: `packet-up` работает и без потока вверх, а закрытый 443 важнее (вывод).
5. **TLS без PQ на участках CDN** — только в профиле CDN, по решению владельца 2026-11-19, на двух условиях:
   - защита внутреннего трафика не слабее: VLESS Encryption с ML-KEM-768 из конца в конец, сервер удостоверяет ключ из
     `encryption` ссылки (§5.3);
   - реализация без лишних накладных расходов. В форме B лишнее — прокси `rayd xhttp` → Xray (ещё одна копия байтов
     и кадры h2c на unix-сокете). Замерить в этапе 2. Если цена заметна — Xray сам завершает TLS для имени края
     (§3.3), ценой токена в `rayd` и ответа сайта на чужой путь (вывод).

### 7.2. План (предварительно)

| Этап | Что | Выпуск |
|---|---|---|
| 0 | Открытые решения владельца (§8.3); ответы клиента (§8.4); пробные аккаунты 2–3 CDN и ручной замер через них из российских сетей (устроить попробует владелец). В форке: тесты `RemoveUser`, пределов и счётчиков на XHTTP; замер памяти до аутентификации | до v0.36.0 |
| 1 | Форма A: вид сервиса, рендер, ротация как у REALITY, маршрут фронта, ссылка с `extra`, `ProbeTunnels`, случай в `traffic.Processes`, `rayctl service add`. CI: задача `xray`, relay e2e, interop с Niko (в том числе Vision поверх XHTTP) | **v0.36.0** (предварительно) |
| 2 | Форма B: `rayd xhttp` (fd и packet от фронта), токен устройства в пути, ответ сайта, h3, `niko-pin`; замер накладных расходов прокси (§7.1, п. 5). CI: эмулятор CDN | **v0.37.1** (владелец, 2026-11-19; с v0.37.0 сдвинута 2026-11-24) |
| 3 | CDN — отдельный профиль для проверок: набор и порт в периметре, снимок relay с публичным портом для подсетей, список подсетей CDN к источнику, `rayctl` для края (провайдер, имя, источник, секрет), строка профиля края в подписке после REALITY (§5.1, вариант 1) | v0.37.1 или позже, после замеров |
| 4 | Вид relay в подписке (`edges[]` по `X-Raycontrol-Features`, §5.1, вариант 2); `downloadSettings` (вверх и вниз разными путями), если клиент добавит; `xorpub`/`random` для профиля края; keepalive вниз (Xray) | позже |

### 7.3. Не проверено

- Ничего не запускалось. Поведение CDN с XHTTP (буферизация, тайм-ауты, кеш) — только по документации.
- Ни один CDN не мерился из российских сетей нами. Сведения о достижимости — из одного замера в одном городе и из
  форумов. ntc.party из сессии не открылся.
- Что умеет текущее ядро клиента `688d100`: у нас только `34eaa8c` от 2026-11-02.
- Как Cloudflare Tunnel и CDN передают потоковое тело `stream-up` — нет данных.
- Расход памяти XHTTP до аутентификации — оценка по коду.
- Накладные расходы прокси `rayd xhttp` → Xray (условие §8.3, Р1) — не замерены.
- Vision поверх XHTTP с VLESS Encryption у клиента — только по коду, interop не было.

## 8. Вопросы

### 8.1. Что предлагается решить

См. §7.1. Решения владельца пойдут в decisions.md и roadmap.md, как у прочих исследований. Решения 2026-11-19 — в
§8.3, они же в [decisions.md](../decisions.md) R4-50 и в [roadmap.md](../roadmap.md) («Мультиплексирование»).

### 8.2. Размеры

S — до двух дней, M — около недели, L — две–четыре недели, как в [platforms-and-hosts.md](platforms-and-hosts.md).

### 8.3. Вопросы владельцу

**Решения владельца 2026-11-19:**
- **Р1.** Путь через CDN — отдельный профиль для проверок (§5.1, вариант 1). На участках «клиент — CDN» и «CDN —
  источник» этого профиля, и только его, допустим обычный TLS без PQ. Условия: защита внутреннего трафика не слабее
  (VLESS Encryption с ML-KEM из конца в конец) и реализация без лишних накладных расходов; оптимизировать схему —
  приветствуется (§7.1, п. 5).
- **Р2.** Замеры CDN из российских сетей владелец попробует устроить: «сложно, но попробуем» (§7.1, п. 2).
- **Р3.** Форма B — в v0.37.0, не в v0.36.0. Форма A — предварительно в v0.36.0 (§7.2).
- **Р4.** Порядок профилей в подписке не меняется: REALITY первым; для XHTTP его не трогаем (§5.1).

Ниже ответ отмечен там, где решения на вопрос отвечают; остальное открыто.

1. Делаем обе формы (A — mux для REALITY, B — источник для CDN), или только одну? Если одну — какую?
   **Отвечено Р3:** обе, A — первой.
2. Форма B напрямую нужна, или только как источник CDN? Напрямую у нас уже есть naive с настоящим Chromium.
3. CDN вообще делаем? Какие провайдеры первыми: только международные, или и отечественный для белых списков, с
   правовым риском §6.2? **Отвечено частично Р1 и Р2:** делаем отдельным профилем для проверок, после замеров.
   Провайдеры — открыто.
4. Чей аккаунт CDN: владельца, администратора ноды? Оплата и KYC связывают личность с ролью ноды.
5. Отдельный домен для имён на CDN — согласны?
6. Источник для CDN — relay, или допустим выход? `cloudflared` на выходе допустим?
7. PQ в TLS обязателен (`docs/design/protocols.md:58`). На участке «клиент — CDN» гибридный PQ есть у Cloudflare,
   CloudFront (с 2025-09-05, [анонс](https://aws.amazon.com/about-aws/whats-new/2025/09/amazon-cloudfront-TLS-policy-post-quantum-support), по выдаче поиска)
   и Azure Front Door (политика обмена ключами, [FAQ](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq)).
   На участке «CDN — источник» — только у Cloudflare (по найденному). Постквант для содержимого даёт VLESS Encryption.
   Снимаем требование для этих участков? **Отвечено Р1:** да, только для профиля CDN и на условиях Р1.
8. Путь — общий секрет сервиса или токен устройства (как DoH, R4-37)? Меняем по расписанию?
9. Имя на CDN показывает настоящий сайт (`pages`) или пустой `404` (R4-8)?
10. Ночной тест на настоящем CDN с секретами в CI — нужен?

### 8.4. Вопросы клиенту (Niko)

1. Что из XHTTP умеет текущее ядро (`688d100`)?
   - режимы `stream-one`, `stream-up`, `packet-up`;
   - XMUX — все шесть полей;
   - `xPaddingObfsMode` с заголовком, ключом и методом;
   - аплинк GET в `packet-up` с данными в заголовке или cookie;
   - h3.
2. XHTTP под REALITY с `pqv` (ML-DSA-65) — работает?
3. `flow=xtls-rprx-vision` поверх XHTTP вместе с VLESS Encryption — работает? Сервер это принимает (§2).
4. VLESS Encryption в режимах `xorpub` и `random` — умеете?
5. `downloadSettings`: в `34eaa8c` его нет (`client.go:299-301`), Niko его выкидывает (`XHTTP.kt:102-105`). Планируете?
6. Строгий разбор подписки (Niko 1.26): примет `type=xhttp` с `extra`, `path`, `mode`, `alpn`?
7. Профиль края: отдельная строка или вид relay с `X-Raycontrol-Features: cdn` (§5.1)? Владелец выбрал отдельную
   строку после REALITY (§8.3, Р1 и Р4). Как её видит детектор белых списков; значение `path: cdn` в отчёте?
8. Без `niko-pin` для профиля края — что проверяет клиент на участке до CDN: WebPKI системы или Chromium?
9. Подписка через туннель (имя замера) для профиля XHTTP — включается сама, если сервис в `tunnel_svc`?
10. Отпечаток TLS клиента XHTTP (uTLS, `fp`) — какой и меняется ли?

Ответы клиента 2026-11-19 (по коду ядра, не проверено interop; Niko сверит против `xray` из v0.34.0, форк
`46b58d4`):
- п. 1: режимы `auto`, `stream-one`, `stream-up`, `packet-up`; `auto` — как у Xray: REALITY → `stream-one`, иначе
  `packet-up` (`transport/v2rayxhttp/client.go:291-301` ядра). XMUX — все шесть полей из `extra`, умолчания Xray
  (без секции — 3 соединения, 600–900 запросов, 1800–3000 с). `xPaddingBytes` (100–1000) и `x_padding_obfs_*` есть.
  С REALITY — всегда HTTP/2 на uTLS; свой пинг HTTP/2 раз в 45 с и прерыватель с отсрочкой. Клиент XHTTP — свой, в
  форке sing-box (порт из sing-box-lx), не Xray.
- п. 2: `pqv` в ссылке читается.
- п. 3: да, по коду: ядро регистрирует `CommonConn` шифрования в реестре TLS-соединений Vision, как Xray. Поверх XHTTP
  не проверялось — войдёт в interop.
- п. 5: `downloadSettings` нет.
- п. 6: `type=xhttp` (и `type=splithttp`) с `extra`, `path`, `mode` принимается (golden `vless-xhttp-reality.txt`).
- UDP поверх XHTTP — обычный запрос VLESS, без XUDP (`packetEncoding=xudp` только явно в ссылке).
- Пп. 4, 7–10 — открыты.

### 8.5. Вопросы к Xray (upstream), по желанию

- keepalive на потоке вниз (GET), чтобы CDN не рвал простаивающий туннель;
- предел ресурсов сессий XHTTP до аутентификации.

## Источники

Код и документы этого репозитория — ссылками в тексте. Внешние, открытые в этой работе:

- Xray: [обсуждение 4113 (руководство по XHTTP)](https://github.com/XTLS/Xray-core/discussions/4113),
  [PR 5067 (VLESS Encryption)](https://github.com/XTLS/Xray-core/pull/5067).
- Россия:
  - [блог Cloudflare, 2025-06-26](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/);
  - [net4people 490](https://github.com/net4people/bbs/issues/490);
  - [Habr 1104904, 2026-11-10](https://habr.com/ru/articles/1104904/) и
    [пересказ Men Today](https://www.mentoday.ru/technics/news/11-11-2026/saity-zagrujayutsya-napolovinu-v-rossii-nachalas-blokirovka-zarubejnyh-hostingov-celymi-podsetyami/);
  - [Habr 1021160](https://habr.com/ru/articles/1021160/); [Habr 1027276](https://habr.com/ru/articles/1027276/);
  - [Men Today, 2026-07-11, ЕСИА для хостинга](https://www.mentoday.ru/life/news/11-07-2026/mincifry-hochet-sdelat-obyazatelnoi-identifikaciyu-pokupatelei-hostingov-cherez-gosuslugi/);
  - [TechCrunch, 2022-03-10](https://techcrunch.com/2022/03/10/amazon-microsoft-and-google-have-suspended-cloud-sales-in-russia).
- Cloudflare:
  - [524](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-524/);
  - [HTTP/2 to origin](https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/);
  - [gRPC](https://developers.cloudflare.com/network/grpc-connections/);
  - [AOP](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/);
  - [защита источника](https://developers.cloudflare.com/learning-paths/prevent-ddos-attacks/advanced/prevent-external-connections/);
  - [Origin Rules](https://developers.cloudflare.com/rules/origin-rules/);
  - [пределы соединений](https://developers.cloudflare.com/fundamentals/reference/connection-limits/);
  - [буферизация тел, 2026-01-27](https://developers.cloudflare.com/changelog/2026-01-27-body-buffering-settings/);
  - [PQ к источнику, 2026-09-08](https://blog.cloudflare.com/automatic-key-exchange-for-origins/);
  - [Service-Specific Terms](https://www.cloudflare.com/service-specific-terms-application-services/).
- Fastly: [between_bytes_timeout](https://www.fastly.com/documentation/reference/vcl/variables/backend-connection/bereq-between-bytes-timeout/),
  [GrpcBackend](https://www.fastly.com/documentation/reference/compute/sdks/rust/fastly/experimental/trait.GrpcBackend/),
  [WebSockets](https://docs.fastly.com/products/websockets),
  [бесплатные аккаунты](https://quic.fastly.com/blog/its-free-instant-and-yours-fastlys-free-developer-accounts-are-here).
- Akamai: [gRPC](https://techdocs.akamai.com/property-mgr/docs/google-rpc).
- AWS: [gRPC](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-using-grpc.html),
  [Origin settings](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DownloadDistValuesOrigin.html),
  [поведение с источником](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html),
  [origin mTLS](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-mtls-authentication.html).
- Google: [backend service](https://docs.cloud.google.com/load-balancing/docs/backend-service),
  [request distribution](https://docs.cloud.google.com/load-balancing/docs/https/request-distribution).
- Azure: [FAQ Front Door](https://learn.microsoft.com/en-us/azure/frontdoor/front-door-faq).
- Gcore: [тайм-ауты](https://docs.gcore.com/cdn/cdn-resource-options/general/customize-connection-and-read-timeouts).
- Bunny: [SSE](https://bunny.net/docs/cdn/server-sent-events), [ToS](https://bunny.net/tos/),
  [AUP](https://bunny.net/acceptable-use/).
- Yandex: [решение проблем CDN](https://yandex.cloud/ru/docs/cdn/troubleshooting),
  [release notes CDN](https://docs.yandex.cloud/int/en/cdn/release-notes.md), [AUP](https://yandex.ru/legal/cloud_aup).
- VK: [концепции CDN](https://cloud.vk.ru/docs/en/networks/cdn/concepts),
  [методы](https://cloud.vk.ru/docs/en/networks/cdn/instructions/manage-cdn/http-headers).
- Selectel: [методы](https://docs.selectel.ru/en/cdn/content/http-methods.md).

По выдаче поиска, страницы не открывались:
- [список подсетей CloudFront для источников](https://aws.amazon.com/blogs/networking-and-content-delivery/limit-access-to-your-origins-using-the-aws-managed-prefix-list-for-amazon-cloudfront);
- анонсы AWS: [mTLS к источникам, 2026-01](https://aws.amazon.com/about-aws/whats-new/2026/01/amazon-cloudfront-mutual-tls-for-origins),
  [PQ к зрителям, 2025-09](https://aws.amazon.com/about-aws/whats-new/2025/09/amazon-cloudfront-TLS-policy-post-quantum-support);
- [WS Gcore](https://docs.gcore.com/cdn/cdn-resource-options/websockets-allow-permanent-connections-with-the-origin);
- [закрытие StackPath (DCD)](https://www.datacenterdynamics.com/en/news/stackpath-to-close-down-liquidate-assets/);
- [issue russia-whitelist 20](https://github.com/kort0881/russia-whitelist/issues/20);
- идентификация клиентов хостинга с 2023-12-01 ([Habr](https://habr.com/ru/amp/publications/766708/)).
