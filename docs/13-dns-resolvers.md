# 13. Резолверы для DNS-туннелей

Кабинетное исследование 2026-11-05: резолверы не опрашивались, утверждения со ссылками. Непроверенное помечено в тексте.
Полные отчёты — ниже, после выводов.

## Выводы и что из них сделано

**Сервер (raycontrol v0.11.1, niko-server v0.8.3):**
- **dnstt и малый размер EDNS.** dnstt-server отвечал `FORMERR`, если резолвер объявлял буфер меньше 1232. Резолверы
  с 512 или 1220 ломали туннель целиком. Теперь ответы укладываются в размер запрашивающего, а сессия берёт MTU по
  самому малому размеру своих запросов: медленнее, но работает.
- **QNAME minimisation.** На запросы не TXT dnstt отвечал `NXDOMAIN`. Резолвер с минимизацией (RFC 9156) спрашивает
  имена выше туннельного запросами A или NS, а по RFC 8020 может после `NXDOMAIN` бросить всё. Теперь ответ —
  `NOERROR` без записей.
- **Проба резолвера** ([`spec/dnsprobe-v1.md`](spec/dnsprobe-v1.md)). Фронт сам отвечает на проверку кандидата:
  доходит ли зона, цел ли TXT, проходят ли большие ответы. Ещё он сообщает, что увидела нода: размер EDNS, 0x20 и
  выходной адрес резолвера. Метка — с MAC ключа из подписки, сканеру зон она не отличима от запроса туннеля.
- **Сводка** ([`spec/probe-v1.md`](spec/probe-v1.md) §6): вид резолвера (`net`, `udp`, `doh`, `dot`) по виду туннеля,
  без адресов.

**Клиент (Niko 1.33):**
- **Порядок кандидатов:** резолвер сети (LinkProperties, UDP 53) → национальные или внутренние публичные по UDP 53 →
  DoT/DoH там, где не заблокированы. Google, Cloudflare и Quad9 — нет. Яндекс в России — последним.
  - Россия: НСДИ 195.208.5.1 и 195.208.4.1, MSK-IX 62.76.76.62.
  - Иран: внутренние резолверы.
  - Китай: DNSPod, AliDNS, CNNIC.
- **Поиск в сети клиента:** `LinkProperties.getDnsServers()`, признак DoT до резолвера сети (`isPrivateDnsActive()`
  без имени) и собственный запрос DDR (RFC 9462). DNR (RFC 9463) приложению на Android недоступен. DDR у провайдеров
  почти не развёрнут.
- **Несколько резолверов на одну сессию.** У dnstt сервер это уже понимает: сессия по ClientID, ответ тому, кто
  спросил. Нужен планировщик на 2–4 резолвера: AIMD на резолвер, карантин, фоновая перепроверка. Дублировать только
  управляющие пакеты. MasterDnsVPN это умеет сам. Multipath QUIC не нужен.

**Не сделано, на будущее:**
- TCP 53 у фронта: в России перехватывают UDP, а TCP — нет. Но ни dnstt, ни MasterDnsVPN TCP пока не умеют.
- Адрес резолвера в сводке — только для инфраструктуры провайдера той же AS, с порогом по уникальным клиентам.
- Имена зон туннелей нейтральные: в Туркменистане фильтруют по регулярным выражениям вроде `^doh\.`. Нода берёт
  случайные метки, так что это уже так.
- Ответы на SOA и NS у вершины зоны туннеля: по отчёту в net4people #30, часть публичных резолверов давала
  SERVFAIL без них. Сейчас вершина отвечает `NOERROR` без записей.

## Отчёты


### Кандидаты по странам


Кабинетное исследование, 5 ноября 2026. Ни один резолвер не опрашивался. «Не подтверждено» означает, что первичного источника не нашлось или он был недоступен. Из среды исследования не открылись ntc.party, 403.online, shecan.ir и electrotm.org (503), а также techora.ru (проверка на бота). Утверждения из этих мест взяты из поисковой выдачи и помечены. Источники старше 2023 года помечены **[<2023]**.

---

#### 0. Что нужно от резолвера и что клиент может быстро проверить

| Свойство | Почему важно | Источник |
|---|---|---|
| Рекурсия в произвольную делегированную зону без фильтрации домена | Цензурирующий резолвер может «забыть» домен туннеля. На НСДИ это уже произошло с публично раздававшимися доменами туннелей. По одному отчёту, Google DNS перестал резолвить домен туннеля примерно через 10 минут работы (страница недоступна, не подтверждено). | [Meduza, 14.05.2026](https://meduza.io/cards/my-uzhe-rasskazyvali-o-nekotoryh-metodah-obhoda-belyh-spiskov-vot-esche-odin-ot-roskomnadzora-chto); [ntc.party/20104](https://ntc.party/t/google-dns-isnt-responding-to-domain-after-using-dnstt/20104) |
| Кэш | dnstt делает каждый QNAME уникальным (ClientID плюс случайный паддинг, «cache inhibition»), поэтому кэш не мешает. | [dnstt-client/dns.go](https://github.com/OutlineFoundation/dnstt/blob/master/dnstt-client/dns.go) |
| TXT | dnstt-server отвечает только на QTYPE=TXT, на остальные типы возвращает NXDOMAIN. Какой тип записи использует MasterDnsVPN, README не говорит (не подтверждено). | [dnstt-server/main.go](https://github.com/OutlineFoundation/dnstt/blob/master/dnstt-server/main.go); [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) |
| Размер EDNS(0) | dnstt-server отвечает FORMERR, если резолвер объявляет UDP payload меньше `-mtu` (по умолчанию 1232). Резолверы с 512 или 1220 ломают туннель. Это лечится запуском сервера с `-mtu 512` ценой скорости. MasterDnsVPN подбирает MTU для каждого резолвера отдельно. | код сервера (выше); [net4people #30](https://github.com/net4people/bbs/issues/30); [ntc.party/7836](https://ntc.party/t/dns-provider-that-has-cookies-doesnt-work-with-dnstt/7836) (по выдаче поиска) |
| Лимиты частоты | Бывают лимиты QPS и полосы на клиентский IP (Google), лимиты исходящих запросов к одному NS или к одной зоне (Unbound `ratelimit`, BIND `fetches-per-zone`) и защиты от атак random-subdomain. Против них работают несколько резолверов с балансировкой или дублированием пакетов (так делает MasterDnsVPN). | [Google Public DNS security](https://developers.google.com/speed/public-dns/docs/security); [unbound.conf](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html); [ISC, 2015](https://www.isc.org/docs/FOSSETCON-2015-BIND9_Recursive_Client_Rate_limiting.pdf) **[<2023]** |
| QNAME minimisation | Минимизирующий резолвер шлёт нашему NS запросы A/NS на усечённые имена. dnstt отвечает на них NXDOMAIN, и в коде есть комментарий именно об этом. По RFC 8020 строгий резолвер может считать всё, что ниже NXDOMAIN, несуществующим. На Google и Cloudflare dnstt работал, но риск для ISP-резолверов в строгом режиме теоретический и не подтверждён. Похожий отчёт 2026 года: SERVFAIL на части публичных резолверов исправили патчем `-auth-name`/`-glue-ips`. | [RFC 9156](https://www.rfc-editor.org/rfc/rfc9156); [RFC 8020](https://www.rfc-editor.org/rfc/rfc8020); [net4people #30](https://github.com/net4people/bbs/issues/30) |
| Рандомизация регистра 0x20 | dnstt переводит метки в верхний регистр перед декодированием base32, поэтому 0x20 ему не мешает. В Unbound `use-caps-for-id` по умолчанию выключен, Google 0x20 использует. Чувствительно ли кодирование MasterDnsVPN к регистру (опция `BASE_ENCODE_DATA`), не подтверждено, и это надо проверить. | код сервера; [unbound.conf](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html); [Google](https://developers.google.com/speed/public-dns/docs/security) |
| Фронтенды DoH | dnstt шлёт DoH-запросы методом POST с типом `application/dns-message`. По RFC 8484 сервер обязан поддерживать GET и POST. Известные сбои: Cloudflare иногда отвечает 400, Google DoT рвёт соединение примерно каждые 200 КБ, Quad9 DoH обрезал ответы при EDNS 1232. MasterDnsVPN DoH не документирует (в примерах только IP:port). | [http.go](https://github.com/OutlineFoundation/dnstt/blob/master/dnstt-client/http.go); [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484); [#30](https://github.com/net4people/bbs/issues/30); [DNS-OARC 2022](https://lists.dns-oarc.net/pipermail/dns-operations/2022-April/021613.html) **[<2023]** |
| Обнаружение резолвера сети | Android в режиме Automatic сам переходит на DoT, если резолвер сети его поддерживает. Публикации DDR (RFC 9462, `_dns.resolver.arpa`) у операторов из списка не найдено. | [Android blog, 2018](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html) **[<2023]**; [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462) |

**Быстрые проверки на клиенте** (по образцу сканеров [SlipNet](https://github.com/anonvector/slipnet), [findns](https://github.com/SamNet-dev/findns/releases/tag/v0.1.5) и `--scan` в MasterDnsVPN):

1. Доступность по UDP 53, а для DoH отдельно проверить коды HTTP 400/404/429.
2. Подмена NXDOMAIN: случайное несуществующее имя должно вернуть NXDOMAIN.
3. TXT-проба в свою зону. Нужен отдельный проб-поддомен с фиксированным TXT-ответом примерно на 1200 байт. Проверяются ответ, задержка и отсутствие TC или обрезки.
4. Серверный лог: размер EDNS от резолвера, регистр QNAME (0x20) и запросы A/NS на частичные имена (QNAME minimisation).
5. Короткий всплеск уникальных запросов, чтобы найти потолок QPS.
6. Сессия на 10 минут и больше, чтобы поймать троттлинг по домену.

---

#### 1. Россия (приоритет)

| # | Кандидат | Транспорт | Оператор и доступ | Заметки |
|---|---|---|---|---|
| 1 | Резолвер сети из DHCP/LinkProperties | UDP 53 | МТС, МегаФон, Билайн, T2, Ростелеком и другие. Только для своих абонентов. | В режиме белых списков резолвер Билайна остался доступен ([net4people #516](https://github.com/net4people/bbs/issues/516), 09.2025). По утверждению 2021 года, владельцы АС обязаны использовать НСДИ как вышестоящий DNS ([Habr](https://habr.com/ru/post/579634) **[<2023]**). Значит, блокировка домена туннеля на НСДИ, вероятно, дойдёт и сюда (не подтверждено). DoT/DoH/DDR у операторов не найдены. |
| 2 | НСДИ: 195.208.5.1 (b.res-nsdi.ru), 195.208.4.1 (a.res-nsdi.ru) | UDP/TCP 53. DoT/DoH не найдены. | Роскомнадзор/НСДИ. Открыты: отвечали на запросы из-за рубежа при проверках 28.08 и 08.10.2026. | dnstt через НСДИ давал 2–3 Мбит/с в течение нескольких дней ([Meduza](https://meduza.io/cards/my-uzhe-rasskazyvali-o-nekotoryh-metodah-obhoda-belyh-spiskov-vot-esche-odin-ot-roskomnadzora-chto)). Публичные домены туннелей там блокировали (там же). Адреса, PTR и AS41740 приведены в [zapret wiki](https://wiki.zapret.moe/DPI/tspu-dns-nsdi-dnat-august-2026). Резолвер государственный и видит все запросы. |
| 3 | MSK-IX: 62.76.76.62, 62.76.62.76; 2001:6d0:6d0::2001, 2001:6d0:d6::2001 | UDP/TCP 53. DoT/DoH не заявлены. | MSK-IX, «доступен всем». Фильтрует по реестру 139-ФЗ. | [kb.msk-ix.ru](https://kb.msk-ix.ru/public/dns-server/). У части абонентов Дом.ру запросы к нему тоже перехватываются ([zapret wiki](https://wiki.zapret.moe/DPI/tspu-dns-nsdi-dnat-august-2026)). |
| 4 (последний) | Яндекс: 77.88.8.8, 77.88.8.1; DoT/DoH common.dot.dns.yandex.net (:853/:443) | UDP 53, DoT, DoH | Яндекс, открыт | Адреса взяты с [dns.yandex.com](https://dns.yandex.com). Путь `/dns-query` на официальной странице не указан, а сообщение о 404 на форуме Keenetic автор позже отозвал ([forum.keenetic.ru](https://forum.keenetic.ru/topic/27863-%D1%8F%D0%BD%D0%B4%D0%B5%D0%BA%D1%81-dns-%D0%BF%D1%80%D0%B5%D1%81%D0%B5%D1%82%D1%8B-yandex-safefamilybase-%E2%80%94-%D0%BD%D0%B5%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%B0%D1%8E%D1%89%D0%B8%D0%B9-doh-endpoint/)). В белых списках Билайна Яндекс был заблокирован (#516). По выдаче поиска, на ntc.party пишут, что Яндекс «не подходит для dnstt» ([ntc.party/23468](https://ntc.party/t/%D0%B1%D0%B5%D0%BB%D1%8B%D0%B5-%D1%81%D0%BF%D0%B8%D1%81%D0%BA%D0%B8-%D1%87%D0%B5-%D0%B4%D0%B5%D0%BB%D0%B0%D1%82%D1%8C/23468); не подтверждено). Почему ваш тест dnstt через DoH не прошёл, неизвестно. Гипотезы: метод POST или размер EDNS на DoH-фронтенде, либо лимиты. Проверить пунктами 1, 3 и 4 из раздела 0. |

**Вмешательство:**
- **Август 2026.** ТСПУ узнаёт DNS по содержимому пакета, а не по порту, и через DNAT перенаправляет UDP-запросы к 8.8.8.8/1.1.1.1 на 195.208.5.1. TCP 53 при этом не перехватывается ([Habr 1075272](https://habr.com/ru/articles/1075272/)). У части абонентов так перехватывались все 16–18 проверенных адресов, включая Яндекс и AdGuard. В Центральном ФО и у Yota подмены не было ([zapret wiki](https://wiki.zapret.moe/DPI/tspu-dns-nsdi-dnat-august-2026)). Teplitsa своими замерами DNAT не подтвердила ([te-st.org](https://te-st.org/2026/08/07/dnsdnsdns/)). Вывод: если указать «иностранный» резолвер по UDP, запрос, скорее всего, всё равно попадёт на НСДИ.
- **DoH/DoT, август 2026.** DoH блокируется по SNI: dns.google, cloudflare-dns.com, dns.adguard(-dns).com, dns.quad9.net, dns.alidns.com и другие. DoT к Cloudflare сбрасывается RST. Затронуты Ростелеком, Дом.ру, Билайн, Таттелеком и SkyNet ([Habr 1077682](https://habr.com/ru/articles/1077682/), [zapret wiki](https://wiki.zapret.moe/DPI/tspu-dns-nsdi-dnat-august-2026)). В ноябре 2026 NextDNS заблокирован по IP и TLS-имени ([techora](https://techora.ru/news/v-rossii-massovaya-blokirovka-zashchishchyonnykh-dns-2026-11-01), страница не открылась, известно по выдаче поиска).
- **Белые списки, с сентября 2025.** На мобильных сетях внешние IP режутся, а резолверы оператора и НСДИ остаются доступны. Именно поэтому туннель через них работает, хотя сервер туннеля напрямую недоступен ([#516](https://github.com/net4people/bbs/issues/516), [Meduza](https://meduza.io/cards/my-uzhe-rasskazyvali-o-nekotoryh-metodah-obhoda-belyh-spiskov-vot-esche-odin-ot-roskomnadzora-chto)).
- **Детектирование туннелей ТСПУ.** Публичных данных не найдено (не подтверждено). Наблюдались только блокировки доменов на уровне резолвера.

**Рекомендуемый порядок:** резолвер сети (UDP) → 195.208.5.1 → 195.208.4.1 → MSK-IX → Яндекс по UDP → Яндекс DoT/DoH как эксперимент. Ни dnstt, ни MasterDnsVPN не умеют TCP 53, поэтому то, что TCP не перехватывается, им сейчас не помогает. Домен туннеля нигде не публиковать и держать запасные домены.

---

#### 2. Беларусь (приоритет)

| # | Кандидат | Заметки |
|---|---|---|
| 1 | Резолвер сети: Белтелеком/byfly, A1, МТС BY, life:) (UDP 53) | Только для абонентов. DoT/DoH не найдены. |
| 2 | НСДИ и MSK-IX (РФ) по UDP 53 | Резолверы открытые, но доступность из Беларуси не проверена (не подтверждено). Это российская государственная инфраструктура. |
| 3 | Яндекс 77.88.8.8 (UDP) | Последний вариант. |

**Вмешательство:** в 2020 году блокировка шла через DPI и по SNI ([OONI 2020](https://lists.torproject.org/pipermail/ooni-talk/2020-September/000236.html) **[<2023]**). Запрет на иностранные DNS тогда касался только госорганов ([Onliner 2020](https://tech.onliner.by/2020/06/26/vizhu-dokument-o-blokirovke-provajderami-inostrannyx-dns-chto-eto-telegram-otklyuchat) **[<2023]**). Данных 2023–2026 годов о перехвате UDP 53 и блокировке DoH не найдено. Национального резолвера не найдено.

#### 3. Казахстан (приоритет)

| # | Кандидат | Заметки |
|---|---|---|
| 1 | Резолвер сети: Казахтелеком, Beeline KZ, Kcell, Tele2/Altel (UDP 53) | Только для абонентов. DoT/DoH не найдены. |
| 2 | Российские НСДИ и MSK-IX (UDP 53) | Трансграничный путь, не проверено. |
| 3 | Яндекс (UDP) | Последний вариант. |

**Вмешательство:** OONI за 2023–2024 годы описывает блокировки как вмешательство в TLS и MITM с государственным корневым сертификатом. DNS-подмена как основной метод там не упоминается ([OONI 2024](https://ooni.org/post/2024-kazakhstan-report/)). DoH к cloudflare-dns.com блокировался по SNI ([OONI DoH/DoT study](https://ooni.org/post/2022-doh-dot-paper-dnsprivacy21/) **[<2023]**). Значит, обычный UDP 53, вероятно, не трогают (не подтверждено). Национального резолвера не найдено.

#### 4–6. Кыргызстан, Узбекистан, Таджикистан (приоритет)

Здесь первый и практически единственный кандидат — резолвер сети по UDP 53. Национальных публичных резолверов не найдено: запущенные в Узбекистане и Таджикистане экземпляры K-root — это корневые серверы, а не резолверы. DoT/DoH у операторов не найдены.
- **Кыргызстан:** OONI подтверждает блокировку TikTok в 5 сетях с апреля 2024 года, механизм в выдаче не указан ([OONI finding](https://explorer.ooni.org/findings/154621229001)).
- **Узбекистан:** агрегатор данных Censored Planet фиксирует DNS-блокировки в 2026 году, механизм и провайдер не определены ([voidly](https://voidly.ai/incident/UZ-2026-0191), вторичный источник).
- **Таджикистан:** внешний трафик идёт через Tojiktelecom, бывают длительные отключения ([Eurasianet](https://eurasianet.org/tajikistan-and-its-terrible-horrible-no-good-very-bad-internet), дата не проверена, вероятно **[<2023]**).
- Российские НСДИ, MSK-IX и Яндекс можно оставить как резерв (доступность не подтверждена).

#### 7. Туркменистан (приоритет)

| # | Кандидат | Заметки |
|---|---|---|
| 1 | Резолвер Turkmentelecom из DHCP (UDP 53) | Единственный реалистичный вариант. По комментарию в [net4people #30](https://github.com/net4people/bbs/issues/30), dnstt работал во время отключения и был стабильнее iodine (дата комментария не проверена). |

**Вмешательство:** цензор подменяет ответы DNS по UDP в обе стороны для любого IP на пути через границу и фильтрует по регулярным выражениям. Правило `^doh\..*` заодно блокирует множество DoH-резолверов. Есть и инъекции в TCP ([Nourin et al., WWW 2023](https://arxiv.org/abs/2304.04835)). Отсюда практические советы. Имя туннельной зоны должно быть невыразительным: без `doh`, `vpn`, `proxy` и тому подобного. Обращаться к иностранным резолверам бессмысленно. Блокируются целые CDN ([#523](https://github.com/net4people/bbs/issues/523), 2025).

#### 8. Азербайджан (приоритет)

Первый кандидат — резолвер сети (Azertelecom, Delta Telecom, Azercell, Bakcell) по UDP 53. В анализе OONI 2023 года среди аномалий преобладают таймауты, признаки DNS-подмены встречались только в отдельных старых измерениях ([OONI 2023](https://ooni.org/post/2023-azerbaijan-internet-censorship/)). Данных о DoH/DoT и национальных резолверах нет.

#### 9. Иран (приоритет)

| # | Кандидат | Транспорт | Заметки |
|---|---|---|---|
| 1 | Резолвер ISP: MCI, Irancell, TCI, Shatel (DHCP) | UDP 53 | Только для абонентов. |
| 2 | Внутренние «антисанкционные» резолверы: Shecan 178.22.122.100 / 185.51.200.2; Electro 78.157.42.100/.101; Radar 10.202.10.10/.11; 403 10.202.10.202 / 10.202.10.102; Begzar 185.55.226.26 / .25 (второй адрес разнится); DNS Pro 87.107.110.109/.110 | UDP 53 | Адреса взяты из сообществ ([dns-switcher](https://github.com/Linuxmaster14/dns-switcher), [dns-changer](https://github.com/ALIILAPRO/dns-changer)), официальные сайты не открылись, поэтому не подтверждено. Адреса 10.x работают только внутри Ирана. Эти сервисы обходят геоблокировку зарубежных сайтов, а не цензуру. |
| 3 | Найденные сканером открытые резолверы внутри Ирана | UDP 53 | findns поставляет 7854 известных иранских резолвера ([findns](https://github.com/SamNet-dev/findns/releases/tag/v0.1.5)). Списки быстро устаревают. Работать лучше через MasterDnsVPN с балансировкой и дублированием. |

**Вмешательство:**
- Инъекция DNS-ответов с адресами 10.10.34.34/.35/.36 ([FOCI 2025](https://petsymposium.org/foci/2025/foci-2025-0002.php)). Инъекция ломала даже резолв имени DoH-сервера для dnstt ([#30](https://github.com/net4people/bbs/issues/30)).
- DoT блокировался в 50–57% случаев с 2020 года. DoH с сентября 2022 блокируется через DNS-подмену ([OONI 2022](https://ooni.org/post/2022-iran-blocks-social-media-mahsa-amini-protests/) **[<2023]**).
- Перед отключением в июне 2025 был заблокирован DNS по TCP (96% доменов), после отключения сильно терялся UDP ([FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0016.pdf)). На резервный переход на TCP рассчитывать нельзя.
- Во время отключений доля TXT в запросах к 1.1.1.1 доходила примерно до 25–30% (июнь 2025) и до 80% и больше (январь 2026) ([#484](https://github.com/net4people/bbs/issues/484)). Туннели видны на статистике.
- В 2026 году dnstt по UDP 53 был почти единственным рабочим методом ([#586](https://github.com/net4people/bbs/issues/586), [#561](https://github.com/net4people/bbs/issues/561)). Но через 1–2 недели внешние резолверы закрыли, и около 99% локальных оказались непригодны. Скорость была около 100 КБ/с, соединения рвались примерно на первой минуте ([#626](https://github.com/net4people/bbs/issues/626)).

**Порядок:** резолвер ISP → внутренние публичные → найденные сканером. Только UDP, сразу несколько резолверов. DoH/DoT в Иране бесполезны.

#### 10. Китай (приоритет)

| # | Кандидат | Транспорт | Заметки |
|---|---|---|---|
| 1 | Резолвер сети: China Telecom, Unicom, Mobile | UDP 53 | Только для абонентов. |
| 2 | DNSPod (Tencent) 119.29.29.29 | UDP 53; DoH `https://doh.pub/dns-query`, DoT dot.pub (1.12.12.12, 120.53.53.53) | IP указан в [официальной документации](https://docs.dnspod.com/public-dns/public-dns-introduction/) (2022) **[<2023]**. DoH/DoT известны только из стороннего списка ([wiki](https://github.com/QIN2DIM/tuic-installer/wiki/%E5%85%AC%E6%9C%89-DNS-%E6%B1%87%E6%80%BB-DOT-DOH-DOQ)). |
| 3 | AliDNS 223.5.5.5, 223.6.6.6; 2400:3200::1, 2400:3200:baba::1 | UDP/TCP 53 | IP из [официальной документации](https://help.aliyun.com/document_detail/212066.htm). С 30.09.2024 бесплатный тариф ограничивается по числу одновременных запросов с IP ([Aliyun](https://help.aliyun.com/dns/public-dns-free-version-access-speed-limit-notification)). В пересказе называют 20 QPS для DoH/DoT и 2000 бит/с для UDP/TCP ([V2EX](https://v2ex.com/t/1058732)); официально эти цифры не подтверждены. Для туннеля это узкое место. DoH/DoT теперь работают только через `<user_id>.alidns.com` и включаются в консоли ([Alibaba Cloud](https://alibabacloud.com/help/en/dns/service-access)), а `dns.alidns.com` встречается только в сторонних списках. |
| 4 | CNNIC SDNS 1.2.4.8, 210.2.4.8 | UDP 53 | [CNNIC](https://www.cnnic.cn/n4/2026/0105/c221-11459.html) описывает сервис как бесплатный для внутренних пользователей. |
| 5 | 114DNS 114.114.114.114/115.115; Baidu 180.76.76.76; 360 101.226.4.6 / 218.30.118.6; ByteDance 180.184.1.1 / 180.184.2.2 | UDP 53 | Адреса из сторонних списков ([xiaoz](https://en.xiaoz.org/post/6522)), не подтверждены. |

**Вмешательство:** GFW подделывает ответы для запрещённых доменов по UDP и отравляет кэши открытых резолверов ([USENIX Sec 2021](https://usenix.org/conference/usenixsecurity21/presentation/hoang) **[<2023]**). DoT/DoH к Cloudflare и другим блокировались на уровне TCP/IP ([OONI](https://ooni.org/post/2022-doh-dot-paper-dnsprivacy21/) **[<2023]**). Публичных первичных данных о детектировании dnstt именно GFW не найдено. Распространённое мнение, что Китай детектирует туннели, тоже не подтверждено. **Порядок:** ISP → DNSPod → AliDNS → CNNIC → 114 и прочие. Нагрузку раскладывать по нескольким резолверам. DoH через doh.pub пригоден только для dnstt.

---

#### 11–15. Остальные страны (кратко)

Везде первый кандидат — резолвер сети по UDP 53. Национальных публичных резолверов не найдено, статус DoH/DoT не подтверждён.
- **Турция.** В 2014 году трафик к 8.8.8.8 перехватывали маршрутизацией, а резолверы ISP подделывали ответы ([Bortzmeyer](https://www.bortzmeyer.org/dns-routing-hijack-turkey.html) **[<2023]**). За январь–май 2024 года заблокировано 139 519 доменов ([İFÖD](https://ifade.org.tr/en/news/at-least-139-519-domains-blocked-in-january-may-2024/)). Значит, «иностранный» UDP-резолвер может оказаться подменой.
- **Египет.** DPI, троттлинг и TCP-инъекции на сетях TE Data, Vodafone и Noor ([OONI 2016](https://ooni.org/post/egypt-network-interference/) **[<2023]**). Свежих данных нет.
- **Пакистан.** Есть упоминания DNS-инъекций и обрывов по SNI ([агрегатор](https://corpus.lantern.io/censors/pk/), не подтверждено). Пробы файрвола против VPN шли в 2024 году.
- **Мьянма.** Провайдеры блокируют и через DNS, и по IP. Пользователи, работающие через публичные резолверы, искажают картину измерений ([OONI](https://lists.torproject.org/mailman3/hyperkitty/list/ooni-talk@lists.torproject.org/thread/DNO2K5A2XKWY7YNIO7DDLBL2XPAACQRZ), [Raman 2023](https://corpus.lantern.io/findings/2023-raman-advancing__myanmar-public-resolver-masks-ip-blocking/)). С мая 2024 года блокируются VPN.
- **ОАЭ.** Etisalat и du, по утверждениям вендоров, показывают страницы блокировки через DNS (не подтверждено).
- Сравнение DoH-даунгрейдов по 110 странам за 2023 год есть в [CoNEXT 2024](https://doi.org/10.1145/3696385). Цифры по странам извлечь не удалось.

#### Итог для клиента

1. Сначала берите резолверы из LinkProperties, затем национальные или внутренние публичные резолверы по UDP 53, затем DoT/DoH только там, где они не заблокированы. Яндекс в России ставьте последним.
2. Клиенту нужен быстрый скоринг кандидатов (раздел 0) и работа сразу через несколько резолверов.
3. На сервере держите `-mtu` в диапазоне 512–1232 и запасные непубличные домены. Логируйте EDNS, 0x20 и QNAME minimisation по каждому резолверу.

### Несколько резолверов и поиск в сети клиента


Дата: 2026-11-05. Это исследование, а не изменения в коде: я читал исходники и документацию, сетевых тестов против резолверов не запускал.
Пометка **[не подтверждено]** означает, что утверждение я не смог проверить по первичному источнику. Ссылки на код закреплены за конкретным коммитом:

| Репозиторий | Коммит (дата) |
|---|---|
| dnstt (`https://www.bamsoftware.com/git/dnstt.git`) | `0c5c52a5`, тег v1.20260501.0 |
| [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN/tree/4052a6b95e758adf2dc26fa1fe527457e58d627c) | `4052a6b9` (2026-11-02) |
| [EndPositive/slipstream](https://github.com/EndPositive/slipstream/tree/e158a681f1cc5cb000a92274371e67237d2a6493) | `e158a681` (2026-10-03) |
| [SagerNet/sing-box](https://github.com/SagerNet/sing-box/tree/9f1cd1ef75b7999bb118a9322a003f6edce2752d) | `9f1cd1ef` (2026-11-03) |
| AOSP [NetworkStack](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/83ea07ed94890b52265e07d6760c7ed8f4cbd344) / [DnsResolver](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/4d70e9efa5ae4b5eae682e5267fa09a2d694d23e) | `83ea07ed` / `4d70e9ef` (последний публичный `main`, март 2025) |

#### Главное

1. **Несколько резолверов в одной сессии работают уже сейчас, и для dnstt серверную часть менять не нужно.** Сервер dnstt узнаёт сессию по ClientID внутри запроса, а не по адресу, с которого пришёл запрос. Ответ он шлёт тому резолверу, который задал вопрос. KCP переставленные пакеты переносит. Этим уже пользуется XDNS в Xray-core: там round-robin по резолверам в одной mKCP-сессии, PR смержен 2026-04-11, сервер не меняли. В MasterDnsVPN всё это встроено: балансировщик, дублирование, health-check, MTU-проба для каждого резолвера.
2. **Рекомендация:** вариант (a), но вместо чистого round-robin нужен взвешенный планировщик: у каждого резолвера свой лимит запросов в полёте с AIMD, карантин при отказах и фоновая перепроверка. Дублирование (c) включать только для управляющих пакетов и при высоких потерях. Multipath QUIC (b) не рекомендую: стандарта всё ещё нет, в Go реализации нет, а автор slipstream-rust от этого подхода отказался.
3. **Поиск резолвера:** на практике для Android-приложения пригодны три вещи. `LinkProperties.getDnsServers()`. Признак того, что Android сам поднял DoT до резолвера провайдера: `isPrivateDnsActive()` при `getPrivateDnsServerName()==null`. И собственный SVCB-запрос DDR из Go. DNR приложению недоступен.
4. **DDR у провайдеров почти не развёрнут.** Больше 97% DDR-ответов указывают на Google, Cloudflare, Cisco или Quad9. Собственный DoE-резолвер провайдера внутри своей AS указывают около 0,7% резолверов. Данных по DoT/DDR у провайдеров RU/KZ/UZ/IR/CN/TR отдельно по странам я не нашёл.
5. **Проба резолвера:** около 5 запросов и меньше 3 секунд. Наш авторитетный сервер в ответе на пробу сообщает то, что видит только он: EDNS-размер резолвера, 0x20, QNAME-минимизацию, TCP, повторы и AS выходного адреса резолвера.

---

#### Часть A. Одна сессия через несколько резолверов

##### A1. dnstt сегодня

- **Клиент принимает ровно один транспорт:** `-doh`, `-dot` или `-udp`. Если указать два, выходит ошибка `only one of -doh, -dot, and -udp may be given` (`dnstt-client/main.go:280-284, 395`). В режиме UDP все запросы уходят с одного сокета. В `TODO` по этому поводу записано, что в Туркменистане UDP-ассоциации с одинаковым 4-tuple блокируются через несколько секунд, и предложено открывать отдельный сокет на каждый запрос (`TODO`, раздел «Randomize the source port…», ссылка на ntc.party/t/475). Для DoH запросы и так идут параллельно через несколько `sendLoop` (`dnstt-client/http.go:62-75`).
- **Сервер от адреса не зависит.** В каждом запросе есть 8-байтовый ClientID и случайный паддинг против кэширования (`dnstt-client/dns.go:278-336`). Сервер достаёт ClientID и кладёт пакеты в очередь этой сессии (`dnstt-server/main.go:519-534`). Ответ уходит на `rec.Addr`, то есть тому, кто прислал запрос (`main.go:674`). Поэтому запросы одной сессии через разные резолверы сервер собирает без каких-либо изменений. Это прямо следует из дизайна Turbo Tunnel ([Fifield, FOCI 2020](https://www.usenix.org/conference/foci20/presentation/fifield)).
- **Как настроен KCP:** окно перегрузки отключено (`nc=1`), быстрый перезапрос тоже (`resend=0`) (`dnstt-client/main.go:191-200`). Переставленные пакеты из-за этого не вызывают ложных fast-retransmit. Остаётся только повтор по RTO. Если у резолверов сильно разный RTT, RTO растёт, и медленный резолвер начинает вызывать лишние повторы.
- **Свойства сервера, важные для пробы (часть B):**
  - DNS слушается только по UDP (`main.go:935`), бит TC сервер не ставит.
  - На любой QTYPE, кроме TXT, сервер отвечает **NXDOMAIN** (`main.go:451-459`). Автор сам подозревает, что такие запросы приходят из-за QNAME-минимизации.
  - Если запрашивающий объявил EDNS-размер меньше 1232, сервер отвечает FORMERR (`main.go:98`).
  - Ответ сервер держит не дольше 1 секунды (`maxResponseDelay`, `main.go:78`).
- **Форки:**
  - [net2share/vaydns PR #64](https://github.com/net2share/vaydns/pull/64) (MultiResolver с health-check). Рецензент возражал против round-robin, PR закрыт без слияния 2026-11-03. Логику вынесли в [hiddify/hmrd_multi_resolver_dns](https://github.com/hiddify/hmrd_multi_resolver_dns).
  - [hiddify/vaydns PR #1](https://github.com/hiddify/vaydns/pull/1): повторяемые `-udp/-doh/-dot`, round-robin среди живых, ответы с RCODE≠0 считаются по каждому резолверу отдельно, при ошибке транспорта следующий живой. Тоже закрыт.
  - В основной ветке VayDNS несколько резолверов не поддерживаются: в README сказано «Transport (pick one)» ([README](https://github.com/net2share/vaydns)).
  - hmrd — Go-библиотека для встраивания в hiddify-sing-box. Стратегии LBAuto/RR/Weighted/LowestLatency, лимит запросов на каждый резолвер подбирается по AIMD. REFUSED, SERVFAIL и HTTP 429 считаются сигналом rate-limit, а не отказа. Есть hedging и fanout. Статус pre-1.0, лицензия не определена.
  - [Xray-core PR #5872](https://github.com/XTLS/Xray-core/pull/5872), XDNS поверх mKCP: список `resolvers`, по сокету на каждый резолвер, round-robin. Серверные правки откатили, потому что «сервер и так принимает данные от разных DNS-источников». Смержен 2026-04-11. Без failover умерший резолвер забирает свою долю пропускной способности: при трёх резолверах и одном мёртвом это примерно −1/3.
  - Внешний балансировщик anonvector/DNS-Multiplexer ([карточка](https://awesome.ecosyste.ms/projects/github.com%2Fanonvector%2Fdns-multiplexer)) **[не подтверждено, репозиторий не читал]**.

##### A2. MasterDnsVPN

По README и коду (`README.MD:602-642`):

- **Выбор резолвера:** `RESOLVER_BALANCING_STRATEGY` задаёт одну из 8 стратегий: RR, Random, Least Loss, Lowest Latency, Hybrid, Loss-then-Latency и две top-tier. У каждого потока есть предпочтительный резолвер с переключением при повторах: `STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD`, `…_COOLDOWN`.
- **Дублирование:**
  - `PACKET_DUPLICATION_COUNT` (по умолчанию 2) и `SETUP_PACKET_DUPLICATION_COUNT`.
  - [`SelectTargets`](https://github.com/masterking32/MasterDnsVPN/blob/4052a6b95e758adf2dc26fa1fe527457e58d627c/internal/client/balancer.go#L935-L980) возвращает предпочтительный резолвер плюс N−1 других уникальных. Планировщик отправляет копию фрейма в каждый из них ([`async_runtime.go:543-560`](https://github.com/masterking32/MasterDnsVPN/blob/4052a6b95e758adf2dc26fa1fe527457e58d627c/internal/client/async_runtime.go#L543-L560)).
  - Сервер может повторять последний управляющий блок: `PACKET_BLOCK_CONTROL_DUPLICATION` (`README.MD:791`).
- **Здоровье резолверов:**
  - `AUTO_DISABLE_TIMEOUT_SERVERS`: отключать резолвер, если за окно 30 секунд от него были одни таймауты.
  - `RECHECK_INACTIVE_SERVERS_ENABLED`: перепроверять отключённые в фоне.
  - MTU для каждой пары «резолвер × домен» подбирается двоичным поиском. Пробы зашифрованы и содержат 4-байтовый код, который сервер возвращает обратно ([`mtu.go:981-1360`](https://github.com/masterking32/MasterDnsVPN/blob/4052a6b95e758adf2dc26fa1fe527457e58d627c/internal/client/mtu.go#L981)).
  - Список резолверов можно задать CIDR-диапазоном, то есть клиент умеет сканировать (`README.MD:832-878`).
- **Android:** `FD_CONTROL_UNIX_SOCKET` передаёт fd каждого исходящего сокета хосту, чтобы тот вызвал `VpnService.protect` (`README.MD:614`).
- **Сервер:** сессия опознаётся по SessionID внутри пакета (uint8) и cookie ([`vpnproto/builder.go:13-45`](https://github.com/masterking32/MasterDnsVPN/blob/4052a6b95e758adf2dc26fa1fe527457e58d627c/internal/vpnproto/builder.go#L13-L45)), поэтому сервер тоже не зависит от резолвера. Попутно для нашего форка: `maxServerSessionID = 255` (`internal/udpserver/session.go:31-32`), то есть на одном сервере не больше 255 одновременных сессий.

##### A3. slipstream, другие проекты и исследования

- **slipstream** ([protocol.md](https://github.com/EndPositive/slipstream/blob/e158a681f1cc5cb000a92274371e67237d2a6493/docs/protocol.md)):
  - QUIC (picoquic) с multipath-расширением, один путь на один резолвер. `--resolver` можно указать несколько раз ([`slipstream_client_cli.cpp:12`](https://github.com/EndPositive/slipstream/blob/e158a681f1cc5cb000a92274371e67237d2a6493/src/slipstream_client_cli.cpp#L12)), пути добавляются через `picoquic_probe_new_path_ex` ([`slipstream_client.c:284-310`](https://github.com/EndPositive/slipstream/blob/e158a681f1cc5cb000a92274371e67237d2a6493/src/slipstream_client.c#L284-L310)).
  - На сервере у входящих пакетов адрес источника подменяется фиктивным. Из-за этого приходится вручную отключать PATH_CHALLENGE/RESPONSE и миграцию.
  - Управление перегрузкой: на клиенте DCUBIC, на сервере отключено. Сигналы потерь из-за перестановки игнорируются, используется только RACK, потому что «DNS messages may be received out of order by hundreds of packets».
  - Минимальный размер Initial в 1200 байт пришлось уменьшить.
- **Mygod/slipstream-rust:** заархивирован, см. [discussion #111](https://github.com/Mygod/slipstream-rust/discussions/111) от 2026-08-28. Автор пишет, что MP-QUIC «gives us some machinery for multiple paths, but it does not give us that resolver policy». Пришлось накопить слой совместимости: poll-фреймы, свои ACK и loss, изменённый CC, отдельную обработку путей. Сейчас автор считает правильным свой лёгкий транспорт с ARQ, как в MasterDnsVPN.
- **iodine** работает с одним relay. Тип запроса, кодировку upstream (Base32/64/128 с проверкой, сохраняет ли relay регистр) и размер фрагмента он определяет автоматически ([README](https://github.com/yarrick/iodine/blob/master/README.md)). Это хороший прецедент для пробы из B3. **dns2tcp** тоже работает с одним сервером ([README](https://github.com/alex-sector/dns2tcp)).
- **Tor:** официального DNS-транспорта нет. Есть тикет [#15213](https://gitlab.torproject.org/legacy/trac/-/issues/15213) и [план 2020 года](https://archive.torproject.org/websites/lists.torproject.org/pipermail/anti-censorship-team/2020-May/000089.html) (dnstt как PT, «примерно GSoC»). Внедрение **[не подтверждено]**.
- **Исследования:** рецензируемых работ именно про multipath DNS-туннели через несколько резолверов я не нашёл. Самое близкое — бенчмарк [EndPositive/dns-tunneling-benchmark](https://github.com/EndPositive/dns-tunneling-benchmark), он мерит один резолвер. Работа [Lange, Niere, Somorovsky, FOCI 2026](https://www.petsymposium.org/foci/2026/foci-2026-0001.php) описывает DPYProxy-DNS, который сам перебирает 8 способов доставки DNS по списку публичных резолверов. Результат: в Иране DoQ работал со всеми резолверами, а UDP+wait не работал ([обсуждение в net4people #581](https://github.com/net4people/bbs/issues/581)).
- **net4people:** [#586](https://github.com/net4people/bbs/issues/586) про отключение интернета в Иране с 2026-02-28. Там «DNS tunnels are the only thing that is so far known to work». Главной проблемой был поиск рабочего резолвера: несколько резолверов были доступны с обеих сторон, но в основном без DoT и DoH, а 8.8.8.8 открывался только у части провайдеров. Операторы держали dnstt, slipstream, MasterDnsVPN и XDNS за одним dns-router.

##### A4. Варианты дизайна для нас

| | (a) Пакеты по резолверам в одной KCP/ARQ-сессии | (b) Multipath QUIC, путь на резолвер | (c) Дублирование через 2 резолвера |
|---|---|---|---|
| Клиент | `net.PacketConn`-мультиплексор над N транспортами. В dnstt `DNSPacketConn` и так принимает произвольный `transport`. Плюс планировщик и статистика по каждому резолверу | Замена KCP+smux+Noise на MP-QUIC. В Go реализации нет ([quic-go #3343](https://github.com/quic-go/quic-go/issues/3343) **[статус не подтверждён]**), остаётся picoquic через cgo | Отправка копии через другой резолвер. Upstream дедуплицируется номерами KCP/ARQ |
| Сервер | dnstt: ничего, как и в XDNS. MasterDnsVPN: уже есть | Новый сервер (по образцу slipstream), подмена адресов, отключение проверки путей | Ничего, если копии уникальны. Чтобы дублировался и downstream, нужен memo «тот же QNAME — тот же ответ» |
| Заметность | Объём на канале тот же, что при одном резолвере. Новый признак — число разных резолверов у одного клиента. Нагрузка на каждый резолвер ниже, а зону видит больше операторов | Как (a), плюс QUIC-специфика (уменьшенный Initial) | Объём запросов ×2 при 2 копиях, это самый заметный вариант |
| Кэш и rate-limit | Запросы уникальны, кэш не мешает. Ограничение на клиента у каждого резолвера своё. У Google по умолчанию 1500 QPS на IP или /64 ([docs](https://developers.google.com/speed/public-dns/docs/isp)). В Unbound есть `ratelimit` на зону (по умолчанию выключен, [unbound.conf](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)): распределение по резолверам и по зонам его обходит | Как (a) | Одинаковый QNAME через резолверы с общим бэкендом может прийти из кэша или слиться в один запрос (Google держит не больше одного незавершённого запроса на имя, тип и адрес назначения, [security](https://developers.google.com/speed/public-dns/docs/security)). Rate-limit срабатывает вдвое быстрее |
| Сложность | Низкая или средняя | Высокая. Черновик [draft-ietf-quic-multipath-21](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21) ещё не RFC | Низкая |

**Чего не хватает round-robin.** Мёртвый резолвер или резолвер с rate-limit забирает свою 1/N запросов, и это стоит пропускной способности (Xray #5872). Резолверы с разным RTT раздувают RTO. Поэтому предлагаю такую схему:

- У каждого резолвера окно запросов в полёте с AIMD: рост на успехе, деление пополам на таймауте, REFUSED, SERVFAIL или HTTP 429.
- Следующий запрос, в том числе poll, уходит резолверу с наибольшим свободным окном и с учётом доли успешных ответов.
- После N подряд таймаутов или подделанного ответа резолвер уходит в карантин. Его перепроверяет проба из B3 с backoff 30 секунд → 10 минут, живой трафик для этого не используется (так делает hmrd).
- Для UDP у каждого резолвера отдельный сокет с периодической сменой порта (см. TODO dnstt).
- На сервере стоит добавить memo ответов по QNAME на несколько секунд. Сейчас повтор того же запроса резолвером считается новой возможностью отправить данные. Резолвер берёт первый ответ, второй выбрасывает, и вложенные во второй данные теряются.

**Рекомендация по A:** для dnstt сделать (a) с описанным планировщиком только на стороне клиента. Для MasterDnsVPN использовать то, что уже есть: стратегию Least Loss или Hybrid, `PACKET_DUPLICATION_COUNT=1` для данных и 2 для setup и control. Дублирование (c) включать только для управляющих пакетов или когда измеренные потери выше примерно 10–15%. От (b) отказаться. Одновременно использовать 2–4 резолвера, по возможности те, которыми устройство и так пользуется: резолвер провайдера, его DoT/DoH и один публичный.

---

#### Часть B. Автоматический поиск и проверка резолверов

##### B1. Стандарты и что из них доступно

| Механизм | Что даёт | Android-приложение без root | Go (sing-box) |
|---|---|---|---|
| `LinkProperties.getDnsServers()` (API 21), `getDhcpServerAddress()` (API 30) ([docs](https://developer.android.com/reference/android/net/LinkProperties)) | Адреса DNS-серверов сети | Да, через `ConnectivityManager.getLinkProperties(network)` для базовой сети, не для VPN | Через platform interface libbox (адреса передаёт Kotlin) |
| Private DNS: `isPrivateDnsActive()`, `getPrivateDnsServerName()` (API 28) | `active && name==null` значит, что opportunistic DoT до DNS-сервера сети **прошёл валидацию**. Если `name≠null`, включён strict-режим с хостнеймом пользователя | Да | Через platform interface |
| Автоматический DoT в Android | С Android 9 по умолчанию система сама пробует TLS на :853 к каждому DNS-серверу сети ([блог, 2018](https://android-developers.googleblog.com/2018/04/dns-over-tls-support-in-android-p.html)). Валидационный запрос — `<random>-dnsotls-ds.metric.gstatic.com` (`DnsTlsTransport.cpp:46`). Повтор с 1 минуты с backoff до раза в час (`PrivateDnsConfiguration.cpp:353`). **Сертификат в opportunistic-режиме не проверяется**: `SSL_VERIFY_PEER` ставится только при непустом имени (`DnsTlsSocket.cpp:238-250`) | Результат виден через предыдущую строку | — |
| DoH в Android | В opportunistic-режиме только по встроенному списку: Google и Cloudflare (`PrivateDnsConfiguration.h:276-290`, `.cpp:650-680`). DoH3 с Android 11 ставится через Play system update ([пересказ блога Google](https://thehackernews.com/2022/07/google-adds-support-for-dns-over-http3.html); исходный пост был недоступен, 503) | Нет, это внутреннее устройство системы | — |
| DDR, RFC 9462 ([RFC](https://www.rfc-editor.org/rfc/rfc9462.html)) | SVCB-запрос `_dns.resolver.arpa`: alpn, порт, `dohpath`. Verified Discovery требует сертификат с IP исходного резолвера (§4.2). Opportunistic-режим разрешён только для частных адресов и только если адрес тот же (§4.3) | В Android DDR реализован в `DdrTracker` NetworkStack, но закрыт экспериментальным флагом `dns_ddr_version` и учитывает только ALPN `h3` (`DdrTracker.java:81-83, 391-415`; `NetworkMonitor.java:677-682`). Включён ли флаг по умолчанию, **[не подтверждено]**. Приложение может само отправить SVCB-запрос | Да: miekg/dns (его уже использует sing-box) поддерживает SVCB. Запрос уходит через защищённый сокет |
| DNR, RFC 9463 ([RFC](https://www.rfc-editor.org/rfc/rfc9463.html)) | DHCPv4 162, DHCPv6 144, RA 144: ADN, адреса, SvcParams | Нет. В NetworkStack разбора DNR нет: поиск по `DNR` и `162` в `main` от марта 2025 ничего не находит. Приложение не видит ни DHCP-lease, ни RA. В сотовых сетях DHCP нет | Транспорт `dhcp` в sing-box слушает `:68` (`dns/transport/dhcp/dhcp.go:389-402`). На Android без root это привилегированный порт **[не проверял]** |
| Системный резолвер (вид `net`) | `DnsResolver.rawQuery` (API 29) отправляет произвольный запрос, в том числе TXT, через резолвер ОС. Если Android уже поднял DoT, запрос пойдёт по DoT | Да. SFA так и делает ([`LocalResolver.kt:23,57`](https://github.com/SagerNet/sing-box-for-android/blob/a548a7903e96266a0046018562c73b192edbfc18/app/src/main/java/io/nekohasekai/sfa/bg/LocalResolver.kt)) | `LocalDNSTransport.Exchange` ([`libbox/dns.go:23-27`](https://github.com/SagerNet/sing-box/blob/9f1cd1ef75b7999bb118a9322a003f6edce2752d/experimental/libbox/dns.go#L23-L27)). Есть ограничитель одновременных запросов на UID (`DnsProxyListener.cpp:82-87`) |
| Apple | iOS 16 и macOS 13: DDR с проверкой, что IP есть в сертификате; для частных IP не работает ([WWDC22 10079](https://developer.apple.com/videos/play/wwdc2022/10079/)). DNR в сессии не упоминается | — | — |
| Windows | DDR ([MS blog](https://techcommunity.microsoft.com/blog/networkingblog/making-doh-discoverable-introducing-ddr/2887289)). DNR в Insider build 25982 ([Techzine](https://www.techzine.eu/news/applications/112581/microsoft-adds-dnr-in-windows-11-insider-preview-build), вторичный источник) | — | — |

Вывод по B1: самый дешёвый и самый надёжный сигнал — состояние Private DNS. Если Android сам провалидировал DoT до резолвера провайдера, вид `dot` к тому же IP:853 работает, а ClientHello к этому адресу у устройства уже бывает (наш uTLS-отпечаток стоит приблизить к BoringSSL-отпечатку DnsResolver). Вид `net` даёт трафик, неотличимый от трафика ОС, но не позволяет управлять параллельностью.

##### B2. Насколько DDR, DNR и DoT развёрнуты у провайдеров

- **PoPETs 2025** ([Ververis, Sassalla, Roth, Bajpai](https://www.petsymposium.org/popets/2025/popets-2025-0140.pdf)), измерения июль–ноябрь 2024:
  - около 309 тыс. IPv4-резолверов с DDR;
  - **больше 97%** из них отправляют клиентов к Google, Cloudflare, Cisco или Quad9, из них к Google около 79%;
  - среди резолверов категории «Network Services» (это провайдеры) свой DoE-резолвер в той же AS указывают **0,71%** (IPv6: 1,21%);
  - Verified Discovery проходят меньше 0,005% пар (§3.6, §6). То есть DDR-клиент по стандарту в больше чем 99% случаев не сможет переключиться на шифрование;
  - §5.4 описывает «traffic shadowing»: уникальные QNAME повторно приходили на авторитетный сервер. Перехват происходил чаще всего в Китае (22%) и России (около 15%), повторы шли через Google, Cloudflare и Yandex. Нашему серверу нужно спокойно переносить такие повторы проб.
- **IFIP Networking 2025** ([Sassalla et al.](https://vaibhavbajpai.com/documents/papers/proceedings/ddr-networking-2025.pdf)): DDR отвечают 7,3% корректно отвечающих IPv4-серверов. В топ-10 AS по числу DDR-резолверов входят TC Iran (AS58224, 4 086 резолверов) и Chinanet (AS4134, 1 814 резолверов). Почти все они указывают на `dns.google`, то есть это открытые форвардеры, скорее всего CPE, а не DoE-инфраструктура провайдера.
- **DoT у провайдеров по странам** RU/KZ/UZ/IR/CN/TR: измерений я не нашёл **[нет данных]**. Есть косвенные данные:
  - **Россия, август 2026:** сообщения о блокировке DoT к 1.1.1.1 и DoH к dns.google у нескольких операторов ([comss.ru, 2026-08-25](https://www.comss.ru/page.php?id=21721), вторичный источник). Есть также утверждение, что UDP/53-запросы к 8.8.8.8 прозрачно перенаправляются на НСДИ (195.208.5.1) ([mentoday, 2026-08-31](https://www.mentoday.ru/technics/news/31-08-2026/populyarnyi-sposob-obhoda-blokirovok-perestal-rabotat-rkn-nachal-perehvatyvat-dns-google-i-cloudflare/)) **[не подтверждено, без методики]**.
  - **Иран:** во время отключений внешние резолверы закрывали. Внутренние резолверы в основном без DoT и DoH ([#586](https://github.com/net4people/bbs/issues/586)), DoT в Иране блокировался ещё в 2020 году ([OONI](https://msg.ooni.io/post/2020-iran-dot/)).
  - Отсюда практический вывод: «8.8.8.8 отвечает» ещё не значит, что отвечает Google. Это проверяет только токен от нашего сервера плюс AS выходного адреса резолвера (см. B3).
- ntc.party из этой сессии был недоступен, поэтому треды оттуда я цитирую только по вторичным источникам.

##### B3. Проба кандидата: туннель через него работает или нет

Запросы идут в отдельную подзону `p.<zone>`. В первой метке случайный nonce, во второй HMAC(probe_key, nonce‖команда) — это защита от использования зоны для усиления, о ней ниже. Все запросы уникальны. Проба идёт параллельно по 3–5 кандидатам, общий бюджет около 3 секунд, после ~1 секунды без ответа на шаге 1 кандидат отбрасывается.

| # | Запрос | Что проверяется | Успех |
|---|---|---|---|
| 1 | `TXT n.h.p.zone` | Резолвер пересылает делегированную зону, ответ свежий и не из кэша, TXT доходит целым | TXT с тем же nonce и отчётом сервера (ниже). Таймаут — зону дропают; SERVFAIL — до сервера не достучаться; NXDOMAIN или чужой ответ — перехват или RPZ |
| 2 | `TXT n.nx.p.zone` | Подменяет ли резолвер NXDOMAIN (такую же проверку делает [findns](https://github.com/SamNet-dev/findns)) | NXDOMAIN с SOA |
| 3 | QNAME длиной 160 и 253 октета (метки по 63) | Пропускная способность upstream: длинные имена не режутся | Сервер возвращает длину и хэш принятого имени |
| 4 | Ответ на 512, 1200 и 4000 байт (EDNS0 клиента 1232 или 4096) | Пропускная способность downstream, TC, целостность. Для UDP: при TC повтор по TCP к резолверу | Хэш совпал. Если резолвер объявил серверу EDNS меньше 1232, dnstt не будет работать (FORMERR) |
| 5 | Burst из 30–50 запросов примерно за 1 с, параллельность 8–16 | Rate-limit и начальное окно для AIMD | Доля успешных ответов, p50 и p95 RTT, число REFUSED и SERVFAIL |
| 6 (опц.) | Сервер задерживает ответ на 0,5, 1 или 2 с | Сколько резолвер ждёт; от этого зависит, как долго сервер может держать long-poll | Максимальная задержка, после которой ответ ещё доходит |
| 7 | Рукопожатие туннеля: Noise NK у dnstt, session-init и MTU-пробы у MasterDnsVPN | Аутентификация сервера и настоящий MTU | Сессия установлена |

**Отчёт сервера в TXT шага 1** (для экономии места пары ключ=значение):

- `edns`: размер, который резолвер объявил *нашему* серверу;
- `do`: бит DO;
- `x20`: были ли в принятом QNAME буквы разного регистра ([draft-vixie-dnsext-dns0x20](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00); Google использует 0x20 только для «правильных» серверов, [security](https://developers.google.com/speed/public-dns/docs/security));
- `qmin`: видел ли сервер в последние секунды A- или NS-запрос к усечённому имени-предку nonce ([RFC 9156](https://www.rfc-editor.org/rfc/rfc9156.html) §2.1, §2.3);
- `tcp`: пришёл ли запрос по TCP;
- `dup`: сколько копий запроса пришло;
- `ecs`: был ли EDNS Client Subnet (только 0 или 1);
- `eas`: AS выходного адреса резолвера (по образцу `resolver_asn` в [OONI](https://github.com/ooni/spec/blob/master/data-formats/df-000-base.md)).

Поле `eas` отличает «ISP-резолвер сам ходит к нам» от «ISP-резолвер переправляет запросы в Google» и от прозрачного перенаправления.

**Что нужно на нашем авторитетном сервере** (общий модуль для форков dnstt и MasterDnsVPN):

1. Обработчик подзоны `p.` с короткой памятью по nonce (5–10 с) для полей `qmin`, `x20` и `dup`. Ничего не писать на диск.
2. На имена внутри зоны с другим QTYPE и на пустые нетерминальные узлы отвечать **NOERROR/NODATA**, а не NXDOMAIN, как сейчас делает dnstt. По RFC 9156 §3 резолвер с поддержкой [RFC 8020](https://www.rfc-editor.org/rfc/rfc8020.html), получив NXDOMAIN на предка, обязан вернуть NXDOMAIN на исходный запрос. Насколько это реально ломает dnstt с минимизирующими резолверами, я не измерял **[не подтверждено]**.
3. Слушать TCP/53 для пути «TC → TCP»: dnstt сейчас работает только по UDP.
4. Большие ответы (шаг 4) отдавать только при верном HMAC, а размер ответа на UDP ограничивать. Иначе нашей зоной можно воспользоваться для отражённого усиления через открытые резолверы.
5. Не отражать ECS и не логировать его: ECS раскрывает /24 клиента ([RFC 7871](https://www.rfc-editor.org/rfc/rfc7871.html)).
6. Отвечать идемпотентно на повторы: резолверы повторяют запросы сами, а «shadowing» из PoPETs §5.4 даёт повторы от третьих сторон.
7. probe_key: в MasterDnsVPN его можно вывести из общего ключа. В dnstt ключ Noise публичный, поэтому нужен отдельный ключ в конфиге. Можно и не аутентифицировать пробу, а полагаться на шаг 7.

**Заметность.** Проба выглядит как сам туннель: высокоэнтропийные TXT к нашей зоне. Не стоит сканировать десятки резолверов сразу, как это умеет MasterDnsVPN с `MTU_TEST_PARALLELISM`: телефон, который опрашивает много резолверов подряд, заметен на канале. Тестировать надо системные и DDR-кандидаты и короткий список подсказок по AS.

##### B4. Обмен результатами по автономным системам

- **Минимальный отчёт** (согласован): AS клиента, вид (`net/udp/doh/dot`), результат, загрублённые метрики (корзины MTU и QPS), день. AS определять так же, как OONI: сервер узнаёт его по IP при приёме отчёта и тут же IP выбрасывает ([OONI data policy](https://ooni.org/about/data-policy/)). Если отчёт идёт через туннель, IP клиента сервер вообще не видит.
- **Можно ли отдавать адрес резолвера.** Адрес резолвера провайдера персональными данными не является: OONI публикует `resolver_ip` и `resolver_asn` открыто. Но есть риски, и на каждый нужна мера:
  1. **Редкий адрес идентифицирует.** Резолвер маленького офиса, VPS-резолвер пользователя или региональный резолвер сужают круг до организации или города. Мера: порог k=10 считать для кортежа *(AS, вид, адрес)*, а не для AS. Считать уникальных клиентов (псевдоним с суточной солью), а не число отчётов.
  2. **Частные адреса.** RFC1918, CGNAT 100.64/10, link-local и ULA не публиковать никогда: обычно это домашний роутер, для других пользователей он бесполезен.
  3. **Отравление (Sybil).** Цензор может продвигать подконтрольный резолвер, чтобы собирать IP пользователей туннеля. Меры:
     - принимать подсказку, только если адрес резолвера в той же AS, что и клиент, или это известный публичный оператор;
     - сверять с `eas` из пробы;
     - k считать только по пользователям, привязанным к аккаунту;
     - клиент всегда проверяет подсказку сам, а туннель аутентифицирован сквозным образом.
  4. **Подсказка для цензора.** Список показывает, какие резолверы провайдера пропускают нашу зону, и цензор может точечно закрыть её через RPZ. Сам провайдер и так видит зону в логах, поэтому риск умеренный. Мера: отдавать подсказки только клиентам той же AS, не держать глобальный список, ставить TTL 7–14 дней.
  5. **География узла.** Агрегаты «у этого узла есть ≥10 пользователей в AS X» раскрывают аудиторию узла. Наружу их не отдавать, только как подсказку внутри AS.
- **Источник без клиентских отчётов.** Авторитетный сервер и так видит выходной адрес каждого резолвера. Агрегат «AS выхода → число различных ClientID в сутки» показывает, что резолверы провайдера X пересылают зону, и IP клиента для этого не нужен. Входной адрес резолвера сервер, правда, не видит, поэтому адрес для подсказки всё равно приходит от клиента.

---

#### Рекомендации

1. **dnstt (клиент в sing-box):** `MultiResolverPacketConn` над 2–4 транспортами с планировщиком по AIMD-окну, карантином и перепроверкой пробой. Отдельный UDP-сокет на каждый резолвер со сменой порта. Сервер для этого менять не нужно. Как основу взять hmrd (лицензию надо уточнить) или PR из Xray-core.
2. **niko-server (оба форка):** обработчик пробы `p.<zone>` (B3); NOERROR/NODATA вместо NXDOMAIN для других QTYPE и предков; TCP/53; memo ответов по QNAME; HMAC и ограничение размера; никакого логирования ECS. Для MasterDnsVPN оценить лимит в 255 сессий.
3. **MasterDnsVPN:** использовать встроенный балансировщик. По умолчанию дублировать только setup и control (2), данные не дублировать (1), а при потерях выше ~10–15% включать дублирование данных автоматически.
4. **Порядок поиска на Android:**
   1. Получить `LinkProperties` базовой сети.
   2. Если Private DNS активен, взять `dot://<ISP-IP>:853` (или strict-хостнейм).
   3. Отправить DDR SVCB к каждому DNS-серверу; ответ, указывающий на крупного публичного оператора, понизить в приоритете.
   4. Добавить `net` (rawQuery) и `udp://<ISP-IP>:53`.
   5. Добавить подсказки по AS от узла.
   6. Добавить короткий встроенный список.

   Каждого кандидата прогнать через пробу B3 и запомнить результат на сеть (SSID или оператор плюс AS) на 24 часа.
5. **DNR** не реализовывать: он недоступен ни приложению, ни на сотовой связи.
6. **Обмен результатами:** вид плюс AS с k=10 для всех. Адрес только для инфраструктуры провайдера, только внутри той же AS, с k=10 по кортежу и с проверкой по `eas`.

#### Что осталось непроверенным

- Включён ли флаг `dns_ddr_version` в серийных сборках Android и что изменилось после марта 2025: AOSP `main` после этого публично не обновлялся.
- Ломает ли NXDOMAIN от dnstt на не-TXT запросы работу через конкретные минимизирующие резолверы (Unbound и BIND в конфигурациях провайдеров).
- Статус multipath в quic-go; репозиторий DNS-Multiplexer; форк 32east/vaydns («stable multi-resolver», упомянут в PR #64).
- Измерения DoT и DDR у провайдеров RU/KZ/UZ/IR/CN/TR. Достоверность сообщений о прозрачном перенаправлении 8.8.8.8 на НСДИ.
