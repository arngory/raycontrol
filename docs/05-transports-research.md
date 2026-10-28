# 05. Исследование транспортов для режима белых списков

Статус: **исследование**, октябрь 2026 года. Сведения взяты из README и документации проектов;
код, безопасность и заявленная скорость нами не проверялись. Перед включением любого транспорта в ноду
нужен PoC (см. [04-roadmap.md](04-roadmap.md), этап M6).

## Главный вывод

Исследованные проекты решают другую задачу, чем VLESS и Hysteria2: они рассчитаны на режим **белых
списков**, когда до IP сервера нельзя достучаться вообще. Трафик идёт через разрешённую чужую
инфраструктуру: реле звонков VK, видеоконференции, сервисы документов, объектные хранилища, DNS-резолверы.

Для ноды это означает **четыре разных класса входа** вместо одного:

| Класс входа | Как трафик доходит до ноды | Входящий порт на ноде | Работает ли knock/SPA | Примеры |
|---|---|---|---|---|
| **direct** | Клиент подключается к IP ноды напрямую. | да | да | VLESS REALITY, Hysteria2, Naive, TrustTunnel |
| **relayed** | Клиент → TURN-реле платформы → нода. Источник — IP реле, а не клиента. | да | **нет** (IP клиента не виден) | qWDTT, CSQTT |
| **rendezvous** | И клиент, и нода сами подключаются к сторонней платформе (комната звонка, документ, бакет). | **нет** (только исходящие) | не применимо | olcRTC, OpenFlux, S3 Bypass |
| **dns** | Клиент → рекурсивный резолвер → нода как авторитативный DNS-сервер поддомена. | UDP 53 | **нет** (источник — резолвер) | dnstt, Slipstream, MasterDnsVPN |

И два класса выхода:

| Класс выхода | Что это | Что нужно на ноде |
|---|---|---|
| **L4** | Движок сам открывает TCP/UDP-соединения к цели (SOCKS-подобный выход). | Исходящий фильтр по UID процесса. |
| **L3** | Клиент получает IP-туннель (WireGuard, TUN); нода маршрутизирует пакеты. | TUN-интерфейс, `forward` и NAT для подсети, фильтрация по интерфейсу. |

## Сводная таблица

| Проект | Класс входа | Носитель | Аутентификация | Выход | Язык | Лицензия | Состояние | Вывод |
|---|---|---|---|---|---|---|---|---|
| qWDTT | relayed | WireGuard → DTLS → WRAP (RTP/Opus, ChaCha20-Poly1305) → TURN-реле VK | пароли пользователей (до 10), привязка устройства | L3 (WG, NAT) | Go (сервер), Kotlin (Android) | GPL-3.0 | экосистема форков, происхождение кода запутано | кандидат, PoC |
| CSQTT | relayed | TURN/RTP | не описана | TUN или SOCKS5 | Rust, Kotlin | **PolyForm Noncommercial** | **архивирован 20.10.2026**; версии 2.1 и 2.5 несовместимы | только наблюдать |
| olcRTC | rendezvous | WebRTC: Jitsi, Яндекс Телемост, WB Stream; datachannel или данные внутри видео | общий PSK (XChaCha20-Poly1305) | L4 (SOCKS5) | Go | WTFPL | бета; upstream архивирован, развивается как движок Ghostlane | кандидат, PoC |
| OpenFlux | rendezvous | сервисы документов: Яндекс Документы, Mail.ru, MAX/OneMe и др.; подключаемые JS-транспорты | согласование сессии; шифрование AES-256-GCM **опционально** | L3 (Linux, root) или L4 (gVisor) | Go | GPL-3.0+ | CI, релизы, клиенты под все ОС | кандидат, PoC |
| dnstt | dns | DNS (UDP, DoH, DoT), KCP + smux, Noise_NK | только ключ сервера | L4 (TCP к upstream) | Go | CC0 (public domain) | зрелый, медленный | базовый DNS-движок |
| Slipstream | dns | QUIC multipath поверх DNS (base32 в имени, TXT в ответах) | средствами QUIC | L4 (TCP) | C (picoquic); порты на Rust и Go | уточнить | несколько реализаций, у Rust-версии отметка о прекращении развития | наблюдать |
| MasterDnsVPN | dns | DNS, своя ARQ, балансировка по резолверам | общий ключ; шифрование выбирается, **включая None и XOR** | L4 (напрямую или через SOCKS5) | Go | MIT | очень активный (~7k звёзд, >1000 коммитов) | кандидат на основной DNS-движок, PoC |
| S3 Bypass | rendezvous | объекты в S3-бакете (Yandex Object Storage, VK Cloud, Selectel) | S3-ключи и префикс на клиента | L4 (freedom Xray) | Go (форк Xray с транспортом `fedarisha`) | MPL-2.0 (ядро), GPL-3.0 (приложение) | ранний; есть усиленный форк s3network с исправлением зависаний | кандидат, PoC |

## По проектам

### qWDTT (и WDTT)

- Схема: WireGuard внутри DTLS, поверх — слой WRAP, который упаковывает пакеты в RTP с типом Opus и
  шифрует ChaCha20-Poly1305 (ключ из пароля туннеля через HKDF). Всё идёт через TURN-реле звонков VK.
- Клиент получает временные TURN-учётные данные через групповой звонок VK по хэшу ссылки
  `vk.com/call/join/…` (до 4 хэшей), иногда решая капчу.
- Сервер `wdtt-server`: UDP 56000 (DTLS), WireGuard внутри на 56001, интерфейс `wdtt0`, подсеть `10.66.66.0/24`, NAT.
  Пароли в `/etc/wdtt/passwords.json`, перезагрузка по SIGHUP. Первый канал вызывает `GETCONF` и получает WireGuard-конфиг.
- Сопутствующие проекты: `ildarmaga/wdtt` (сервер + панель + REST API + Xray для маршрутизации выхода),
  клиенты для Android, Windows, Linux, iOS (VK Turn Proxy), пакет для OpenWrt.
- Для нас:
  - вход relayed: knock/SPA для него невозможны, периметр — только аутентификация в сервисе и ограничение источников;
  - выход L3: нужны TUN, `forward`, NAT и отдельная подсеть на инстанс;
  - ссылки на звонки создаются из **реального аккаунта VK** (панель WDTT хранит cookies `remixsid`) —
    это учётные данные третьей стороны с риском блокировки аккаунта;
  - пароль туннеля — единственный источник ключа WRAP, нужна высокая энтропия.

### CSQTT

- TURN/RTP-туннель с сервером на Rust; TUN или SOCKS5 у клиента; свой формат ссылок `csqtt://connect?v=2`.
- **Лицензия PolyForm Noncommercial** и **архивирован 20 октября 2026 года**. Версии протокола 2.1 и 2.5 несовместимы.
- Для нас: не включать, пока нет поддерживаемого форка с подходящей лицензией.

### olcRTC

- Зашифрованный TCP-туннель внутри WebRTC-сессии видеозвонка: Jitsi, Яндекс Телемост, WB Stream.
  Клиент и сервер заходят в одну комнату; сервер — участник звонка, который выходит в интернет.
- Транспорты: datachannel (быстрее всего, стабильно с Jitsi) или данные внутри видео
  (VP8, H264 SEI, QR/тайлы — экспериментально).
- Шифрование: XChaCha20-Poly1305, общий PSK, ключи по направлениям через HKDF, защита от повтора. smux поверх.
- Go, WTFPL, бета; есть gomobile-обвязка для Android и c-shared для встраивания в клиент.
- Для нас:
  - вход rendezvous: у ноды нет входящего порта, только исходящие соединения к платформе;
  - **нет пользователей**, только общий PSK: нужна внутренняя аутентифицированная ступень (см. 01-architecture);
  - нужны учётные данные платформ (Телемост, WB Stream требуют регистрации).

### OpenFlux

- TCP/UDP-туннель через сервисы совместной работы с документами; транспорты подключаемые,
  включая подписанные JS-скрипты (goja), можно добавлять без пересборки.
- Мультитранспортные сессии с переключением; пакетирование и zstd.
- Выход: L3 (raw forward, Linux, root) или L4 (userspace-стек gVisor, без root). Есть PHP-выход для хостинга без VPS.
- Шифрование AES-256-GCM **опционально** — в нашей ноде должно быть обязательным.
- Go-ядро, клиенты под macOS, Linux, Windows, iOS, Android; GPL-3.0+; CI на каждый push.
- Для нас: вход rendezvous; предпочтителен выход L4 (без root); нужны аккаунты на платформах документов;
  модель доверия подписанных JS-транспортов нужно разобрать отдельно.

### dnstt

- DNS-туннель с поддержкой DoH и DoT; KCP + smux + Noise_NK (аутентифицируется только сервер).
- Нужен свой домен и делегирование NS поддомена на ноду; UDP 53 (или высокий порт за резолвером).
- Выход — TCP к одному upstream (SSH, SOCKS, Tor ORPort). Лицензия CC0. Зрелый, но медленный.
- Для нас: эталонный DNS-движок; пользователей нет — upstream должен быть внутренней аутентифицированной ступенью.

### Slipstream

- QUIC multipath поверх DNS: каждый резолвер — отдельный путь, полосы суммируются.
  Накладные расходы 24 байта против 59 у dnstt. Шифрование и аутентификация — средствами QUIC.
- Реализации: исходная на C (picoquic, EndPositive), переписанная на Rust (Mygod, с отметкой о прекращении развития),
  Go-порт от Lantern без multipath.
- Для нас: наблюдать; выбрать реализацию только после проверки сопровождения и лицензии.

### MasterDnsVPN

- DNS-туннель со своей ARQ (окна, NACK, повторы), восемью режимами балансировки по резолверам,
  дублированием пакетов, проверкой здоровья резолверов и подбором MTU.
- Сервер на UDP 53 по NS-делегированию; выход напрямую или через внешний SOCKS5.
- Шифрование выбирается: None, XOR, ChaCha20, AES-GCM — в ноде разрешаем только AEAD.
- Пользователей нет, только общий ключ. Go, MIT, бинарники под множество архитектур, Docker.
- Заявлено «до 9× быстрее dnstt» — это данные автора без методики.
- Для нас: главный кандидат в DNS-класс; общий ключ закрываем внутренней ступенью.

### S3 Bypass (транспорт fedarisha)

- Клиент пишет трафик объектами в S3-бакет; сервер опрашивает бакет, ходит в интернет и пишет ответы обратно.
  Прямого соединения клиент–нода нет.
- Ядро — форк Xray с транспортом `fedarisha`; усиленный форк s3network исправляет зависания при потере объекта
  (сервер и клиент должны быть на форке).
- Учётные данные: S3-ключ сервера и отдельный ключ и префикс на каждого клиента.
- Ограничения: высокая задержка (опрос раз в ~100 мс); **оплата запросов к хранилищу**; в примере конфига
  включён webhook на `0.0.0.0:80`, назначение не описано.
- Для нас: вход rendezvous; отдельный инстанс модифицированного Xray; учётные данные S3 — в хранилище секретов.

## Что это меняет в архитектуре ноды

1. **Классы входа и выхода** становятся частью манифеста движка (см. [01-architecture.md](01-architecture.md)).
2. **Периметр** применяется только к классу direct; для relayed, rendezvous и dns защита строится на
   аутентификации в сервисе и на внутренней ступени (см. [02-security-model.md](02-security-model.md)).
3. **Внутренняя аутентифицированная ступень** обязательна для движков без пользователей
   (olcRTC, dnstt, MasterDnsVPN): иначе любой, кто знает общий ключ, получает выход в интернет без учёта.
4. **Учётные данные третьих сторон** (аккаунты VK, Телемоста, сервисов документов, S3-ключи) —
   отдельный класс секретов со своим хранилищем, ротацией и учётом риска блокировки аккаунта.
5. **Выход L3** возвращает в nftables `forward` и NAT, но только для подсетей конкретных инстансов.
6. **Лицензии разные** (MIT, CC0, WTFPL, MPL-2.0, GPL-3.0, PolyForm Noncommercial): на сервере движки работают
   отдельными процессами и не линкуются с нашим кодом; для клиента встраивание GPL-движков определяет лицензию клиента.

## Источники

- qWDTT: [studasd/qWDTT](https://github.com/studasd/qWDTT), [FreedomCats/qwdtt-cli](https://github.com/FreedomCats/qwdtt-cli), [code2fingers/qwdtt-openwrt](https://github.com/code2fingers/qwdtt-openwrt/pull/18), [ildarmaga/wdtt](https://github.com/ildarmaga/wdtt)
- CSQTT: [amurcanov/csqtt](https://github.com/amurcanov/csqtt), [SanityProtocol/csq-socks](https://github.com/SanityProtocol/csq-socks), [Throne issue #1894](https://github.com/throneproj/Throne/issues/1894), [wdtt-suite: каталог исследований](https://github.com/saymer-alt/wdtt-suite/issues/20)
- olcRTC: [openlibrecommunity/olcrtc: about.md](https://github.com/openlibrecommunity/olcrtc/blob/master/docs/about.md), [ghostlane-project/olcrtc](https://github.com/ghostlane-project/olcrtc), [romanpodpriatov/olcbox](https://github.com/romanpodpriatov/olcbox)
- OpenFlux: [p1neappleXpress/OpenFlux](https://github.com/p1neappleXpress/OpenFlux), [imbazyx/OpenFlux](https://github.com/imbazyx/OpenFlux)
- dnstt: [Mygod/dnstt (зеркало)](https://www.github.com/Mygod/dnstt), [AUR dnstt-git](https://aur.archlinux.org/packages/dnstt-git)
- Slipstream: [EndPositive/slipstream](https://github.com/EndPositive/slipstream), [описание протокола](https://endpositive.github.io/slipstream/protocol.html), [Mygod/slipstream-rust](https://github.com/Mygod/slipstream-rust), [getlantern/slipstream](https://github.com/getlantern/slipstream)
- MasterDnsVPN: [masterking32/MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)
- S3 Bypass: [SpaceNeuroX/s3-bypass](https://github.com/SpaceNeuroX/s3-bypass), [s3network/s3-bypass-protocol](https://github.com/s3network/s3-bypass-protocol)
- Клиенты-агрегаторы: [spkprsnts/WireTurn](https://github.com/spkprsnts/WireTurn)
