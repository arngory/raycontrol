# 01. Архитектура: нода как серверный стек

Статус: **черновик для согласования**. Решения, помеченные «предлагается», ждут ответов из
[07-questions.md](07-questions.md).

## Цели

1. **Нода — самодостаточный серверный стек.** Одна установка на хосте работает сама по себе, без центрального
   сервера. Внутри — набор микросервисов, у каждого своя часть инфраструктуры.
2. **Агрегация.** Ядра, протоколы, транспорты и способы маскировки («реальности») описываются одной моделью,
   управляются одним API и отдаются клиенту одним списком профилей подключения.
3. **Расширяемость.** Добавить новый движок, в том числе своё ядро, — значит написать адаптер по общему контракту,
   а не переделывать ноду.
4. **Многоуровневая защита и zero trust** (подробно в [02-security-model.md](02-security-model.md)).
5. **CLI и API** для будущего кроссплатформенного клиента в режимах пользователя и администратора
   (требования к клиенту — [06-client-requirements.md](06-client-requirements.md)).

## Не цели этой фазы

- Реализация клиента: в этой фазе только требования к нему.
- Центральный контроллер нескольких нод. У ноды есть собственная идентичность и API, поэтому контроллер
  можно добавить позже, не меняя ноду (см. [07-questions.md](07-questions.md), раздел B).
- Веб-панель: её роль играет режим администратора в клиенте.

## Основные понятия

| Понятие | Что это |
|---|---|
| **Нода** | Установка серверного стека на одном хосте. Имеет свою идентичность (ключевую пару), своё состояние и API. |
| **Сервис** | Один микросервис ноды: процесс под systemd со своим системным пользователем и своим срезом инфраструктуры. |
| **Срез инфраструктуры** | Всё, чем владеет сервис: порты и сокеты, наборы nftables, TUN-интерфейс и подсеть, сертификаты, каталог данных, учётные данные третьих сторон, правила исходящего трафика. |
| **Движок (engine)** | Программа, которая реализует протокол или транспорт (Xray, Hysteria, dnstt, olcRTC…). Один движок может работать несколькими сервисами-инстансами. |
| **Адаптер** | Код, который переводит модель ноды в конфиг конкретного движка и обратно (пользователи, статистика, ссылки). |
| **Манифест движка** | Декларация возможностей движка: классы входа и выхода, нужные ресурсы, модель пользователей. |
| **Профиль подключения** | То, что видит клиент: «как подключиться к этой ноде этим способом». Собирается из сервиса, учётных данных пользователя и параметров клиента. |

## Единая модель трафика

Любой способ подключения раскладывается на одинаковые слои. Движок закрывает часть слоёв; манифест говорит, какие:

```
 Вход        → Носитель            → Маскировка           → Сессия/протокол  → Аутентификация → Маршрут  → Выход
 (ingress)     (carrier)             («реальность»)          (session)          (auth)           (route)    (exit)
 direct        TCP, TLS, QUIC        REALITY, self-steal,    VLESS, Hy2, WG,    per-user,        политика   L4 / L3
 relayed       DTLS, WebRTC,         masquerade, salamander, smux, KCP,       общий ключ,      ноды       цепочка на
 rendezvous    DNS, HTTP-документы,  RTP/Opus, SFU-звонок,   QUIC streams       нет                         другую ноду,
 dns           S3-объекты            документ, бакет                                                        WARP
```

Примеры:

| Сервис | Вход | Носитель | Маскировка | Сессия | Аутентификация | Выход |
|---|---|---|---|---|---|---|
| xray-reality | direct TCP 443 | TLS 1.3 | REALITY, self-steal | VLESS + Vision | UUID на пользователя | L4 |
| hy2-masq | direct UDP 443 | QUIC | masquerade своего сайта | Hysteria2 | пароль на пользователя | L4 |
| hy2-obfs | direct UDP | QUIC | salamander | Hysteria2 | пароль на пользователя | L4 |
| qwdtt | relayed | DTLS | RTP/Opus через TURN VK | WireGuard | пароль, устройство | L3 |
| olcrtc | rendezvous | WebRTC | звонок Jitsi/Телемост | smux | общий PSK → внутренняя ступень | L4 |
| masterdns | dns UDP 53 | DNS | DNS-запросы | своя ARQ | общий ключ → внутренняя ступень | L4 |

Благодаря единой модели API, CLI и клиент описывают любой способ подключения одними и теми же полями.

## Компоненты ноды

```
                                      ┌──────────────────────── нода ──────────────────────────┐
 интернет / сторонние платформы       │                                                        │
 ───────────────────────────────────▶ │  rayspa ── nftables (inet raycontrol): периметр,      │
   direct: knock → SPA → сервис       │            allow-наборы, исходящие фильтры, NAT для L3 │
                                      │                                                        │
   direct / relayed / dns ──────────▶ │  edge-сервисы (по одному процессу на инстанс):         │
   rendezvous ◀─── исходящие ──────── │   xray-reality │ hy2-masq │ hy2-obfs │ qwdtt │ olcrtc… │
                                      │        │ L4-выход        │ L3 (TUN)  │ без пользователей │
                                      │        ▼                 ▼           ▼                   │
                                      │   [ray-core: внутренняя ступень — аутентификация,      │
                                      │    учёт, маршрутизация, политика выхода]  (см. ниже)    │
                                      │        │                                               │
                                      │        ▼  egress → интернет / WARP / другая нода        │
                                      │                                                        │
                                      │  rayd ── состояние (SQLite), адаптеры, аллокатор,      │
                                      │          API (unix socket + удалённый за SPA и mTLS)   │
                                      │  vault ── учётные данные третьих сторон (S3, VK, …)     │
                                      │  caddy ── сайт-приманка, ACME                          │
                                      └────────────────────────────────────────────────────────┘
```

| Компонент | Роль | Права |
|---|---|---|
| `rayd` | Control plane ноды: состояние, адаптеры, аллокатор ресурсов, генерация конфигов, управление юнитами, API. | Свой пользователь, без capabilities. Управляет только юнитами `raycontrol-*` (правило polkit). |
| `rayctl` | CLI администратора; тонкий клиент к API `rayd` через unix socket. | root или группа `raycontrol`. |
| `rayspa` | Периметр: таблица `inet raycontrol`, knock, SPA, allow-наборы, исходящие фильтры, NAT для L3-сервисов. | Единственный компонент с `CAP_NET_ADMIN`; к базе доступа нет. |
| Edge-сервисы | Инстансы движков: принимают трафик своего класса входа. | Свой пользователь и срез инфраструктуры на каждый инстанс. |
| `ray-core` | Внутренняя ступень: аутентификация для движков без пользователей, единый учёт и политика выхода. | Свой пользователь; слушает только unix-сокеты. |
| `vault` | Хранилище учётных данных третьих сторон; выдаёт каждому сервису только его секреты. | Свой пользователь; выдача через `LoadCredential=` или unix socket с проверкой UID. |
| `caddy` | Сайт-приманка для self-steal и masquerade, ACME. | Свой пользователь, `CAP_NET_BIND_SERVICE`. |
| `rayknock` | Клиентская утилита и Go-библиотека для knock + SPA. | У клиента. |

Нужен ли `vault` отдельным процессом или достаточно модуля `rayd` с выдачей через `LoadCredential=` —
вопрос C-6 в [07-questions.md](07-questions.md).

## Внутренняя ступень (ray-core)

Зачем она:

- У части движков нет пользователей, только общий ключ (olcRTC, dnstt, MasterDnsVPN). Если пустить их выход
  прямо в интернет, любой, кто знает ключ, получит выход без учёта и без возможности отозвать доступ.
- У движков разные политики выхода и разная статистика. Единая точка выхода даёт одинаковый запрет приватных сетей,
  одинаковый учёт трафика и маршрутизацию (WARP, цепочка на другую ноду) для всех.

Как работает:

- Edge-сервис отдаёт трафик в `ray-core` через свой unix socket. Сокет определяет, от какого сервиса пришёл трафик.
- Для движков без пользователей клиент проходит аутентификацию уже внутри туннеля: например, внутри
  olcRTC-туннеля клиент говорит с `ray-core` по VLESS или SOCKS5 с паролем на пользователя.
- Движки со своими пользователями (Xray, Hysteria) могут выходить напрямую или через `ray-core`. Через `ray-core` —
  единая политика ценой лишнего перехода; выбор — вопрос C-3.
- L3-сервисы (WireGuard в qWDTT) идут мимо `ray-core`: политика и учёт для них — правила nftables на TUN-интерфейсе
  и счётчики по адресу клиента.

Реализация (предлагается): на первом этапе `ray-core` — отдельный инстанс Xray или sing-box
с inbound-ами на unix-сокетах и пользователями на каждый сервис. Контракт `ray-core` фиксируется так,
чтобы позже заменить его **своим ядром** без изменений в остальных сервисах.

## Адаптеры и манифест движка

Манифест (черновик):

```yaml
engine: masterdnsvpn
version: "pinned-version"
ingress: [dns]                  # direct | relayed | rendezvous | dns
exit: l4                        # l4 | l3
users: shared-key               # per-user | shared-key | none
needs:
  ports: [{proto: udp, port: 53, public: true}]
  domain: ns-delegation         # none | own-domain | ns-delegation
  certificate: none
  tun: false
  capabilities: [CAP_NET_BIND_SERVICE]
  third_party: []               # например [vk-account], [s3-bucket], [jitsi-room]
features:
  hot_user_sync: false
  stats: none                   # per-user | per-instance | none
  kick: false
client:
  link_format: "masterdns://…"
  platforms: [windows, macos, linux, android]
license: MIT
```

Контракт адаптера:

```go
type Engine interface {
    Manifest() Manifest
    Render(inst Instance, users []UserCred, res Resources) (Files, error)
    Validate(files Files) error
    SyncUsers(ctx context.Context, inst Instance, diff UserDiff) error // на лету или reload
    Stats(ctx context.Context, inst Instance) ([]Traffic, error)
    Kick(ctx context.Context, inst Instance, userID string) error
    Health(ctx context.Context, inst Instance) (HealthStatus, error)
    ClientProfile(inst Instance, cred UserCred) (Profile, error)  // ссылка, QR, фрагмент подписки
}
```

Два вида адаптеров:

- **Встроенные** (Go, внутри `rayd`): для движков из основного набора.
- **Внешние плагины**: отдельный процесс, который реализует тот же контракт как gRPC-сервис через unix socket.
  Плагин можно написать на любом языке — так подключается и **своё ядро**. Плагин запускается под своим пользователем
  и получает только описание своего инстанса.

## Аллокатор ресурсов

`rayd` раздаёт сервисам ресурсы и следит, чтобы они не пересекались:

- порты и протоколы (TCP 443 и UDP 443 — разные ресурсы);
- системные пользователи с фиксированными UID из диапазона raycontrol (на них опираются правила nftables);
- TUN-интерфейсы и подсети для L3-сервисов;
- имена наборов nftables и юнитов systemd;
- каталоги данных и сокеты;
- домены и поддомены (сайт, NS-делегирование для DNS-класса).

## Модель данных (черновик)

```
node            id, name, public_key, created_at                      — идентичность ноды
users           id, name, enabled, expires_at, traffic_limit_bytes, note, created_at
devices         id, user_id, name, role(user|admin), spa_pubkey, api_cert_fingerprint, scopes, last_seen, revoked_at
services        id, engine, name, ingress, exit, profile(public|gated), enabled, settings_json
resources       service_id, kind, value                               — выданные аллокатором ресурсы
credentials     id, user_id, service_id, kind, secret, created_at, revoked_at
third_party     id, service_id, kind, secret_ref, status, last_checked — аккаунты платформ, S3-ключи
grants          id, device_id, src_ip, scope, expires_at              — журнал SPA-доступов
traffic         user_id, service_id, period, up, down
api_tokens      id, subject, scopes, created_at, expires_at, revoked_at
audit_log       ts, actor, action, target, result
settings        key, value
```

Принципы те же: единственный источник правды — база `rayd`; у пользователя отдельные учётные данные
на каждый сервис; миграции версионируются.

## Язык и инструменты (предлагается)

- **Go** для своих компонентов: тот же стек, что у большинства движков (Xray, Hysteria, sing-box, Caddy,
  olcRTC, OpenFlux, MasterDnsVPN, dnstt), статические бинарники под amd64 и arm64.
- Периметр: `github.com/google/nftables`, `github.com/florianl/go-nflog`.
- Хранилище: `modernc.org/sqlite` (без CGO).
- API: protobuf + **ConnectRPC** (gRPC, gRPC-Web и JSON из одного описания), генерация через `buf`.
- Управление юнитами: systemd через D-Bus.

## Структура репозитория (предлагается)

```
cmd/
  rayd/  rayctl/  rayspa/  rayknock/  ray-core/ (позже, когда появится своё ядро)
api/proto/            API ноды и контракт плагинов
internal/
  store/ model/ authz/ pki/ alloc/ vault/
  engine/             контракт, манифесты, встроенные адаптеры
  render/             шаблоны и проверка конфигов
  perimeter/          nftables, SPA
  system/             systemd, пользователи, sysctl
plugins/              примеры и SDK внешних адаптеров
deploy/               юниты, Caddyfile, манифест версий движков
install/bootstrap.sh
docs/
legacy/               v0 до завершения миграции
```

## Развёртывание

- `install/bootstrap.sh` проверяет ОС и архитектуру, скачивает подписанный релиз и запускает `rayctl install`.
- Нода ставится с минимальным набором сервисов; остальные включаются командой `rayctl service add <engine>`.
  Движок скачивается по манифесту версий с проверкой SHA-256.
- Повторный запуск установки и любых операций безопасен.
- Целевые ОС: Debian 12/13, Ubuntu 24.04 LTS; amd64 и arm64.
