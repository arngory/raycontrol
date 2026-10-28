# 01. Архитектура (база)

Статус: **черновик для согласования**. Решения, помеченные «предлагается», ждут подтверждения;
открытые вопросы собраны в [04-roadmap.md](04-roadmap.md#открытые-вопросы).

## Цели

1. Набор CLI-инструментов и API, через который ими можно управлять из будущего клиента.
2. Многоуровневая защита: port-knocking (первый эшелон) → SPA → собственная аутентификация каждого сервиса.
3. Zero trust между компонентами: у каждого свои учётные данные, свой системный пользователь, минимальные права,
   доступ только к тому, что ему нужно.
4. Несколько протоколов как подключаемые модули (engines), а не жёстко прошитый набор.
5. Установка, обновление, бэкап и удаление — повторяемые и безопасные операции.

## Не цели (на первом этапе)

- Веб-панель. Её роль выполняет API; интерфейс появится как клиент этого API.
- Несколько серверов под одним контроллером. Архитектура оставляет под это место
  (граница «контроллер ↔ узел»), но реализуется один узел.
- Cloudflare и другие CDN как обязательная часть деплоя.

## Компоненты

```
                       ┌───────────────────────────── хост ─────────────────────────────────┐
  клиент / устройство  │                                                                    │
  ─────────────────────┼─▶ [nftables: table inet raycontrol]  ◀── управляет ── rayspa         │
   1. knock            │        │ knock-стадии, SPA-гейт, allow-наборы по сервисам           │
   2. SPA-пакет ───────┼────────┘ (NFLOG) ──────────────────────────────▶ rayspa (проверка)  │
   3. подключение      │        │                                             │ unix socket  │
                       │        ▼                                             ▼              │
                       │  ┌──────────┐ ┌────────────┐ ┌────────────┐   ┌──────────────┐     │
                       │  │  xray    │ │ hy2-obfs   │ │ hy2-masq   │   │    rayd      │     │
                       │  │ REALITY  │ │ salamander │ │ свой SNI   │   │ control plane│     │
                       │  └────┬─────┘ └─────┬──────┘ └─────┬──────┘   │ SQLite, API  │     │
                       │       │ fallback    │ auth (http)  │ auth     └──────┬───────┘     │
                       │       ▼             └──────────────┴──────────▶      │ unix socket │
                       │  ┌──────────┐                                         ▼             │
                       │  │  caddy   │ сайт-приманка (self-steal), ACME   rayctl (CLI)      │
                       │  └──────────┘                                                      │
                       └────────────────────────────────────────────────────────────────────┘
```

| Компонент | Роль | Права |
|---|---|---|
| `rayd` | Control plane: состояние (SQLite), генерация конфигов, синхронизация пользователей с движками, API (локальный и удалённый), колбэки авторизации, статистика. | Свой пользователь `rayd`. Без capabilities. Пишет только в `/var/lib/raycontrol` и `/etc/raycontrol/rendered`. |
| `rayctl` | CLI администратора. Тонкий клиент к API `rayd` через unix socket. | Запускается от root или группы `raycontrol`. Не читает базу напрямую. |
| `rayspa` | Периметр: управляет таблицей `inet raycontrol`, принимает knock и SPA, выдаёт временные доступы. | Свой пользователь, только `CAP_NET_ADMIN`. Без доступа к базе: ключи устройств получает от `rayd`. |
| `rayknock` | Клиентская утилита и Go-библиотека: knock + SPA. Ляжет в основу будущего клиента. | Запускается у клиента. |
| Engines | Процессы протоколов: `xray`, `hysteria@obfs`, `hysteria@masq`, далее по [03-protocols.md](03-protocols.md). | У каждого инстанса свой пользователь и только свои учётные данные. |
| `caddy` | Сайт-приманка для self-steal (цель REALITY, masquerade Hysteria), ACME. | Свой пользователь, `CAP_NET_BIND_SERVICE`. |

Почему `rayspa` отдельно от `rayd`: это единственный компонент с `CAP_NET_ADMIN`, и он смотрит в сеть до
любой аутентификации. Его компрометация не должна давать доступ к базе пользователей, а компрометация `rayd`
не должна давать управление файрволом напрямую.

## Язык и инструменты (предлагается)

**Go** для всех своих компонентов:

- тот же стек, что у Xray, Hysteria, sing-box, Caddy: можно использовать их API-клиенты и библиотеки;
- статические бинарники под amd64 и arm64, без зависимостей на хосте;
- библиотеки для периметра: `github.com/google/nftables` (netlink, без вызова `nft`),
  `github.com/florianl/go-nflog` (приём SPA-пакетов через NFLOG);
- `modernc.org/sqlite` (без CGO) для хранилища.

API (предлагается): описание в protobuf, сервер на **ConnectRPC**. Одно описание обслуживает gRPC,
gRPC-Web и обычный JSON поверх HTTP, поэтому будущий клиент на любом языке и платформе сможет работать
без отдельного REST-слоя. Клиентский код генерируется через `buf`.

## Структура репозитория (предлагается)

```
cmd/
  rayd/          control plane
  rayctl/        CLI администратора
  rayspa/        периметр (knock + SPA + nftables)
  rayknock/      клиентская утилита knock + SPA
api/proto/       protobuf-описание API (ConnectRPC)
internal/
  store/         SQLite, миграции
  model/         пользователи, устройства, учётные данные, инстансы
  engine/        интерфейс Engine + адаптеры: xray, hysteria, (naive, tuic, trusttunnel, dnstt)
  render/        шаблоны конфигов, валидация (xray run -test и т.п.)
  perimeter/     правила nftables, формат SPA-пакета, криптография
  authz/         роли, области доступа, проверка вызовов API
  pki/           внутренний CA для mTLS API
  system/        systemd-юниты, системные пользователи, sysctl
deploy/
  systemd/       юниты с hardening
  caddy/         Caddyfile сайта-приманки
install/
  bootstrap.sh   тонкий установщик: проверка ОС → скачать бинарник → `rayctl install`
docs/
legacy/          v0 (ray.sh, uninstall.sh) до завершения миграции
```

## Модель данных (черновик)

```
users          id, name, enabled, expires_at, traffic_limit_bytes, note, created_at
credentials    id, user_id, instance_id, kind, secret, created_at, revoked_at
               — у пользователя отдельные учётные данные на каждый инстанс
devices        id, user_id, name, spa_pubkey, api_cert_fingerprint, scopes, last_seen, revoked_at
instances      id, engine, name, profile(public|gated), listen, settings_json, enabled
grants         id, device_id, src_ip, scope, expires_at        — журнал выданных SPA-доступов
traffic        user_id, instance_id, period, up, down
api_tokens     id, subject, scopes, created_at, expires_at, revoked_at  — для enrollment и автоматизации
audit_log      ts, actor, action, target, result
settings       key, value
```

Принципы:

- **Единственный источник правды — база `rayd`.** Конфиги движков генерируются из неё и не правятся руками.
- **Отдельные учётные данные на каждый инстанс.** Утечка пароля от `hy2-obfs` не даёт доступа к VLESS.
  Отзыв выполняется точечно.
- **Секреты в базе**, файл `0600`, владелец `rayd`. Шифрование на диске (age или ключ из systemd credentials)
  остаётся открытым вопросом.
- **Миграции схемы** версионируются и применяются при запуске `rayd`.

## Интерфейс Engine

Каждый протокол — адаптер с одинаковым контрактом:

```go
type Engine interface {
    Name() string
    Render(inst Instance, users []UserCred) (Files, error) // конфиги для systemd-инстанса
    Validate(files Files) error                            // xray run -test, проверка YAML и т.п.
    SyncUsers(ctx, inst, diff UserDiff) error               // на лету, если движок умеет, иначе reload
    Stats(ctx, inst) ([]UserTraffic, error)
    Kick(ctx, inst, userID) error
    ClientLink(inst, cred) (URI, error)                     // ссылка или фрагмент подписки
}
```

Как пользователи доходят до движков:

| Движок | Способ | Перезапуск при изменении |
|---|---|---|
| Xray | gRPC API (`HandlerService` AddUser/RemoveUser, `StatsService`) | нет |
| Hysteria2 | `auth: http`: `rayd` отвечает на колбэк. Статистика и отключение через Traffic Stats API. | нет |
| Остальные | По возможностям движка; иначе перегенерация + reload | зависит от движка |

## Потоки

**Добавление пользователя:** `rayctl user add` → API `rayd` → запись в базу + учётные данные на каждый
включённый инстанс → `SyncUsers` для Xray (gRPC); Hysteria подхватит при следующей авторизации →
ответ: ссылки и QR.

**Подключение клиента в режиме gated:** knock → SPA-пакет → `rayspa` проверяет подпись и окно времени →
IP добавляется в allow-набор нужного сервиса на TTL → клиент подключается → сервис проверяет свои учётные данные.

**Будущий клиент:** то же, плюс удалённый API `rayd` за SPA и mTLS: получить конфиг или подписку,
ротировать свои учётные данные, зарегистрировать ключ устройства.

## Развёртывание и операции (направления, подробнее в roadmap)

- `install/bootstrap.sh` только проверяет ОС и архитектуру, скачивает подписанный релиз и запускает
  `rayctl install`. Вся логика установки — в Go, повторный запуск безопасен.
- Systemd-юниты с hardening: отдельные пользователи, `ProtectSystem=strict`, `NoNewPrivileges`,
  минимальные `CapabilityBoundingSet`, `RestrictAddressFamilies`, `SocketBindAllow`/`IPAddressDeny` где возможно;
  TLS-ключи через `LoadCredential=`.
- Версии движков закреплены в манифесте релиза, проверка SHA-256; `rayctl update`.
- `rayctl backup`/`restore`: зашифрованный архив (база + конфиги + ключи), проверка на чистом хосте.
- `rayctl uninstall` по журналу установки: удаляется только то, что поставил raycontrol.
- Целевые ОС: Debian 12/13, Ubuntu 24.04 LTS; amd64 и arm64.
