# 01. Архитектура ноды

Статус: **принята** (редакция 2, по решениям из [08-decisions.md](08-decisions.md)).
Data plane описан в спецификации niko-server
([`arngory/niko`, `docs/server/SPEC.md`](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)),
изменения к ней — в 08, «Следствие 3».

## Разделение ролей

| Слой | Что | Где код |
|---|---|---|
| **Data plane** | niko-server (форк sing-box): фронт-мультиплексоры и бэкенды протоколов; Xray (форк) для REALITY; движки белых списков (olcRTC, OpenFlux). | `arngory/sing-box` (`cmd/niko-server`), `arngory/xray-core`, форки движков |
| **Control plane** | raycontrol: состояние, генерация конфигов, ротация, SPA и файрвол, подписка, API, установка, обновления, бэкапы. | этот репозиторий |

Нода — самодостаточная установка на одном хосте. Центрального сервера нет; у ноды своя ключевая пара,
которой она подписывает подписки и идентифицирует себя в API.

## Процессы

```
                         ┌──────────────────────────────── нода ────────────────────────────────────┐
 интернет                │                                                                          │
 ──▶ nftables (policy drop) ◀── rayspa: SPA v2 (NFLOG, ротируемый порт), allow-наборы,            │
       │  открыто для всех: только UDP 53; TCP 443 — на время ACME                                  │
       │  после SPA: адрес клиента → разрешённые ему порты, на TTL                                  │
       ▼                                                                                          │
   niko-front ── tcpmux (TCP 443) ──┬─▶ xray (REALITY + Vision, ML-DSA-65) ──▶ site (self-steal) │
   (фронт, без ключей               ├─▶ naive-h2 · doh · yggdrasil · acme (rayd)                  │
    пользователей)                  │                                                             │
              udpmux (UDP 443) ─────┼─▶ hy2-masq · hy2-obfs · naive-quic · doh3                  │
              dnsmux (UDP 53) ──────┴─▶ dnstt · masterdns ──▶ inner (VLESS + ML-KEM) ──▶ выход   │
                                                                                                  │
   olcrtc · openflux (только исходящие к платформам) ──────────▶ inner ──▶ выход                  │
                                                                                                  │
   rayd ── SQLite · генерация конфигов · ротация · подписка · API · ACME · хранилище секретов     │
   rayctl (CLI) ── unix socket ──▶ rayd                                                           │
                         └──────────────────────────────────────────────────────────────────────────┘
```

| Процесс | Роль | Права |
|---|---|---|
| `niko-front` | tcpmux, udpmux, dnsmux: классифицирует соединения и пакеты (SNI, ALPN, QUIC Initial, salamander, DNS-зона) и передаёт их бэкендам. Ключей пользователей не знает. | `CAP_NET_BIND_SERVICE`; знает только таблицу маршрутов и пароль salamander (для классификации). |
| Бэкенды niko-server | По одному процессу на протокол (`hy2-masq`, `hy2-obfs`, `naive`, `doh`, `dnstt`, `masterdns`, `yggdrasil`, `inner`, `site`). | Свой пользователь; без capabilities; слушают только свой unix-сокет. |
| `xray` | REALITY + Vision с ML-DSA-65; цель — бэкенд `site`. | Свой пользователь; принимает соединения через unix-сокет с PROXY v2. |
| `olcrtc`, `openflux` | Движки белых списков; входящих портов нет, выход — в `inner`. | Свой пользователь; исходящие разрешены только к адресам своей платформы. |
| `rayd` | Control plane. | Свой пользователь; управляет только юнитами raycontrol (polkit). |
| `rayspa` | nftables: политика drop, SPA v2, allow-наборы, окно ACME, исходящие фильтры. | Единственный с `CAP_NET_ADMIN`; к базе доступа нет, ключи SPA получает от `rayd`. |
| `rayctl` | CLI администратора. | root или группа `raycontrol`. |

### Связь фронта с бэкендами

- **TCP:** фронт передаёт принятый сокет бэкенду через unix-сокет (`SCM_RIGHTS`) вместе с метаданными:
  адрес клиента, уже прочитанные байты ClientHello, выбранный маршрут. Для Xray — поток через unix-сокет
  с заголовком PROXY v2 (`acceptProxyProtocol`).
- **UDP:** фронт пересылает датаграммы в unix-сокет бэкенда (`SOCK_DGRAM`) с заголовком «адрес клиента»;
  бэкенд видит виртуальный `net.PacketConn`. Ответы идут обратно тем же путём и уходят с общего сокета фронта.
- Права на сокет бэкенда — только у UID фронта; бэкенд принимает соединения только от UID фронта (`SO_PEERCRED`).

Цена разделения — лишняя копия UDP-датаграмм через фронт. Её проверяет нагрузочный тест (SPEC §6.4);
если она окажется заметной, для UDP рассматривается передача через `SO_REUSEPORT` + eBPF.

## Внутренняя ступень (`inner`)

Транспорты без своих пользователей и без постквантового шифрования (dnstt, MasterDnsVPN, olcRTC, OpenFlux) не выходят
в интернет сами. Их выход ведёт в бэкенд `inner`: VLESS с `decryption` ML-KEM-768 и пользователями на каждого.
Клиент внутри туннеля поднимает VLESS-соединение к `inner`. Так получаются учёт по пользователю, отзыв доступа
и постквантовое шифрование поверх любого носителя.

## Единая модель трафика

Любой способ подключения описывается слоями: вход → носитель → маскировка → сессия → аутентификация → маршрут → выход.

| Сервис | Вход | Носитель | Маскировка | Сессия | Аутентификация | PQ |
|---|---|---|---|---|---|---|
| REALITY | direct, TCP 443 за SPA | TLS 1.3 | REALITY self-steal | VLESS + Vision | UUID | X25519MLKEM768 + ML-DSA-65 |
| hy2-masq | direct, UDP 443 за SPA | QUIC | masquerade | Hysteria2 | пароль | X25519MLKEM768 |
| hy2-obfs | direct, UDP 443 за SPA | QUIC | salamander | Hysteria2 | пароль | X25519MLKEM768 |
| naive | direct, TCP/UDP 443 за SPA | h2 / QUIC | сайт | HTTP CONNECT | логин и пароль | X25519MLKEM768 |
| dnstt, masterdns | dns, UDP 53 открыт | DNS | DNS-запросы | KCP/smux, ARQ | ключ туннеля → `inner` | через `inner` |
| olcrtc | rendezvous | WebRTC | видеозвонок | smux | PSK → `inner` | через `inner` |
| openflux | rendezvous | документы | правки документов | своя | ключ → `inner` | через `inner` |
| yggdrasil | direct, TCP 443 за SPA | TLS | — | Yggdrasil | ключ узла | — (нужно проверить) |

## Control plane

### Данные (SQLite)

```
node            id, name, public_key, created_at
users           id, name, enabled, expires_at, traffic_limit_bytes, note, created_at
devices         id, user_id, name, role(user|admin), spa_key_ref, api_cert_fingerprint, scopes, last_seen, revoked_at
services        id, kind, enabled, settings_json                     — бэкенды и движки
credentials     id, user_id, service_id, secret_ref, valid_from, valid_to, revoked_at  — с перекрытием при ротации
rotations       id, kind, scope, current_ref, next_ref, switch_at, retire_at   — расписание ротации
platform_accts  id, service_id, mode(node|client), secret_ref, status, last_checked
grants          id, device_id, src_ip, scope, expires_at             — журнал SPA-доступов
traffic         user_id, service_id, period, up, down
audit_log       ts, actor, action, target, result
settings        key, value                                           — включая случайные параметры установки
```

Секреты (`*_ref`) лежат в хранилище секретов `rayd`, на диске — через systemd credentials.

### Генерация конфигов

`rayd` собирает из базы конфиги: фронта (таблица маршрутов), каждого бэкенда, Xray, движков белых списков,
правила для `rayspa`. Перед применением — проверка (`niko-server check`, `xray run -test`).
Применение: `SIGHUP` бэкенду или gRPC API Xray; перезапуск — только при смене портов и доменов.

### Ротация

Планировщик в `rayd`:

| Что | Как | Как узнаёт клиент |
|---|---|---|
| Ключи SPA | эпохи: ключ эпохи выводится из ключа устройства; сервер принимает текущую и соседнюю эпоху | выводит сам, обновлять нечего |
| Порт SPA | вычисляется из секрета ноды и номера слота; `rayspa` держит открытыми текущий и соседний слоты | вычисляет сам |
| Учётные данные пользователей | новые выпускаются заранее, старые действуют до конца окна перекрытия | подписка |
| Ключи REALITY, shortId | новые добавляются заранее, старые снимаются после окна | подписка |
| SNI (поддомены) | см. 08, «Следствие 1» | подписка |

### Случайные параметры установки

Чтобы у проекта не было общего отпечатка, при установке случайно выбираются: диапазон портов SPA и длина слота,
диапазон длины SPA-пакетов, поддомены, тайминги ротации, параметры padding. Значения по умолчанию в коде — только
границы диапазонов.

### API

- Локальный: unix socket, `SO_PEERCRED` — для `rayctl`.
- **Подписка** (с первого этапа): HTTPS за SPA, ответ подписан ключом ноды; через неё клиент получает
  ротируемые учётные данные.
- Полный API (этап M3): protobuf + ConnectRPC, отдельный порт за SPA + mTLS, роли user и admin, регистрация
  устройства по одноразовой ссылке или QR. TLS — с `X25519MLKEM768`.

## Структура репозитория raycontrol

```
cmd/       rayd/  rayctl/  rayspa/
api/proto/ API ноды
internal/
  store/ model/ authz/ pki/ secrets/
  render/       генерация конфигов фронта, бэкендов, Xray, движков
  rotation/     планировщик ротации
  spa/          формат SPA v2 (общий с клиентом: тестовые векторы)
  perimeter/    nftables
  acme/         выпуск сертификатов в коротком окне или через DNS-01
  system/       systemd, пользователи, sysctl
deploy/        юниты, манифест версий (data plane и движки)
install/bootstrap.sh
docs/
legacy/        v0
```

## Развёртывание

- `install/bootstrap.sh` проверяет ОС и архитектуру, скачивает подписанный релиз (minisign + `SHA256SUMS`)
  и запускает `rayctl install`.
- Все бинарники — из своих форков и своих релизов, версии закреплены в `deploy/` (правила P-17).
- Debian 12/13, Ubuntu 24.04 LTS; amd64 и arm64. systemd-resolved stub выключается (нужен UDP 53).
