# raycontrol: удалённый API v1

Статус: **R3, первая версия.** Совместимые изменения — по правилам protobuf; несовместимые — только как
`device.v2` / `node.v2`. Эталонная реализация: сервер — [`internal/api/remote.go`](../../internal/api/remote.go),
клиент — [`cmd/rayctl/remote.go`](../../cmd/rayctl/remote.go) (`rayctl remote enroll`, `rayctl -remote`).
Решение — R3-3 в [`08-decisions.md`](../08-decisions.md).

Удалённый API нужен для двух вещей:

1. **Регистрация устройства по приглашению.** Администратор выдаёт одноразовое приглашение `rcinv1:` (строка или
   QR). Клиент сам заводит ключ, проходит SPA и получает свой пакет `rcdev1:` уже по каналу с `X25519MLKEM768`.
   Ключ устройства не появляется ни на экране администратора, ни в QR.
2. **Администрирование с устройства администратора**: весь `NodeService` — то же, что `rayctl` на ноде.

## 1. Где

- Сервис вида `api`, один на ноду, включается администратором: `rayctl service add api api`, затем
  `rayctl apply`. Порт — случайный TCP, свой у каждой установки.
- Адрес: `https://<host>:<api.port>/`. `host` — поле пакета или приглашения, `api` — `{"port": N, "pin": "…"}`.
- Порт закрыт до SPA. Через SPA к нему проходят только:
  - устройства с ролью `admin`, зарегистрированные через API (у них есть клиентский сертификат);
  - действующие приглашения: не использованные, не истёкшие, пользователь включён.
  Устройства с ролью `user` порт не открывают: им API нужен только один раз, для регистрации.
- TLS 1.3, только `X25519MLKEM768`, ALPN `h2`. Сертификат сервера самоподписанный. Клиент проверяет его по пину
  `api.pin` = base64url(SHA-256(SubjectPublicKeyInfo)), имя не проверяет — так же, как у подписки.
- **Клиентский сертификат обязателен на каждом соединении.** Без него TLS не завершается. Сертификат — любой
  самоподписанный: нода не проверяет ни цепочку, ни сроки, ни имя. Устройство для неё — **ключ** сертификата, то есть
  его пин (base64url SHA-256 SPKI). Рекомендуемый ключ — ECDSA P-256. CA на ноде нет: она хранит пин каждого
  устройства, как клиент хранит пины ноды.

## 2. Протокол

[ConnectRPC](https://connectrpc.com): протокол Connect поверх HTTP/2 (protobuf или JSON). gRPC и gRPC-Web на том же
пути тоже работают. Определения:

- [`api/proto/raycontrol/device/v1/device.proto`](../../api/proto/raycontrol/device/v1/device.proto) — `DeviceService`:
  то, что вызывает устройство;
- [`api/proto/raycontrol/node/v1/node.proto`](../../api/proto/raycontrol/node/v1/node.proto) — `NodeService`:
  администрирование.

Пример пути: `POST /raycontrol.device.v1.DeviceService/Register`, `Content-Type: application/proto`.

## 3. Приглашение `rcinv1:`

```
rcinv1:<base64url без '=' от JSON>
```

Это пакет регистрации из [`spa-v2.md`](spa-v2.md) §8 с тем же разбором полей. Отличия:

| Поле | В приглашении |
|---|---|
| `device_id`, `device_key` | ID приглашения и его одноразовый ключ SPA (открывает только порт API) |
| `services` | один сервис — `api` (его `id` нужен для scope SPA) |
| `api` | `{"port": N, "pin": "<base64url SHA-256 SPKI>"}` |
| `expires` | Unix-время, после которого приглашение не работает (по умолчанию сутки, не больше недели) |
| `pin` | `true`, если нужен ещё PIN (raycontrol v0.13): клиент спрашивает его до регистрации; нет поля — PIN не нужен |
| `node_keys`, `sub` | нет: они придут в пакете после регистрации, по каналу, закреплённому пином `api.pin` |

```json
{
  "v": 1,
  "host": "203.0.113.7",
  "spa": {"node_id": "<32 hex>", "epoch_len_s": 34380, "slot_len_s": 1620, "port_key": "<64 hex>",
          "port_base": 21907, "port_range": 2955, "len_min": 136, "len_max": 206},
  "device_id": "<16 hex>",
  "device_key": "<64 hex>",
  "services": [{"id": 7, "kind": "api", "name": "api"}],
  "api": {"port": 48213, "pin": "<base64url>"},
  "expires": 1767312000
}
```

Длина строки — около 600 символов, это QR средней плотности. Администратор делает приглашение командой
`rayctl device invite USER NAME [-role user|admin] [-ttl 24h]`. Пока приглашение не использовано, оно видно в
`rayctl device list`, а `rayctl device revoke ID` его отзывает. С raycontrol v0.24.0 новое приглашение для того же
пользователя и имени устройства заменяет неиспользованное (повтор `CreateInvite`, ответ на который потерян, не оставляет
второго), а повторный `RevokeDevice` уже отозванного устройства — не ошибка (`not_found` — только для неизвестного ID
или уже отозванного приглашения).

Строка — секрет, пока не использована: тот, кто зарегистрируется первым, получит устройство. После регистрации она
бесполезна.

**PIN** (raycontrol v0.13, по выбору администратора: `rayctl device invite … -pin`).
- Приглашению нужен ещё PIN из 6 цифр. rayctl показывает его один раз, а администратор сообщает его другим каналом,
  не тем, что и QR.
- Утёкшая строка без PIN бесполезна: 5 неверных PIN отзывают приглашение.
- Нода хранит не PIN, а доказательство, которое ждёт от регистрации (§4). Проверить PIN можно только запросом к ноде,
  офлайн-проверки нет.
- `rayctl device list` показывает, сколько попыток осталось.

## 3a. Короткое приглашение `RCINV2:` (raycontrol v0.13, Niko 1.35)

То же приглашение, что `rcinv1`, в двоичной раскладке: около 250 символов вместо 650, QR версии 8–9 вместо 17 (у
администратора — 57–61 колонка терминала). Регистрация (§4) не меняется. `rayctl device invite … -format rcinv2`; по
умолчанию `rcinv1`, пока не выйдет Niko 1.35, потом умолчание станет `rcinv2`, а `rcinv1` останется по флагу.

```
RCINV2:<base32 RFC 4648, верхний регистр, без '='>
```

Префикс и алфавит base32 входят в алфавитно-цифровой режим QR (5,5 бита на символ). Регистр при чтении любой.
Заглавная схема не открывает Niko из другого приложения (Android сравнивает схему с учётом регистра, а схема в
манифесте — строчная): приглашение сканируют сканером Niko или вставляют строкой, а не открывают как ссылку.
Двоичное, big-endian:

| Поле | Байт | Как в `rcinv1` |
|---|---|---|
| версия | 1 | `2` |
| флаги | 1 | бит 0 — `pin`; биты 1–2 — вид хоста: 0 — IPv4, 1 — IPv6, 2 — имя; остальные — 0 |
| хост | 4, 16 или 1 + n | `host`; имя — длина (1 байт) и ASCII: буквы, цифры, `-`, `.`, метки 1–63, всего до 253; IDN — punycode |
| `spa.node_id` | 16 | 32 hex |
| `spa.epoch_len_s`, `spa.slot_len_s` | 4 + 4 | |
| `spa.port_key` | 32 | 64 hex |
| `spa.port_base`, `spa.port_range`, `spa.len_min`, `spa.len_max` | 2 × 4 | |
| `device_id` | 8 | 16 hex |
| `device_key` | 32 | 64 hex |
| `services[0].id` | 2 | `kind` и `name` не передаются: сервис один, `api` |
| `api.port` | 2 | |
| `api.pin` | 32 | base64url SHA-256 SPKI |
| `expires` | 4 | Unix-время |

150 байт с IPv4 (247 символов), 162 с IPv6.

Читатель отказывает, если версия не `2`, есть незнакомый бит флагов, вид хоста — 3, имя не по правилам выше, поле
обрезано, после `expires` остались байты, `expires` или `api.port` — 0. Контрольной суммы нет: у QR своя коррекция
ошибок, а обрезанную строку выдают длины полей.

Векторы — тест `TestInvite2Vectors` (`internal/node/invite2_test.go`), посчитаны отдельно от кода (Python, по раскладке):
`spa.node_id` = `00 … 0f`, `epoch_len_s` 34380, `slot_len_s` 1620, `port_key` = `20 … 3f`, `port_base` 21907,
`port_range` 2955, `len_min` 136, `len_max` 206, `device_id` = `a0 … a7`, `device_key` = `40 … 5f`, сервис 7, порт API
48213, `api.pin` = `60 … 7f`, `expires` 1767312000:

- `203.0.113.7`, с PIN:
  `RCINV2:AIA4WADRA4AACAQDAQCQMBYIBEFAWDANBYHQAAEGJQAAABSUEAQSEIZEEUTCOKBJFIVSYLJOF4YDCMRTGQ2TMNZYHE5DWPB5HY7VLEYLRMAIQAGOUCQ2FI5EUWTKOQCBIJBUIRKGI5EESSSLJRGU4T2QKFJFGVCVKZLVQWK2LNOF2XS7AAD3YVLAMFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJ5XY7L6P5UVOCUA`;
- `2001:db8::7`, без PIN:
  `RCINV2:AIBCAAINXAAAAAAAAAAAAAAAAAAAOAABAIBQIBIGA4EASCQLBQGQ4DYAACDEYAAAAZKCAIJCEMSCKJRHFAUSUKZMFUXC6MBRGIZTINJWG44DSOR3HQ6T4P2VSMFYWAEIADHKBINCUOSKLJVHIBAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNFWXC5LZPQAB54KVQGCYTDMRSWMZ3INFVGW3DNNZXXA4LSON2HK5TXPB4XU634PV7H62KXBKAA`;
- `node.example.com`, без PIN:
  `RCINV2:AICBA3TPMRSS4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA`.

Нода, у которой хост — не адрес и не ASCII-имя, rcinv2 не делает (`invite_code_short` пустой), а `rayctl` с
`-format rcinv2` тогда отзывает приглашение и просит `-format rcinv1`.

## 4. Регистрация

1. Разобрать приглашение и проверить `expires` по своим часам.
2. Создать ключ клиентского сертификата (ECDSA P-256) и самоподписанный сертификат на него. Посчитать свой пин:
   `pin` = base64url(SHA-256(SPKI)).
3. SPA v2 ключом приглашения (`device_id`, `device_key`), scope пустой или `[services[0].id]`.
4. Через 150–400 мс (`spa-v2.md` §7) — TLS к `host:api.port`: пин `api.pin`, свой клиентский сертификат.
5. Вызвать `DeviceService.Register`:
   - `invite_id` — `device_id` приглашения;
   - `minute` — `floor(unix_time / 60)` по часам клиента; сервер принимает ±2;
   - `mac` — HMAC-SHA256(`device_key` приглашения, `"raycontrol-register-v1"` ‖ BE64(`minute`) ‖ `pin`), где `pin`
     — ASCII-строка пина **того сертификата, с которым идёт это соединение**;
   - `pin_proof` — у приглашения с `"pin": true`: HMAC-SHA256(`device_key` приглашения,
     `"raycontrol-invite-pin-v1"` ‖ PIN ASCII-цифрами, без пробелов).
6. Ответ: `bundle` — полный `rcdev1:` нового устройства (новый ключ SPA, `node_keys`, `sub`, сервисы пользователя, а
   для роли `admin` ещё `api` и сервис `api`), `device_id`, `role`. Клиент импортирует пакет как обычно.
7. Приглашение израсходовано. Его доступы SPA закрываются (через 15 минут, см. §4.1), поэтому дальше клиент проходит
   SPA уже ключом из пакета.

Любой отказ — `not_found` без подробностей: приглашение неизвестно, использовано, истекло или отозвано; неверный
`mac`; часы расходятся больше чем на 2 минуты; этот клиентский ключ уже принадлежит другому устройству.

Кроме PIN. Его нода проверяет только после верного `mac`, то есть только у того, кто держит приглашение.
- PIN не прислан: `permission_denied` с деталью `raycontrol.device.v1.PinTries{left}`. Попытка не тратится: это старый
  клиент или пользователь ещё не ввёл код.
- PIN неверный: `permission_denied` с `PinTries{left}`, попыток на одну меньше. Клиент просит ввести снова.
- Неверный при `left: 0`: приглашение отозвано, дальше `not_found`. Клиент говорит пользователю попросить новое.
- Сравнение за постоянное время. Если свежее
приглашение отклонено, его мог использовать кто-то другой: клиенту стоит сказать пользователю, чтобы администратор
проверил `rayctl device list` и отозвал лишнее.

### 4.1 Repeated Register (raycontrol v0.24.0)

A client that lost Register's answer (timeout, dropped connection) may send it again; before v0.24.0 the retry got
`not_found`, as for any used invite, and the client was left with neither a device nor an invite.

- The node answers a repeated `Register` for an invite (`rcinv1:` and `RCINV2:` alike) already used **by the same
  client certificate** (the TLS client key's `pin`, which the MAC covers) **within 15 minutes of its first use** with
  the first answer: the same `device_id` and `role`, and a `bundle` built again from the node's current state for that
  same device (same SPA key; the rest equal to the first one unless the admin changed the node or the user in between).
  No new user, device or key is made; the audit log gets `device.register-replay:<role>`, not a second
  `device.register`.
- The proofs are checked again as in §4: `minute` within ±2, `mac` for this certificate, and for an invite with a PIN
  the right `pin_proof`. A wrong or missing `pin_proof` on a repeat is `not_found` and spends no try (whoever gets this
  far already holds the device's key).
- For those 15 minutes the invite's SPA key still opens the API port (scope `[api]`, as before use), so the retry goes
  the way the first request did: SPA with the invite key, TLS with the same client certificate, `Register` with the
  same invite. The client keeps the certificate key per invite for at least that long.
- Everything else is unchanged `not_found`: a certificate other than the device's current one (after
  `RotateCertificate` the new one is the device's, the first one no longer is), more than 15 minutes after the first
  use, the device revoked, the user disabled or expired.
- During those 15 minutes a `user` device reaches the API port by the invite's SPA key, but besides `Register` it may
  only ask `GetSelf` (about itself); `RotateCertificate` is for `admin` devices (§5) and answers `permission_denied`
  to a `user` device, as `NodeService` does.
- Duplicates sent at the same time all get the one device.

## 5. Роли

| Роль | SPA до API | `DeviceService` | `NodeService` |
|---|---|---|---|
| `user` | нет (только `Register` по приглашению) | — | — |
| `admin` (зарегистрирован через API) | да | `GetSelf`, `RotateCertificate` | всё, кроме `Backup`, `GetDeployment`, `GetDeployInputs` и `SetCertificate` |

- `Backup` — только root на самой ноде: в базе все закрытые ключи ноды (R4-13). `GetDeployment` и `GetDeployInputs` —
  тоже. Ключей в них нет (юниты и системные файлы, имена, UID и порты сервисов), но из них root строит план `apply`
  на ноде, а снаружи они не нужны ([apply-plan-v1.md](apply-plan-v1.md)). `SetCertificate` — тоже: в запросе закрытый
  ключ сайта (R4-23). Через API они отвечают `permission_denied`. Так же отвечает `RotateService` для сервиса вида
  `site`: смена ключа сертификата сайта — только root на ноде ([cert-pin-v1.md](cert-pin-v1.md) §5).
- То, что меняет сам хост, через API не делается: `rayctl apply` (юниты, пользователи, порты хост-файрвола для
  новых сервисов), `update`, `uninstall`, `restore`, `backup`. Сервис, добавленный через API, начнёт работать после
  `rayctl apply` на ноде, если ему нужен свой процесс или порт в хост-файрволе.
- Журнал аудита записывает такие действия от имени `<пользователь>/<устройство> (remote)`.
- Лимит трафика (raycontrol v0.22.0, [traffic-limit-v1.md](traffic-limit-v1.md) §3.6) — как весь `NodeService`:
  `SetUserTraffic {name; optional limit_bytes (0 — снять); optional period ("monthly" | "none"); optional reset_day
  (1–28); reset_usage}` меняет заданное, пустой запрос — `invalid_argument`, в аудите `user.traffic` с тем, что
  просили. `CreateUser` берёт ещё `traffic_period` и `traffic_reset_day`. У `User` — `traffic_used_bytes` (`up + down`
  периода, отстаёт до минуты), `traffic_period_start`, `traffic_period`, `traffic_reset_day`, `traffic_next_reset`
  (`0` — нет) и `traffic_exhausted` (снят по лимиту: включён, не истёк и сверх него); без лимита — нули.
  Admin-устройство пользователя сверх лимита сохраняет SPA до подписки и API (без сервисов данных) и может поднять
  лимит себе само.
- Локальная сеть через Yggdrasil (raycontrol v0.23.0, [lan-v1.md](lan-v1.md) §1.1) — как весь `NodeService`:
  `SetUserLAN {name; lan}` — согласие администратора, ответ — `User`; без сервиса Yggdrasil у пользователя `lan: true`
  — `invalid_argument`; в аудите `user.lan=on|off`, отказы тоже. У `User` — `lan`, у `Device` — `lan`: согласие
  самого устройства, как его последний заголовок `X-Raycontrol-LAN` в запросе подписки (через API его не задать).
  `SetServiceOption` берёт у сервиса Yggdrasil `lan_relay` (Мбит/с на пользователя, 0–100000).

## 6. Смена клиентского ключа

`DeviceService.RotateCertificate` по текущему соединению, то есть со старым ключом:

- `certificate` — DER нового сертификата (ключ ECDSA P-256 или Ed25519);
- `signature` — подпись новым ключом сообщения `"raycontrol-rotate-v1"` ‖ старый пин ‖ новый пин (ASCII). Для ECDSA
  это ASN.1-подпись SHA-256 сообщения, для Ed25519 — подпись самого сообщения.

После ответа старый ключ больше не работает, новые соединения идут с новым сертификатом. Нода сроки сертификатов не
смотрит, поэтому срок смены выбирает клиент; разумно — раз в 90 дней, как ротация REALITY.

## 7. Ошибки

| Код | Когда |
|---|---|
| `not_found` | `Register`: любой отказ (§4) |
| `unauthenticated` | клиентский ключ не принадлежит активному устройству: не зарегистрирован, отозван, пользователь отключён или истёк |
| `permission_denied` | устройство не `admin`, или вызов только для root на ноде; `Register`: PIN не прислан или неверный, деталь `PinTries{left}` (§4) |
| `invalid_argument` | неверные данные: подпись при смене ключа, имя, срок приглашения, период или день сброса лимита, пустой `SetUserTraffic` |
| `failed_precondition` | `ExportUser`: пользователь отключён, истёк или сверх лимита трафика; `RotateService` dnstt или masterdns без `now` и `force`, пока прежний ключ ещё в своём сроке (dnsseal-v1 §8) |

## 8. Что проверить клиенту

1. TLS: `X25519MLKEM768`, пин `api.pin`, клиентский сертификат на каждом соединении.
2. При регистрации — `expires` приглашения, свои часы (±2 минуты), пин в `mac` именно текущего сертификата.
3. Пакет из `Register` — обычный `rcdev1:`, его проверки те же. Подписку дальше клиент берёт как раньше,
   с `/sub/v1` ([`subscription-v1.md`](subscription-v1.md)).
4. Ключ клиентского сертификата — секрет устройства наравне с ключом SPA: хранить в Keystore или Keychain.
