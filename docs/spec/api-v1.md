# raycontrol: удалённый API v1

Статус: **R3, первая версия.** Совместимые изменения — по правилам protobuf; несовместимые — только как
`device.v2` / `node.v2`. Эталонная реализация: сервер — [`internal/api/remote.go`](../../internal/api/remote.go),
клиент — [`cmd/rayctl/remote.go`](../../cmd/rayctl/remote.go) (`rayctl remote enroll`, `rayctl -remote`).
Решение — R3-3 в [`../decisions.md`](../decisions.md).

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
  - устройства интеграций, `billing` и `support` ([integrations-v1](integrations-v1.md) §2): только к API, без
    подписки;
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
или уже отозванного приглашения). Отзыв устройства с v0.27.0 меняет учётные данные его пользователя, с v0.31.0
по выбору — ротацией с перекрытием (`overlap`, §5a).

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

## 3b. Приглашение по имени `RCINV3:` (raycontrol v0.35.0, черновик)

Решение владельца — names-v1 §9 п. 3. Это раскладка rcinv2 с двумя добавками: имя ноды и флаг стука v3. Ноде
не нужно, чтобы первое обращение шло по `host`: клиент стучится и регистрируется по имени, как с пакетом устройства
(names-v1 §5). Регистрация (§4) не меняется. `rayctl device invite … -format rcinv3`. По умолчанию — `rcinv2`, пока
не выйдет Niko 1.63: он читает rcinv3 вместе со стуком spa-v3 (согласовано с клиентом 2026-11-20).

```
RCINV3:<base32 RFC 4648, верхний регистр, без '='>
```

Отличия от §3a:

| Поле | Байт | Что |
|---|---|---|
| версия | 1 | `3` |
| флаги | 1 | биты 0–2 — как у rcinv2; бит 3 — есть имя ноды; бит 4 — нода принимает SPA v3 (`spa.versions` = `[2, 3]`, [spa-v3](spa-v3.md) §5); остальные — 0 |
| хост | 4, 16 или 1 + n | как у rcinv2 |
| имя ноды | 1 + n, если бит 3 | `dns_name` (names-v1 §2): длина (1 байт) и ASCII по правилам имени хоста, последняя метка не из одних цифр (имя не похоже на адрес); только когда хост — адрес |
| дальше | | как у rcinv2, от `spa.node_id` до `expires` |

С IPv4 и именем из 15 символов — 166 байт (273 символа): QR версии 10 с коррекцией M (у rcinv2 — до 9).

Читатель rcinv3:

- отказывает в тех же случаях, что читатель rcinv2;
- отказывает, если бит 3 стоит при хосте-имени;
- отказывает на имени не по правилам, в том числе на имени, последняя метка которого — одни цифры (`198.51.100.99`).

С битом 3 у пакета `dns_name` = имя, а `addrs` = [хост]: адрес и есть запасной путь (names-v1 §3). С битом 4
`spa.versions` = `[2, 3]`. Читатель rcinv2 rcinv3 не берёт: у него версия `3`. Клиент без поддержки rcinv3 отказывает
уже на префиксе `RCINV3:` и не пробует читать строку как rcinv2.

Клиент с rcinv3 стучится и регистрируется по `dns_name`, как с пакетом устройства (names-v1 §5–§6). С битом 4 — стуком
v3 на любой адрес из DNS ([spa-v3](spa-v3.md) §6). Без бита 4 — правило известного адреса (names-v1 §5 п. 5). Без имени
— по `host`, как с rcinv2. TLS к API — с SNI = `dns_name`, проверка пином, как и раньше.

`CreateInviteResponse.invite_code_v3` — то же приглашение как rcinv3. Пусто, если хост в раскладку не помещается, имя
ноды не прочиталось (rcinv1 и rcinv2 тогда всё равно выдаются) или нода старше v0.35.0. rcinv1 и rcinv2 не меняются: в них нет ни имени, ни версий.

Векторы — тест `TestInvite3Vectors` (`internal/node/invite3_test.go`). Они посчитаны отдельно от кода (Python, по
раскладке), с теми же полями, что у векторов §3a, и с именем `k3f.example.com`:

- `203.0.113.7`, имя, PIN, v3:
  `RCINV3:AMM4WADRA4HWWM3GFZSXQYLNOBWGKLTDN5WQAAICAMCAKBQHBAEQUCYMBUHA6AAAQZGAAAAGKQQCCIRDEQSSMJZIFEVCWLBNFYXTAMJSGM2DKNRXHA4TUOZ4HU7D6VMTBOFQBCAAZ2QKDIVDUSS2NJ2AIFBEGRCFIZDUQSKKJNGE2TSPKBIVEU2UKVLFOWCZLJNVYXK6L4AAPPCVMBQWEY3EMVTGO2DJNJVWY3LON5YHC4TTOR2XM53YPF5HW7D5PZ7WSVYKQA`;
- `2001:db8::7`, имя, без PIN, v3:
  `RCINV3:AMNCAAINXAAAAAAAAAAAAAAAAAAAOD3LGNTC4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA`;
- хост `node.example.com`, без имени, v3:
  `RCINV3:AMKBA3TPMRSS4ZLYMFWXA3DFFZRW63IAAEBAGBAFAYDQQCIKBMGA2DQPAAAIMTAAAADFIIBBEIRSIJJGE4UCSKRLFQWS4LZQGEZDGNBVGY3TQOJ2HM6D2PR7KWJQXCYARAAM5IFBUKR2JJNGU5AECQSDIRCUMR2IJFFEWTCNJZHVAUKSKNKFKVSXLBMVUW24LVPF6AAHXRKWAYLCMNSGKZTHNBUWU23MNVXG64DROJZXI5LWO54HS6T3PR6X473JK4FIA`;
- `203.0.113.7`, без имени, без PIN, без v3:
  `RCINV3:AMAMWADRA4AACAQDAQCQMBYIBEFAWDANBYHQAAEGJQAAABSUEAQSEIZEEUTCOKBJFIVSYLJOF4YDCMRTGQ2TMNZYHE5DWPB5HY7VLEYLRMAIQAGOUCQ2FI5EUWTKOQCBIJBUIRKGI5EESSSLJRGU4T2QKFJFGVCVKZLVQWK2LNOF2XS7AAD3YVLAMFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJ5XY7L6P5UVOCUA`.

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

Кроме приглашения интеграции. Оно тоже проверяется после верного `mac`, ещё до PIN. Приглашение роли `billing` или
`support` от клиента, который назвал себя приложением (`X-Raycontrol-Client: niko/…`), получает `failed_precondition`
с деталью `raycontrol.device.v1.InviteRole{role}`. Приглашение не тратится, попытка PIN тоже: его зарегистрирует сама
интеграция (`rayctl remote enroll` или своя реализация, [integrations-v1](integrations-v1.md) §2.1). Клиенту —
сказать «это приглашение для внешней системы, не для приложения».
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
| `billing`, `support` (только по приглашению) | да, только API | `GetSelf`, `RotateCertificate` | свои методы и только обычные пользователи ([integrations-v1](integrations-v1.md) §2.3) |

- Роли методов — в proto: у каждого метода `google.api.method_visibility` (integrations-v1 §5.1). Что недоступно
  роли, отвечает `permission_denied`.

- `Backup` — только root на самой ноде: в базе все закрытые ключи ноды (R4-13). `GetDeployment` и `GetDeployInputs` —
  тоже. Ключей в них нет (юниты и системные файлы, имена, UID и порты сервисов), но из них root строит план `apply`
  на ноде, а снаружи они не нужны ([apply-plan-v1.md](apply-plan-v1.md)). `SetCertificate` — тоже: в запросе закрытый
  ключ сайта (R4-23), и он заменяет ключ, закреплённый у клиентов; на сокете ноды его принимают только от root, не
  от группы ([cert-pin-v1.md](cert-pin-v1.md) §7). Через API они отвечают `permission_denied`. Так же отвечает
  `RotateService` для сервиса вида `site`: смена ключа сертификата сайта — только root на ноде (cert-pin-v1 §5).
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
- Последний сервис `ssh` (после raycontrol v0.26.0): порты включённых сервисов вида `ssh` — те, на которых периметр
  пускает SSH с адресов администратора и после стука. `SetServiceEnabled {name; enabled: false}` и
  `DeleteService {name}` для последнего включённого сервиса вида `ssh` отвечают `failed_precondition`: без него SSH
  закрыт для всех со следующего снимка периметра. Новое поле `force` (`SetServiceEnabledRequest.force = 3`,
  `DeleteServiceRequest.force = 2`) делает это всё равно; в аудите тогда `service.enable=false force` и
  `service.delete force`. Нода до этого поля его не читает и выключает или удаляет без вопросов.
- Обновление ноды ([node-update-v1.md](node-update-v1.md) §2): с raycontrol v0.27.0 у `GetUpdateStatusResponse`
  поле `latest_patch = 9` — самый новый патч минорной версии ноды, новее неё, который видели проверки rayd (`""` —
  нет такого или проверок не было). `latest` значит то же, что раньше: самый новый релиз вообще. Клиенту:
  `StartUpdate {version: latest_patch}`, когда поле не пусто и не равно `latest`, обновляет без смены минорной;
  кнопка с пустым `version` — как раньше, на `latest`.
- Порты ноды (raycontrol v0.27.0, R4-39): `GetPorts {}` — как весь `NodeService`, и через API. Ответ — `ports[]`,
  `NodePort {name; protos ("tcp", "udp"); from; to; source; access; current; current_until}`. `name` — `spa`, `sub`,
  `api`, `acme` или имя сервиса; диапазон ротации UDP сервиса — `"<имя> rotation"`. `source`: `fixed`, `random`,
  `chosen` (`rayctl install -ports`), `sshd`. `access`: `everyone`, `spa` (после стука), `admin` (адреса
  администратора; после стука — устройства с SSH), `acme` (TCP 80 на время выпуска сертификата без DNS-провайдера).
  У диапазонов, которые меняются по расписанию (`spa` и ротация), `current` — порт текущего слота, `current_until` —
  когда он сменится (unix-секунды); у остальных — нули. Ключей в ответе нет. Клиенту метод не нужен для работы:
  порты он по-прежнему берёт из пакета устройства. Он для экрана «что открыть у провайдера». Старая нода отвечает
  `unimplemented`.
- Порты хоста relay (raycontrol v0.31.0, [relay-v1.md](relay-v1.md) §3.1): у `Relay` — `ports = 5`, у
  `IssueRelayBundleResponse` — `ports = 6`: `RelayPort {name; protos; from; to; forwarded; access}`, всё, что хост
  relay принимает снаружи, для файрвола провайдера перед ним. `name` — `ssh` (SSH самого relay), `spa` (диапазон SPA
  relay), `probe` (точка замера) или пересылаемое к выходу: `sub`, `api`, имя сервиса; `forwarded` — к выходу на тот
  же порт, иначе отвечает сам хост relay. `access`: `everyone`, `spa` (после стука к relay), `admin` (адреса
  администратора relay; после стука — устройства с SSH). `ListRelays` (как весь `NodeService`, и через API) отдаёт их
  по текущим сервисам выхода; до первого пакета у relay нет `spa` и `probe`. Старая нода полей не заполняет.
- Ключи для своего пира Yggdrasil (raycontrol v0.31.0): `GetYggdrasilPeerKeys {service; names}` — как `ListDevices`
  (root и группа на ноде, admin-устройства через API; без аудита). Ответ — `node_key` (открытый ключ ed25519 ноды в
  Yggdrasil, hex), `node_address`, `keys[]`: `YggdrasilPeerKey {public_key; address; user; device_id; device;
  credential; from; until; label}` — ключи, которые пускает файл пользователей бэкенда: у каждого активного
  пользователя сервиса свой ключ (`device_id` пуст: ссылки `rayctl user export`) и ключ каждого неотозванного
  устройства, для каждого UUID ротации: `credential` — `current`, `next` (с `from`, unix-секунды) или `previous` (до
  `until`). `label` — имя ключа в том файле: `u<id пользователя>`, `-<id устройства>`, `-n`, `-p`. Имена пользователя
  и устройства (`user`, `device`) — только при `names: true`: ключи уходят в конфиг на хосте вне ноды, а там имён
  быть не должно (lan-v1 §4.3). Порядок — по пользователю (с `names` — по имени, без — по номеру), сначала его
  собственный ключ, затем устройства (с `names` — по имени, без — по id), у каждого `current`, `next`, `previous`.
  Только открытые ключи: ни seed ноды, ни ключей устройств. Не Yggdrasil — `invalid_argument`, нет сервиса — `not_found`, выключен или без `inner` —
  `failed_precondition`, старая нода — `unimplemented`.

## 5a. Отзыв устройства меняет учётные данные пользователя (raycontrol v0.27.0)

Решение R4-36 ([decisions.md](../decisions.md)). `NodeService.RevokeDevice {id}` — с ноды (`rayctl device
revoke`) и с admin-устройства через удалённый API одно и то же.

**Что меняется.** Ключи самого устройства закрываются, как раньше: SPA, сертификат для API, метка dnsauth, ключ
Yggdrasil, токен DoH. Учётные данные сервисов — у пользователя, а не у устройства, одни на все его устройства.
Поэтому в той же транзакции, что и отзыв, у пользователя заменяется каждая строка `credentials`, кроме строк
сервисов `doh` (ниже): новый случайный секрет (UUID v4), без `next` и без `prev`, ротация (R4-1) считается заново
от этого момента. Флага «не менять» нет. Ключ LAN пользователя новый, как и раньше (lan-v1 §3).

| Вид сервиса | Секрет пользователя | Сменяется отзывом | Когда прежний перестаёт действовать | Открытые соединения |
|---|---|---|---|---|
| `reality` | UUID VLESS | да | сразу после apply: Xray получает пользователей по API | рвутся (форк Xray, `RemoveUser`) |
| `inner` (за ним DNS-туннели и Yggdrasil) | UUID VLESS | да | так же | рвутся |
| `hy2-masq`, `hy2-obfs` | пароль | да | когда niko-server перечитает users-файл, до 5 с | рвутся (niko-server ≥ v0.15.0) |
| `naive` | пароль | да | когда `rayd naive` перечитает users-файл, до 5 с | рвутся (потоки CONNECT, UoT, ICMP) |
| `doh` | секрет DoH; токен в пути — устройства (v0.27.0, R4-37) | нет | токен отозванного — со следующего запроса после ответа `RevokeDevice`: изменение отмечается в том же вызове, до ответа, запрос с токеном (сегмент вида токена) ждёт чтения, начатого после него (не дольше 5 с, потом быстрый `404`), и на токен отозванного отвечает сразу пустым `404`; другие запросы не ждут; общий токен пользователя, если окно после обновления ещё идёт, — так же | запрос за запросом, держать нечего |
| `dnstt`, `masterdns`, `slipstream` | нет: ключ сервиса общий, метка dnsauth — устройства | — | метка отозванного уходит из файла ключей; через туннель без `auth=required` запросы доходят, но `inner` их не пускает | через `inner` |
| `yggdrasil` | ключ устройства (из ключа SPA и UUID `inner`) | ключи остальных устройств пользователя тоже новые: они от UUID `inner` | ключ отозванного уходит из users-файла | рвутся |
| `subscription`, `api`, `ssh` | нет: ключи и сертификат устройства | — | сразу | — |

Ключи самих сервисов (REALITY, туннелей, сайта) отзыв не трогает: они не дают пройти без учётных данных
пользователя, а их смена задела бы всех.

**DoH — не общий секрет (v0.27.0, R4-37).** Токен DoH в строке — устройства: HMAC от секрета DoH пользователя с
ключом SPA устройства ([subscription-v1.md](subscription-v1.md) §4, «Профиль DoH»). Секрет пользователя ни в одну
строку не попадает, а токен соседа без ключа соседа не вычислить. Отзыв поэтому секрет DoH не меняет: отозванное
устройство знает только свой токен, а он уходит вместе с устройством. Остальные устройства пользователя сохраняют
DoH — резолвер, через который они берут подписку, — и прежние строки DoH с прежним `next`. Окно после обновления:
72 ч после миграции 0015 нода ещё принимает прежний общий токен (секрет пользователя) от устройств, не взявших
подписку; отзыв любого устройства пользователя в это окно сразу закрывает его для всего пользователя, так что и
здесь отозванному ничего не остаётся. `RenewUser` и шаг миграции 0014 меняют и секрет DoH, как раньше: там данные могли уйти без
устройства или отзыв был до этого правила; перенос отзывов при `restore` и откате — только если копия старше схемы
15 или её окно ещё открыто (ниже).

**Перекрытия нет.** Окно, в котором прежние данные ещё действуют, было бы окном и для отозванного устройства.
Поэтому остальные устройства пользователя теряют связь вместе с ним, пока не возьмут подписку заново
([subscription-v1.md](subscription-v1.md) §6). Подписку они берут своими ключами (SPA и `RC1` устройства, пин
подписки): отзыв другого устройства их не меняет, и прежние учётные данные для этого не нужны.

**Отзыв с перекрытием (`overlap`, raycontrol v0.31.0, R4-43).** `RevokeDeviceRequest {id; overlap}` — `rayctl device
revoke -overlap ID`; для плановой замены (старое устройство отдали или оно сломалось), не для украденного. Всё, что
закрывается сразу, закрывается так же: ключи самого устройства, ключ LAN пользователя новый (у пароля multicast
перекрытия нет, а отозванное может быть в той же Wi-Fi), секрет DoH не трогается. Иначе — учётные данные: каждая
строка `credentials` пользователя, кроме `doh`, не меняется сразу, а ротируется внепланово с перекрытием плановой
(R4-1): новый случайный секрет становится `next` с `next_from` = отзыв + `-cred-lead` (3 дня) и принимается сразу,
текущий секрет и `prev` в его сроке остаются. В момент `next_from` цикл ротации rayd (раз в 10 минут) делает `next`
текущим, прежний текущий — `prev` на `-cred-grace` (2 дня) от `next_from`; `rotated_at` = `next_from`, следующая плановая смена —
через период от него. Остальные устройства пользователя берут `next` со следующей подпиской и переходят без
разрыва (subscription-v1 §6); `lan.next` — пароль нового ключа LAN для следующего UUID. Отозванное устройство не
проходит SPA и не берёт подписку, свежий `next` ему неизвестен; то, что оно знало, принимается lead + grace
(5 дней по умолчанию), соединения на этом рвутся в конце grace. lead и grace — флаги `rayd serve`; rayd задаёт их
хранилищу при каждом старте, и отзыв берёт их из памяти; в базу (`settings.cred_rotation`) rayd их тоже пишет, с
периодом, — для другого процесса на той же базе; откат и обновление назад читают оттуда период (ниже).

- **Ротация уже идёт.** `next`, опубликованный до отзыва — плановой ротацией или прежним отзывом с `overlap`, —
  отозванное устройство могло взять. Отзыв заменяет его свежим и начинает lead заново; прежний `next` со следующего
  apply не принимается, соединения на нём рвутся, а клиент, который уже на нём, возвращается к `link` (§3 подписки).
- **Несколько отзывов с `overlap` подряд** (устройств одного пользователя) каждый раз заменяют `next` и перезапускают
  lead, иначе устройство, отозванное позже, знало бы `next`. Чтобы цепочка не продлевала текущий секрет без конца,
  переход не позже чем через два lead после первого отзыва, который текущий секрет пережил (отзывы устройств
  пользователя, в любом режиме, позже `rotated_at` строки, и этот; отзыв без перекрытия меняет данные в свою же
  секунду, `rotated_at` = его время, и в цепочку не входит, так же замена при переносе; после перехода (у строки
  есть `prev`, `rotated_at` = `next_from`) входит и отзыв в его секунду: новый текущий секрет он знал как `next`): `next_from` =
  max(min(отзыв + lead, первый + 2·lead), отзыв). Так переход никогда не раньше `next`, который отзыв заменил. Граница: то, что знало любое отозванное так устройство, принимается не дольше 2·lead + grace после его
  отзыва (8 дней по умолчанию), после последнего отзыва цепочки — не дольше lead + grace. Граница держится, пока rayd
  работает с теми же флагами: пока он остановлен, переход не наступает (плоскость данных принимает то, что у неё
  есть), а меньший `-cred-lead` после перезапуска ставит переход раньше заменённого `next`. Переход, запоздавший из-за
  простоя, оставляет `prev` до `next_from` + grace, а не до своего хода + grace, так что `until` из ответа не сдвигается,
  — у ротации, начатой отзывом с `overlap` (есть устройство пользователя, отозванное после того, как текущий секрет
  стал текущим, по тому же правилу, что цепочка); плановый переход (R4-1), запоздавший, оставляет `prev` на grace от
  своего хода, как прежде: клиенты, не взявшие подписку, пока rayd стоял, ещё на прежнем. Ещё предел: отзыв в
  секунду перехода, после него (цикл прошёл в ту же секунду), считается в цепочке, пока у строки есть `prev`; цикл
  снимает его через grace, и тогда такой отзыв не отличить от отзыва без перекрытия в его собственной секунде — для
  устройства, отозванного так, граница 3·lead + grace. Поздний отзыв цепочки даёт
  остальным устройствам меньше lead на переход: не взявшее свежий `next` идёт по `link` (теперь `prev`, весь grace) и
  берёт подписку. Отзыв позже границы, пока цикл rayd ещё не сделал переход, ставит `next_from` = сейчас.
- **Без плановой ротации** (`-cred-period 0`) `overlap` ротирует так же: цикл rayd с v0.31.0 работает и без периода,
  только переходы и сроки; `-cred-grace` меньше 12 ч там поднимается до 12 ч, а `-cred-lead` меньше нуля или от
  30 дней становится 3 днями, с предупреждением в журнале. Отзыв берёт lead и grace те же, что у цикла: rayd задаёт их
  хранилищу при старте; запись в базе — для другого процесса на той же базе, а нечитаемая — значения по умолчанию.
- **Кто может.** Как весь `RevokeDevice`: root и группа на ноде, admin-устройство через удалённый API. `overlap` не
  шире отзыва без него: устройство отзывается так же, а данные отозванного и так у того, кто его держит; он лишь не
  рвёт остальные устройства.
- **Нода до v0.31.0** поле не читает и отзывает без перекрытия. Поэтому `rayctl device revoke -overlap` сначала
  спрашивает версию ноды (`GetStatus`; не ответила — отказ) и на выпуске до v0.31.0 отказывает, ничего не отозвав,
  кроме неиспользованного приглашения (его любая нода отзывает одинаково, данных у него нет); у сборки без номера
  выпуска отзывает и, если `switch_at` пуст, говорит, что нода отозвала без перекрытия (с `-json` — в stderr).
- **Последнее устройство.** Если после отзыва с `overlap` у пользователя не осталось активных устройств, `rayctl`
  предупреждает в stderr: перекрытие никого не держит и только продлевает отозванному время; отрезать сразу —
  `rayctl user renew`.
- **Повторный отзыв** — как без `overlap`: ничего не меняет (`already`). Если ротация, которую начал отзыв этого
  устройства с `overlap`, ещё не дошла до перехода, ответ несёт `until` — до какого времени то, что оно знало, ещё
  принимается, и `rayctl` это говорит, с `rayctl user renew`. После перехода нода этого уже не различает.
- Пользователь без учётных данных, приглашение — как без `overlap`.

**Счётчики.** Имена учётных данных (`store.CredentialName`, `u<id>-<отпечаток>`) у новых секретов новые, но
лимит трафика и пределы соединений считаются по пользователю (`u<id>`, traffic-limit-v1 §2.6, conn-limit-v1):
период и его счёт продолжаются. Процессы держат счётчик ушедшего имени до перезапуска, так что байты прежних данных
до разрыва учтены.

**Случаи.**
- Последнее устройство пользователя — данные меняются так же: строки могли скопировать (`rayctl user export`).
- Устройство `admin` и `user` — одинаково. Admin-устройство может отозвать и само себя; ответ оно получит, дальше
  его API закрыт.
- Повторный `RevokeDevice` уже отозванного устройства — успех, ничего не меняет, данные второй раз не трогает
  (`already: true`). Неиспользованное приглашение — `invite: true`, данных у приглашения нет.
- Сбой после записи. Отзыв и смена данных — одна транзакция: «отозвано, а данные прежние» не бывает. Применяет
  изменение `rayd` (apply сразу после ответа и при каждом старте). Не ответил API Xray — процесс перезапускается;
  не удался и перезапуск — он записан как должный (`restarts/<сервис>`, v0.26.0), повторяется при каждом apply,
  раз в минуту, а `rayctl status` показывает ошибку apply. Пока перезапуск не прошёл, на этом сервисе прежние
  данные ещё действуют. Процесс, который завис и не перечитывает users-файл (Hysteria2, naive), нода не замечает.

**Ответ.** `RevokeDeviceResponse {invite; already; user; device; credentials; switch_at; until}`: чьё устройство, его
имя и сколько учётных данных пользователя новых (с `overlap` — ротируется): все его строки `credentials`, по одной на
каждый сервис, на котором у него есть или была учётная запись, вместе с `inner`, кроме строк `doh` (с v0.27.0 их
отзыв не меняет), — это число строк, а не сервисов пользователя сейчас. `switch_at` и `until` (поля 6 и 7,
v0.31.0) — у отзыва с `overlap`: переход на `next` (самый поздний из строк, unix-секунды) и конец grace, когда то, что
знало отозванное устройство, перестаёт приниматься; оба — до 10 минут позже (цикл rayd). У повторного отзыва
(`already`) — только `until`, пока ротация его отзыва с `overlap` не дошла до перехода. Нода старше v0.27.0 отвечает
пустым сообщением.
**Аудит:** `device.revoke`, цель — `<id> <пользователь>/<устройство>: N credentials of <пользователь> new`, с
`overlap` — `<id> <пользователь>/<устройство>: with overlap: N credentials of <пользователь> rotate: next published,
switch at <RFC 3339 UTC>, the old ones accepted until <RFC 3339 UTC>` (или `revoked already, nothing changed`);
секретов и адресов там нет.

**Имя.** С v0.27.0 имя отозванного устройства свободно: уникально только среди неотозванных устройств
пользователя (миграция 0014). Новое устройство или приглашение может взять то же имя.

**Восстановление и откат.** `rayctl restore` и `rayctl update -rollback` оставляют отозванными устройства,
отозванные в нынешней базе, и дают их пользователям в восстановленной базе новые данные. Замену данных без
отзыва они тоже не отменяют: замена идёт без `next` и `prev`, и прежние секреты в копии — ровно те, что знают
отозванные устройства. С v0.31.0 у восстановления исключение — ротация, которую начал последний отзыв пользователя с
`overlap` и которая ещё не дошла до перехода (у строки, кроме DoH, есть `next`, а текущий секрет не новее этого
отзыва; `store.overlapInFlight`): она переносится как идёт, без новых данных, — новые оборвали бы остальные
устройства, которые оператор решил не рвать, а свежий `next` отозванному неизвестен; отозванное устройство остаётся в
восстановленной базе, и следующие отзывы с `overlap` считают его в цепочке. После перехода — новые данные, как
раньше. Только при нынешней базе на схеме 14 и выше и копии, где секрет DoH — не токен (иначе — новые, как раньше),
и только если у пользователя нет устройства, которого копия не знает (тогда — новые, ниже). Откат такую ротацию не
переносит, а даёт новые данные: `rayd`, к которому он возвращается (до v0.31.0), с `-cred-period 0` цикла ротации не
запускает, переход не наступил бы никогда, и отозванное устройство сохранило бы доступ.

Откат, при котором база остаётся (схема не сдвинулась: v0.27.0–v0.30.x тоже на 15), переноса не делает; не делает
его и обновление назад (`rayctl update -version`, `-from`, `-local`: релиз старше ставит этот же `rayctl`, без
передачи). Поэтому везде, где на ноду встают бинарники `rayd` до v0.31.0 (выпуск старше или сборка без номера, и
`-local`), `rayctl` перед установкой смотрит период в базе (`settings.cred_rotation`: его пишет rayd при старте, так
что флаги, поменянные в юните, учитываются только после перезапуска rayd; при откате и обновлении на v0.31.0 и
новее база не читается). Отрицательный период — это «нет периода» (rayd любой версии тогда не ведёт расписание;
rayd v0.31 и пишет его как 0); записи нет или она не читается — тоже «нет периода», то есть данные обновляются:
лишнее обновление безвредно. Если периода нет (0), `rayctl` останавливает rayd — до решения, чтобы отзыв, сделанный пока
rayd работает, не прошёл мимо, — и на копии root (`store.RenewOverlapRotations`) даёт новые данные, как при отзыве
без перекрытия, и новый ключ LAN каждому пользователю, у которого хоть одна строка, кроме DoH, в ротации: есть
`next` или `prev`, который ещё принимается (`prev_until` впереди). Ни окон, ни lead, ни правил секунды: без периода
плановых ротаций нет, и всё, что в пути, — либо отзыв с `overlap`, либо плановая ротация, начатая до того, как
период стал 0. Пользователи последней тоже получают новые данные — это безвредно: их устройства переподключаются
после следующей подписки. Копия кладётся обратно; аудит `user.renew:rollback` или `user.renew:downgrade` (актор —
команда, как её дали: `rayctl update -rollback`, `rayctl update (automatic rollback)` у отката после неудачного
обновления, `rayctl update -version vX.Y.Z`, `rayctl update -from (vX.Y.Z)`, `rayctl update -local`,
`rayctl update (vX.Y.Z)` у `-force`, когда «последний» старше установленного), `rayctl` перечисляет таких
пользователей. База другой схемы, чем у этой сборки (откат, вернувший копию старее), для этого не открывается:
открытие её бы мигрировало; там отозванное после копии несёт перенос (`CarryRevocations`), который даёт новые данные
пользователям таких устройств при любом периоде. Ошибка после остановки rayd запускает его снова, и ошибка говорит,
в каком состоянии нода (в том числе что обновлённая база уже на месте, если не удалась лишь синхронизация каталога
или WAL; откат, который положил копию базы без её WAL, останавливается с rayd остановленным и пишет команды, которыми
положить копию и её WAL руками, — повторный откат с `-no-carry` нашёл бы схемы равными и базу не тронул);
обновление назад, которое не смогло обновить данные, ничего не ставит; откат с ошибкой тоже
ничего не ставит, кроме отката после неудачного обновления (он идёт дальше и пишет, что то, что знали отозванные с
`-overlap` устройства, ещё принимается, и что нужен `rayctl user renew ИМЯ`), а `-no-carry` никого не обновляет. С
периодом ротацию доведёт цикл прежней версии (переход и срок `prev`), база остаётся как есть, и rayd ради этого не
останавливается.

Пути назад, которые это закрывает и которых нет: обновлением по запросу и автообновлением нода назад не уходит
(запрос не новее установленной версии отклоняется); передача обновления (handoff) — только вперёд, а на релиз до
v0.31.0 с ноды без номера выпуска (`dev`) её нет: обновляет этот `rayctl`. `bootstrap.sh` поверх базы ноды не
ставит релиз старше того, что называет её `rayd`, и предлагает `rayctl update -version` (или
`RAYCONTROL_VERSION=<установленная>`, если «последний» на GitHub оказался старше); если `rayd` релиза не называет
(его нет после `rayctl uninstall -keep-state`, он не запускается, сборка без номера), — не ставит релиз до v0.31.0;
с `-check` в этих случаях выходит с 1. Чего код не видит: копия v0.31, восстановленная `rayctl` старшего релиза на
новом сервере (восстанавливайте её `rayctl` v0.31 или новее, иначе — `rayctl user renew` пользователям устройств,
отозванных с `-overlap`), и `bootstrap.sh` старого релиза, в котором проверки нет: назад — только `rayctl update`.

Восстановление (`store.CarryRestore`, с v0.27.0 без опоры на журнал аудита). На той же ноде (`node_id` в
`spa_params` копии и нынешней базы совпадает) клиенты держат секреты нынешней базы, так что секреты копии — те же
или старее. Вернуть старые значит оборвать всех клиентов до следующей подписки и, возможно, вернуть секрет,
сменённый из-за утечки (`rayctl user renew`), — а строка аудита о той замене могла уйти (журнал чистится через
90 дней) или не попасть в копию (повторное восстановление, откат). Восстановление возвращает пользователей,
устройства, сервисы и настройки, а не старые секреты.

Но тот же `node_id` ещё не значит, что нынешняя база — более позднее состояние той же ноды: `node_id` лежит в базе,
и копия, восстановленная на новом сервере, отдаёт ему `node_id` старого (так же клон диска), а `restore -no-carry`
старой копии оставляет ноду позади её же более новых копий. Перенос в такую базу молча положил бы её старые секреты
поверх секретов копии: секрет, сменённый после утечки, вернулся бы, а данные пользователя отозванного устройства
стали бы теми, что оно знает. Поэтому перед переносом `restore` проверяет, что нынешняя база не старше копии ни в
чём (`backupNewer`), сперва по признакам, которые не сравнивают часы:

- устройство в копии отозвано, а в нынешней базе активно (отзыв — навсегда);
- в копии есть устройство, которого в нынешней базе нет, а его пользователь (ID, имя, время создания) есть: устройство
  уходит только вместе с пользователем;
- строка `credentials`, которая есть в обеих, в копии ушла дальше: нынешний секрет — `prev` копии, нынешний `next` —
  текущий секрет копии, у копии есть `next`, которого нет у нынешней при том же текущем (кроме случая, когда у
  нынешней другой `next` и устройство пользователя отозвано в ней после копии: отзыв с `overlap` заменяет `next`,
  v0.31.0); или `rotated_at` копии (его ставят и смена по ротации, и замена) позже;
- сервис копии с ID, которого нынешняя база не выдавала (выше её последовательности `AUTOINCREMENT`) или выдала
  другому (вид, время создания);
- приглашение в копии использовано, а в нынешней базе нет, или у него в копии меньше попыток PIN;
- строки аудита копии нет в нынешней базе, хотя строки такой давности там ещё хранятся (`rayd` чистит журнал по
  времени, начиная со старых): аудит есть у каждого изменения через API;
- самая поздняя запись копии (создание пользователя, устройства, сервиса, приглашения, отзыв, согласие LAN,
  использование приглашения, ротация, строка аудита) позже самой поздней записи нынешней базы.

Ротация, граница журнала и последняя запись сравнивают время. На одном сервере часы одни, и более позднее состояние
ноды хранит каждую запись копии или более позднюю. Если сервера два (копия восстановлена на новом, и тот пошёл своим
путём), записи нынешней базы до расхождения несут время сервера копии; часы нынешнего сервера, отстающие, делают
эти признаки только чувствительнее, спешащие могут их скрыть, а признаки без часов всё равно видят отзыв, новое
устройство или сервис, смену общего секрета и строку аудита на стороне копии. Признаки читаются из копии как она
есть в файле, до `rayd init` (тот мигрирует копию, и шаг 0014 меняет и аудирует данные временем восстановления).
Хоть один признак — и копия восстанавливается как есть, без переноса, а все её активные устройства — в предупреждении,
как для чужой базы; первой строкой `restore` пишет «the backup is newer than this node's database: nothing carried»
и найденный признак.

Правила переноса, по порядку:

| Что в копии | Как определяется | Что получает восстановленная база |
|---|---|---|
| Строка `credentials`, которая есть и в нынешней базе | тот же пользователь (ID, имя, время создания) и тот же сервис (ID, вид) | секрет, `next`, `prev`, `rotated_at` нынешней базы; ключ LAN пользователя — нынешний |
| Пользователь, удалённый после копии | в нынешней базе нет пользователя с тем же ID, именем и временем создания | все строки — новые секреты без `next` и `prev`, новый ключ LAN: кто ещё знал прежние (устройства, созданные после копии и ушедшие с пользователем), не узнать |
| Пользователь, удалённый и созданный снова под тем же именем | имя есть, ID или время создания другие | так же, новые данные: это другой пользователь |
| Строка сервиса, удалённого после копии | у пользователя совпадает, у сервиса нет (ID или вид) | новый секрет этой строки; остальные строки — нынешние |
| Ключ LAN, которого в нынешней базе нет (LAN выключили после копии) | пользователь совпадает, у нынешнего ключа нет | новый ключ |
| Устройство, отозванное после копии | в копии активно, в нынешней базе отозвано | отозвано (время — нынешней базы); пользователю новые данные во всех строках и новый ключ LAN (`carryDevices`); если его ротация с `overlap` ещё не дошла до перехода — строки и ключ LAN нынешние, ротация идёт дальше (v0.31.0), кроме пользователя со строкой ниже |
| Пользователь с устройством, созданным после копии, отозванным или нет | устройства нет в копии, в нынешней базе оно есть, пользователь совпадает | новые данные во всех строках и новый ключ LAN: устройство знало данные пользователя, а в восстановленной базе его нет, так что действующее до сих пор отрезано сразу, а не к следующей ротации; `restore` перечисляет такие устройства. Отозванное с `overlap` — так же: восстановленная база о нём не знает, и цепочка следующих отзывов его бы не учла |
| Секрет DoH при двух последних правилах | копия на схеме ≥ 15 и окна `doh_shared` в ней нет | остаётся нынешним, как при `RevokeDevice` (R4-37); иначе (окно открыто, копия старше 15) тоже новый: секрет там — токен, и отозванное устройство могло его знать |
| Активное устройство, о котором нынешняя база не знает | нет устройства с тем же ID (его пользователя удалили) | остаётся как в копии; `restore` перечисляет его с предупреждением |
| Чужая база (новый сервер: другой `node_id` или нет `spa_params`) | — | ничего не переносится и не пишется; все активные устройства копии — в предупреждении |
| База этой ноды, но не позднее копии | тот же `node_id`, и хоть один признак выше | так же: ничего не переносится и не пишется, все активные устройства копии — в предупреждении, а первой строкой — почему |

`restore` (`rayctl restore` выполняет перенос после `rayd init` копии, так что копия уже на схеме нынешней `rayd`;
признаки выше — по копии до `rayd init`) говорит коротко: «credentials and LAN keys stay as they are on this node now for N users», затем отозванные
устройства (с v0.31.0 отдельно те, чья ротация с `overlap` идёт дальше: «revoked here with overlap since the
backup»), затем устройства, добавленные после копии («added here since the backup, so not in it»), затем «new
credentials» с пользователем и причиной на строку, затем предупреждение о неизвестных устройствах. `-no-carry` восстанавливает копию как есть.

Откат (`store.CarryRevocations`) учётные данные не возвращает вовсе: каждая строка `credentials`, которая есть
и в копии, и в нынешней базе (тот же пользователь — ID, имя и время создания — и тот же сервис), берётся из
нынешней, ключ LAN тоже. Так остаются и данные шага миграции 0014 и `RenewUser`, и обычная ротация после копии:
её секреты — те, что клиенты уже взяли, и второго разрыва нет. Строк и пользователей, появившихся после копии,
в копии не появляется; пользователь, удалённый после копии, в ней выключен, сервис — тоже. Строка, которой в
нынешней базе нет (пользователь удалён или создан заново, сервис удалён), получает новый секрет, как при
восстановлении, а такой пользователь — новый ключ LAN: устройство, созданное после копии и ушедшее вместе с
пользователем, могло знать секреты копии, и включённый снова пользователь пустил бы его. С v0.31.0 откат, как и
восстановление, даёт новые данные сразу пользователю устройства, созданного после копии, активного или отозванного,
с `overlap` тоже, и ключ LAN, если в копии он есть: откат его убирает, а оно знало данные пользователя; раньше откат
их не трогал. Пользователю устройства, отозванного с `overlap` после копии, откат тоже даёт новые данные, а не
переносит ротацию: прежний `rayd` с `-cred-period 0` её не довёл бы. Таблица `credentials` с миграции 0003
не менялась (0014 меняет только `devices`), так что прежний `rayd` читает перенесённое как своё. Секрет DoH
пользователей отозванных устройств — по тому же правилу, что и у восстановления: копия старше схемы 15 (откат на
v0.26.0) берёт секрет как токен, и он тоже новый.

Копия старше схемы 14 при следующем обновлении снова проходит шаг 0014. Чтобы он не оборвал второй раз тех, кого
уже обновил первый раз, откат пишет в `settings` копии `revoked_renewed_at` (время переноса, секунды Unix; прежний
`rayd` читает настройки по ключу и её не замечает); пользователь копии, которого в нынешней базе нет, новые данные
получает и так (выше). Шаг 0014 с этой настройкой обновляет только пользователей устройств,
отозванных в это время или позже (их отозвал прежний `rayd` уже после отката), и удаляет её. Пишет её откат,
только если нынешняя база на схеме 14 или новее, то есть шаг 0014 в ней прошёл и перенос принёс его данные. Откат
обновления, сорвавшегося до запуска нового `rayd` (не встал юнит `rayspa`, не встали бинарники), находит нынешнюю
базу ещё на 13: шаг не прошёл, никого не обновил, и отметки нет — следующее обновление обновит всех пользователей
с отозванными устройствами. Отметка, которая в копии уже есть (её оставил прошлый откат, и обновление скопировало
базу вместе с ней), остаётся со своим, более ранним временем: отметка — утверждение, что до этого времени все
отозванные обновлены, и позднее время, окажись оно неверным, навсегда оставило бы данные отозванных между двумя
временами; раннее стоит только повторной замены у их пользователей при следующем обновлении.

**Аудит переноса** (в получившейся базе, без секретов): `device.revoke:restore` / `device.revoke:rollback` на каждое
перенесённое отозванное устройство (`<id> <пользователь>/<устройство>: revoked on the node since the copy`, у
ротации с `overlap` — ещё `, with overlap: its rotation goes on`),
`user.renew:restore` / `user.renew:rollback` на каждого пользователя с новыми данными (`<пользователь>: N credentials
new, <причина>`; у отката с v0.31.0 и `a device made on the node since the copy, not in it`, `a device made and
revoked on the node since the copy`) и одна строка `user.carry:restore` / `user.carry:rollback` (`N users: credentials and LAN keys as on
the node`). Так история замены не теряется, даже если её собственная строка осталась в другой базе.

**Обновление до v0.27.0.** Отзыв до v0.27.0 данные пользователя не менял, а повторный отзыв теперь ничего не
меняет (`already`). Поэтому при обновлении, один раз, в транзакции миграции 0014 (шаг на Go после её SQL, вместе
с записью версии 14), каждый пользователь, у которого есть отозванное устройство, получает новые данные так же,
как при отзыве: новый секрет в каждой строке `credentials`, без `next` и `prev`, и новый ключ LAN, если он есть.
Все такие отзывы — от прежних версий: база на схеме 13 других не знает. Время последней ротации (`rotated_at`)
не доказывает, что данные уже другие: текущий секрет был в подписках как следующий за время `-cred-lead` до
смены, прежний принимается ещё `-cred-grace` после неё, а когда секрет впервые ушёл в подписку, база не хранит.
Поэтому данные меняются у всех таких пользователей. Остальные их устройства переподключаются, как после отзыва:
Niko — на ближайшей проверке соединения, до ~10 минут (subscription-v1 §6). В аудите — строка на пользователя: actor `rayd (schema 14)`, действие
`user.renew:revoked-before`, цель `<пользователь>: N credentials new, ...`, без секретов. При следующих стартах
шаг не повторяется (версия 14 уже записана); база, которая перескакивает несколько версий, проходит его на 14.
База, вернувшаяся на схему 13 (`update -rollback`), при следующем обновлении проходит его снова, но по отметке
отката `revoked_renewed_at` (выше): новые данные получают только пользователи устройств, отозванных на старой версии
после отката, — их отзыв данные не менял, — а не второй раз все.

**Токен DoH при обновлении (миграция 0015).** Таблицы не меняются: токены устройств выводятся, а не хранятся.
Шаг на Go после SQL версии 15 записывает в `settings` окно `doh_shared` (`<начало> <конец>`, секунды Unix, конец —
через 72 ч), если в базе есть учётные записи сервиса `doh`; новая нода и нода без DoH окна не получают. Повторный
старт окно не сдвигает. Откат (`update -rollback`) возвращает базу до обновления: прежняя версия снова принимает
только общий токен, и устройства, уже взявшие подписку с токеном устройства, теряют DoH, пока не возьмут подписку у
прежней версии (их ключи SPA и `RC1` откат не меняет). Отзывы, сделанные после обновления, откат переносит, и
данные их пользователей, секрет DoH тоже, в возвращённой базе новые.

**`RenewUser {name}`** (`rayctl user renew NAME`, v0.27.0) — то же для пользователя без отзыва: все его учётные
данные новые сразу, без перекрытия, новый ключ LAN. Для данных, которые ушли не с устройством (строки
`rayctl user export`, переданные дальше), и чтобы не создавать и не отзывать для этого лишнее устройство; после
отзыва с `overlap` — чтобы всё-таки отрезать отозванное сразу. С ноды и с admin-устройства, как `RevokeDevice`. Ответ `RenewUserResponse {name; credentials}`, неизвестный
пользователь — `not_found`, нода старше v0.27.0 — `unimplemented`. Аудит: `user.renew`, цель
`<пользователь>: N credentials new`.

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
| `permission_denied` | роль устройства этот метод не вызывает (§5, [integrations-v1](integrations-v1.md) §2.3), или вызов только для root на ноде; `Register`: PIN не прислан или неверный, деталь `PinTries{left}` (§4); вызов не с того адреса: устройство интеграции со списком адресов — не из своего списка, любое другое — с адреса из чужого списка, приглашение со списком — не из него (integrations-v1 §3.2) |
| `resource_exhausted` | устройство интеграции сверх своих пределов частоты или общего предела интеграций (integrations-v1 §2.6): ничего не сделано, повтор позже безопасен |
| `invalid_argument` | неверные данные: подпись при смене ключа, имя, срок приглашения, период или день сброса лимита, пустой `SetUserTraffic` |
| `failed_precondition` | `ExportUser`: пользователь отключён, истёк или сверх лимита трафика; `billing`: удаление, выключение или выключение под другим именем (срок «сейчас», список без включённых сервисов, лимит, который сразу отрезает) сверх часового предела без `confirm_mass`, лимит, который включил бы или выключил учёт трафика (integrations-v1 §2.4); `RotateService` dnstt или masterdns без `now` и `force`, пока прежний ключ ещё в своём сроке (dnsseal-v1 §8). Только root на ноде: `RotateService` сайта, пока следующий ключ не пробыл срок публикации (без `force`) или ключу в работе меньше 72 часов (с `force`, без `fresh`); `SetCertificate` без `force`, когда он отрезал бы клиентов с пинами (cert-pin-v1 §5, §7); `SetServiceEnabled` (выключить) и `DeleteService` без `force` для последнего включённого сервиса вида `ssh` (§5) |

## 8. Что проверить клиенту

1. TLS: `X25519MLKEM768`, пин `api.pin`, клиентский сертификат на каждом соединении.
2. При регистрации — `expires` приглашения, свои часы (±2 минуты), пин в `mac` именно текущего сертификата.
3. Пакет из `Register` — обычный `rcdev1:`, его проверки те же. Подписку дальше клиент берёт как раньше,
   с `/sub/v1` ([`subscription-v1.md`](subscription-v1.md)).
4. Ключ клиентского сертификата — секрет устройства наравне с ключом SPA: хранить в Keystore или Keychain.
