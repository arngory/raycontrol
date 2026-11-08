# traffic-limit-v1: лимит трафика пользователя

Статус: **черновик** (2026-11-08). Сервер — raycontrol v0.21.0, niko-server v0.15.0, новый коммит форка Xray.
Клиент — Niko после 1.40.

Зачем: `rayctl user add -limit 50G` только записывает лимит, байты пользователя не считает никто
([15-traffic](../15-traffic.md) §5). Здесь нода считает байты каждого пользователя на всех профилях и снимает его, как
просроченного, когда лимит исчерпан. Клиент видит «N из M ГБ» и «лимит исчерпан» вместо молчаливых отказов.

Пути без префикса — в этом репозитории; `xray:` — форк Xray `a4a3dff`, `niko:` — niko-server v0.14.0.

## 1. Что считается

**Единица** — полезная нагрузка на стороне назначения: байты, которые нода отправила назначению (`up`) и получила от
него (`down`), TCP и UDP. Лимит — сумма `up + down` за период. Почему так:
- так считает Xray: счётчики пользователя стоят на звене между входом и выходом
  (`xray:app/dispatcher/default.go:160-180`), провод он без правок не считает. niko-server и naive считают так же;
- пользователь не платит за потери и повторы (Hysteria2 с Brutal), паддинг naive и Vision, кодирование DNS-туннелей;
- минус: провод ноды тяжелее счётчика (оценка: +5–15 % у TCP-профилей, у DNS-туннелей — в разы). Квоту хостера
  считать с запасом.

| Профиль | Где считается | Имя счётчика |
|---|---|---|
| REALITY | Xray своего сервиса | `u<id>`, при ротации ещё `u<id>-n`, `u<id>-p` (`internal/render/render.go:414-422`) |
| dnstt, masterdns, slipstream, Yggdrasil | Xray `inner` | те же: UUID в `inner` у пользователя свой |
| Hysteria2 | niko-server | имя из users-файла, те же `u<id>…` (`render.go:1508`) |
| naive (HTTP/2, HTTP/3, UoT) | процесс `rayd naive` | хеш пароля → имя (§2.3) |

**Личность за `inner` сохраняется** (проверено по коду):
- клиент DNS-туннеля и Yggdrasil идёт в `inner` по VLESS со своим UUID `inner` (`internal/sub/sub.go:369`, `:378`);
- niko-server VLESS не разбирает, а несёт байты как есть: dnstt и masterdns открывают `inner` на каждый поток
  (`niko:nikoserver/backend.go:42`), выход Yggdrasil копирует TCP в сокет `inner` (`niko:nikoserver/yggdrasil.go:518`),
  slipstream — `--target-unix` (`render.go:998`);
- `inner` узнаёт пользователя по UUID: email `u<id>` (`render.go:1185`). Общей личности нет.

Различить туннели между собой `inner` не может: UUID у пользователя один на все. Для лимита это не нужно.

**Не считается:**
- DoH ноды (`internal/doh`): единицы МБ в месяц, отвечает сам rayd. Снимается вместе с пользователем (§3.1);
- служебное мимо туннелей: SPA, подписка, замеры на порт подписки (свой предел, [probe-v1](probe-v1.md) §5), зеркало
  Niko. Замеры через туннель (имя `probe`) считаются: в Xray это тот же линк пользователя (вопрос 3);
- трафик процесса между последним опросом и его падением (§2.4); устройства по отдельности.

## 2. Сбор

### 2.1 Xray (`inner` и каждый REALITY)

- При включённом учёте (§5): `"stats": {}`, `policy.levels.0` со `statsUserUplink` и `statsUserDownlink`,
  `StatsService` в `api.services` (сейчас только `HandlerService`, `render.go:1232`). Пользователи — уровня 0
  (`internal/xrayapi/xrayapi.go:59`).
- rayd читает тот же API-сокет (`render.go:375`): `QueryStats{pattern: "user>>>", reset: false}` и
  `GetSysStats.Uptime` — по нему видно перезапуск. `reset: true` не годится: rayd, упавший между чтением и записью,
  потерял бы байты.
- `u5`, `u5-n`, `u5-p` складываются в пользователя 5. `reality-prev` — тот же процесс и те же счётчики.
- Proto `app/stats/command` из форка — в `api/xray`, код — в `internal/gen/xray`.
- Vision splice увеличивает счётчик только в конце (`xray:proxy/proxy.go:771-787`). За фронтом splice не бывает: нужен
  `*net.TCPConn` (`:744`), а REALITY всегда на unix-сокете фронта (`render.go:168`). По коду, не замером.

### 2.2 niko-server (Hysteria2)

Сокет статистики сейчас отдаёт только RTT и потери (`niko:nikoserver/hystats.go`). В v0.15.0:
- байты по пользователю: потоки — в `outbound.NewConnectionEx` (`niko:nikoserver/hysteria.go:204`), датаграммы — в
  `relayUDP` (`:238`). Имя — `auth.UserFromContext[string](ctx)`, его кладёт sing-quic (так же берёт sing-box,
  `protocol/hysteria2/inbound.go:239` форка);
- новый запрос на том же сокете — строка `traffic` вместо адреса:

  ```json
  {"v": 1, "boot": "<16 hex>", "users": {"u5": {"up": 123, "down": 456}}}
  ```

  Значения — с запуска процесса, чтение их не сбрасывает; `boot` случаен на каждый запуск;
- старый niko-server на `traffic` закрывает соединение без ответа (`hystats.go:209`): так rayd видит, что счёта нет;
- счёт всегда включён, настройки нет (§5).

### 2.3 naive

Отдельный процесс `rayd naive` (`cmd/rayd/main.go:1239`), не `rayd serve`.
- users-файл — сейчас список хешей (`render.go:1648`), станет `{"<хеш>": "u5"}`; старый вид читается тоже;
- счёт после снятия паддинга: TCP — два `io.Copy` (`internal/naive/naive.go:123`, `:130`), UoT — длины пакетов;
- `-stats-socket` (`Paths.StatsSocket`, как у Hysteria2), запрос и ответ — как в §2.2; юнит —
  `internal/deploy/deploy.go:435`;
- `internal/naive` сейчас правится под UoT (v0.20.0): эти изменения — после неё.

### 2.4 Опрос и дельты

- `rayd serve`, цикл `traffic` по образцу `watchDNSTT` (`cmd/rayd/dnstt.go`): раз в **15 с** все источники —
  `xray:<сервис>`, `hy2:<сервис>`, `naive:<сервис>`.
- По паре (источник, имя) rayd помнит последнее значение и `boot`. Тот же `boot` и значение не меньше — дельта есть
  разница. Новый `boot` или значение меньше — дельта есть всё значение. `boot` Xray — `now − Uptime`, допуск 5 с.
- Метки — по имени, не по пользователю: `users.id` переиспользуется (`INTEGER PRIMARY KEY` без AUTOINCREMENT,
  `internal/store/migrations/0001_init.sql:10`), а Xray помнит счётчик `u7` удалённого до своего перезапуска.
- Источник не ответил — дельты нет, в `rayctl status` цикл `traffic <сервис>` с ошибкой.
- Перед перезапуском, который делает сам rayd (`internal/live/live.go:182`), — внеочередной опрос процесса.
- Теряется только трафик процесса между последним опросом и его падением (≤ 15 с). Счёт бывает меньше настоящего,
  больше — нет.

### 2.5 Хранение

Миграция `0011_traffic.sql` (или следующий свободный номер):

```sql
ALTER TABLE users ADD COLUMN traffic_period TEXT NOT NULL DEFAULT 'monthly'; -- 'monthly' | 'none'
ALTER TABLE users ADD COLUMN traffic_reset_day INTEGER NOT NULL DEFAULT 1;   -- 1..28
CREATE TABLE user_traffic (     -- только пользователи с лимитом
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    period_start INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0);
CREATE TABLE traffic_marks (    -- последние значения счётчиков, без FK (§2.4)
    source TEXT NOT NULL, name TEXT NOT NULL, boot TEXT NOT NULL,
    up INTEGER NOT NULL, down INTEGER NOT NULL, PRIMARY KEY (source, name));
```

- Дельты и метки — **одной транзакцией**: раз в минуту, сразу при переходе через лимит и при остановке rayd. Упал
  rayd — следующий опрос считает от меток в базе: ничего не теряется и не считается дважды.
- Метки — только имён пользователей с лимитом. Лимит только что задан — счёт с первого опроса после этого (метка =
  текущее значение). Новое имя у знакомого процесса — с нуля.
- Откат обновления возвращает базу до него (`internal/store/store.go:81`): учёт за это время теряется.

## 3. Применение

### 3.1 Кто снят

Снят пользователь с лимитом, у которого `up + down` текущего периода ≥ лимита. Снятый — **как просроченный, сразу на
всех профилях**. Условие одно (`store.User.Active(now)`) вместо нынешних копий:
- `render.Collect` (`render.go:225`): нет в конфигах Xray, Hysteria2, naive, Yggdrasil и в профилях подписки;
- `SPADevices` (`internal/store/entities.go:626-633`): устройствам снятого остаются подписка и, у admin, API, без
  сервисов данных. Ключи dnsauth берутся отсюда же;
- `dohTokens` (`cmd/rayd/main.go:613`); `ExportUser` (`internal/api/server.go:403`) — `FailedPrecondition`;
- метрика `raycontrol_users` (`internal/api/metrics.go:92`) — состояние `over_limit`.

Цикл `traffic` будит apply (`Server.Notify`) только при переходе через лимит. В audit — `user.traffic=exhausted` и
`=restored`, актор `rayd`.

### 3.2 Живые соединения

**Находка.** Убрать пользователя из конфигов — сейчас значит порвать его соединения только у Yggdrasil
(`niko:nikoserver/yggdrasil.go:89`). Остальные живут дальше, сегодня так же для просрочки и выключения:
- Xray: `RemoveUser` только убирает UUID из таблицы (`xray:proxy/vless/validator.go:47-58`). Новые TCP Vision не
  пускаются, открытые идут до конца; XUDP и потоки DNS-туннелей — долгие соединения.
- Hysteria2: пароль проверяется раз на QUIC-соединение, `UpdateUsers` только меняет таблицу (sing-quic в
  `third_party` niko-server, `hysteria2/service.go:169-175`, `:301-306`, `:393`). Смотрел checkout v0.10.0-8: в модуле
  v0.14.0 `third_party` нет, вызов тот же (`hysteria.go:146`) — вывод. Клиент с keepalive 25 с ходит без конца.
- naive: пароль — на каждый CONNECT; открытые потоки живут до конца или простоя (5 мин, UoT — 2 мин).

Без разрыва лимит не настоящий. Нужно:
- niko-server: при перечитывании users закрывать QUIC-соединения ушедших имён, как у Yggdrasil (sing-quic отдаёт в
  `ConnectionHook` способ закрыть соединение);
- форк Xray: `RemoveUser` закрывает соединения этого email (учёт в `proxy/vless/inbound`, оценка — ~50 строк);
- naive: сам следит за users-файлом и рвёт потоки ушедших хешей.

Побочно: конец срока прежнего UUID после ротации (R4-1) тоже рвёт соединения на нём. Приемлемо.

### 3.3 Задержка и перерасход

С разрывом: опрос до 15 с, apply 0,5 с (`live.go:327`), Xray через API сразу, Hysteria2 и naive перечитывают
users-файл до 5 с (`niko:nikoserver/hysteria.go:170`). Итого до ~20 с полной скорости пользователя сверх лимита:
~250 МБ на 100 Мбит/с, ~2,5 ГБ на 1 Гбит/с. Без разрыва перерасход не ограничен.

### 3.4 Период

- `monthly` (по умолчанию): день сброса 1–28 (по умолчанию 1), 00:00 UTC — как сутки probe-v1. 29–31 нельзя: их
  нет в каждом месяце.
- `none` — лимит на всё время пользователя («пакет»); обнуляет только `reset-usage`.
- Сброс: `up` и `down` в ноль, `period_start` — момент сброса; снятые возвращаются в течение опроса. Лимит задан
  впервые — `period_start` = сейчас, первый период короче.
- Лимит поднят выше расхода — возврат со следующего опроса; опущен ниже — снятие. Смена дня сброса не обнуляет.
- Лимиты, записанные до этой версии, начинают действовать после обновления, с нуля (вопрос 2).

### 3.5 rayctl

```
rayctl user add NAME -limit 50G [-period monthly|none] [-reset-day 1]
rayctl user limit NAME 50G|off [-period monthly|none] [-reset-day N]
rayctl user usage [NAME]          # USED LIMIT PERIOD SINCE RESET STATE
rayctl user reset-usage NAME      # обнулить текущий период
```

- `user list` — колонка `USED` (`12.0G/50G`).
- «recorded, not enforced yet» (`cmd/rayctl/main.go:385`, `:406-409`) уходит. Новое предупреждение — когда первый
  лимит включает учёт: `inner` и REALITY перезапустятся, соединения оборвутся один раз (§5).

### 3.6 API (`api/proto/raycontrol/node/v1/node.proto`)

- `User` (`node.proto:348`): `traffic_used_bytes = 9` (`up + down` периода), `traffic_period_start = 10` (unix),
  `traffic_period = 11` (`monthly` | `none`), `traffic_reset_day = 12`, `traffic_next_reset = 13` (unix, 0 — нет).
  Без лимита — нули.
- `CreateUserRequest`: `traffic_period = 6`, `traffic_reset_day = 7`.
- Новый `SetUserTraffic {name; optional int64 limit_bytes (0 — снять); optional string period; optional int32
  reset_day; bool reset_usage}`. Пустой — `InvalidArgument`. Аудит `user.traffic`. admin-устройствам доступен, как
  весь `NodeService` ([api-v1](api-v1.md) §5).

## 4. Что видит клиент

В payload подписки ([subscription-v1](subscription-v1.md) §3) — необязательное поле, только у пользователя с лимитом:

```json
"traffic": {"v": 1, "used": 12884901888, "limit": 53687091200, "since": 1767225600, "reset": 1769904000}
```

`used` — `up + down` с `since` в байтах (отстаёт до минуты), `limit` — байты, `since` — начало периода, `reset` —
следующий сброс (`0` — период `none`).

- `used ≥ limit` — лимит исчерпан. Нода отвечает `200` с `profiles: []`, а не `404`, как просроченному
  (`internal/sub/server.go:205`): подписка в SPA у снятого остаётся (§3.1). Пустой список бывает и сейчас — у
  пользователя без сервисов.
- `expires` такого ответа — не позже `reset` (плюс до 10 мин случайно) и не дальше часа: клиент сам узнает о сбросе
  или поднятом лимите.
- Niko показывает «N из M ГБ, сброс 1 декабря», около 90 % предупреждает, при исчерпании — «Лимит исчерпан».
  Свежая цифра — перезапросом подписки, чаще раза в 10 минут незачем.
- Ссылки, подписи, `seq` прежние. Старый Niko поля не знает. Выключенным и просроченным — по-прежнему `404`.

## 5. Выключено по умолчанию. Цена

- Учёт включён, пока хоть у одного пользователя задан лимит. Иначе в конфигах Xray нет `stats`, `policy` и
  `StatsService`, цикл `traffic` никого не опрашивает, таблицы пусты.
- Включение и выключение меняет конфиг Xray не только в `clients`: `live` перезапускает `inner` и REALITY
  (`live.go:154`). Один обрыв соединений этих профилей.
- Xray: два счётчика на пользователя; на соединение — поиск счётчика под мьютексом, на MultiBuffer — один
  `atomic.AddInt64` (`xray:app/dispatcher/stats.go:14-16`). На фоне TLS и ML-KEM-шифрования VLESS — доли процента
  CPU. Оценка, не замер: замерить на стенде [14-capacity](../14-capacity.md) до релиза.
- niko-server и naive: счётчики всегда, та же цена; без лимитов их никто не читает.
- Опрос раз в 15 с — `QueryStats` на процесс Xray и строка в сокет остальным; SQLite — транзакция раз в минуту.

Отложено: счётчики только у пользователей с лимитом через уровни политики Xray. Уровень пришлось бы синхронизировать
(`SyncVLESS` сравнивает только UUID, `xrayapi.go:115`), а живые соединения оставались бы без счёта.

## 6. Приватность

- Счётчики только по пользователю: `up` и `down` за период. Ни назначений, ни имён, ни портов, ни времени
  соединений, ни устройств.
- В базе — только пользователи с лимитом и только текущий период, без истории; время — только `period_start`.
- Журналы: Xray остаётся `warning`, `access none` (`render.go:1231`) и в окне отладки. niko-server и naive счётчики
  не пишут. rayd пишет только переход через лимит, имя — непрозрачный номер ([09-observability](../09-observability.md)
  §1).
- Метрики и `rayctl report` — только числа (с лимитом, снято), без пользователей.
- Сокеты статистики — в каталогах группы сервиса и rayd, как у dnstt (`render.go:1605`). Подписка отдаёт устройству
  счётчик только его пользователя.

## 7. Что где меняется

- **raycontrol v0.21.0:** store (§2.5, `Active`, `SPADevices`); render (§2.1, users-файл naive); rayd — цикл
  `traffic`, `rayctl status`, опрос перед своими перезапусками; `rayd naive` (§2.3, §3.2); api и метрика (§3.6);
  sub (§4); rayctl (§3.5); proto `StatsService`; доки — [15-traffic](../15-traffic.md) §5,
  [subscription-v1](subscription-v1.md) §3, [api-v1](api-v1.md).
- **niko-server v0.15.0:** Hysteria2 — байты по пользователю и запрос `traffic` (§2.2), разрыв QUIC-соединений
  ушедших (правка sing-quic в `third_party`). Yggdrasil, DNS-бэкенды, фронт — без изменений. Затем пин в raycontrol:
  `deploy/versions.env:39-45` (тег, коммит, хеши) и `docs/handoff/SYNC.md`.
- **Форк Xray:** `RemoveUser` рвёт соединения email; пин `XRAY_COMMIT` (`deploy/versions.env:7`). Сам счёт работает и
  на `a4a3dff`.
- **Niko:** разбор `traffic`, экраны §4.

## 8. Открытые вопросы владельцу

1. Период по умолчанию — `monthly`, день 1, UTC (предложение) или `none`?
2. Лимиты, записанные раньше «not enforced»: применять сразу после обновления, с нуля (предложение), или только после
   нового `rayctl user limit`?
3. Замеры probe через туннель считаются: в Xray иначе не выйдет без правок. Оставить так?
4. Разрыв в Xray: правка форка (предложение) или запасной путь — rayd перезапускает процесс Xray, если счётчик
   снятого растёт ещё два опроса (рвёт всех на процессе)?
5. Опрос раз в 15 с даёт до ~2,5 ГБ перерасхода на 1 Гбит/с. Хватит или 5 с?
6. `up + down` (предложение) или только `down`?
7. Для сессии Niko: что нынешний Niko делает с `profiles: []`? Код Niko здесь не смотрелся.

## 9. Версии

- raycontrol v0.21.0: всё из §7; только вместе с niko-server v0.15.0 и новым коммитом форка Xray.
- niko-server v0.15.0: `traffic` и разрыв соединений; IPC и конфиги прежние, со старым rayd — как v0.14.0.
- Форк Xray: коммит после `a4a3dff` с разрывом соединений.
- Niko: первый релиз после 1.40 с `traffic` (номер — за сессией Niko). Старый Niko работает, но без «N из M» и при
  исчерпании видит пустой список профилей.
- Нода до v0.21.0: поля `traffic` нет, лимит не применяется.
