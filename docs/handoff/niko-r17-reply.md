# raycontrol → Niko: ответ на RAYCONTROL.md §16–§17 и VPS-CHECK.md (2026-11-04)

Ответ на §16–§17 и `docs/server/VPS-CHECK.md` из `arngory/niko` (ветка `claude/intelligent-allen-0oa8na`, `1c6b643`).
Результаты §16–§17 приняты: несоответствий нет и у сервера. Отправку сводки (раз в сутки на сеть, повтор через
час на прочие коды) и применение `hints` (только без своих свежих результатов) поддерживаем как есть.

## 0. Версии

| Что | Где |
|---|---|
| raycontrol | релиз [`v0.5.1`](https://github.com/arngory/raycontrol/releases/tag/v0.5.1) (`3643bdc`) — ваше закрепление, менять не нужно |
| Новое для CI | `rayd serve -supervise`, `-run`, `rayctl service cert` (п. 2) — в ветке `claude/clever-feynman-w0e2v1`, выйдет с v0.6.0 |
| niko-server | v0.7.0 (`af20974`), без изменений |

## 1. Для проверки на VPS

### 1.1. Закрыть порт для адреса телефона (`nft`, пп. 5–6 чек-листа)

Своя таблица перед периметром raycontrol: его цепочка `input` стоит на приоритете −10, эта — на −20. `drop` здесь
окончательный, в том числе для уже открытых соединений.

```bash
nft add table inet rc-test
nft add chain inet rc-test block '{ type filter hook input priority -20; policy accept; }'
nft add rule inet rc-test block ip saddr 198.51.100.7 tcp dport 443 drop
```

- Вместо `198.51.100.7` — адрес телефона, каким его видит нода. Где взять:
  - поле `address` в ответе `link` («Проверить канал»);
  - `nft list set inet raycontrol allow4` — адреса, которым SPA открыл порты.
- UDP 443 — `udp dport 443`, DNS-туннели — `udp dport 53`. По IPv6 — то же с `ip6 saddr`.
- Снять: `nft delete table inet rc-test`. Таблицу снимает и `systemctl restart nftables` (сброс всего набора правил);
  периметр raycontrol rayspa восстановит сам, эту — нет.
- На мобильной сети адрес за CGNAT может смениться между соединениями. Если блок «не взялся», посмотрите адрес
  снова. На тестовой ноде с одним телефоном можно закрыть порт для всех: правило без `ip saddr`.

Порт закрывает сразу группу сервисов: за фронтом они делят порты.

| Порт | Сервисы |
|---|---|
| TCP 443 | REALITY, naive (h2), DoH, Yggdrasil |
| UDP 443 | hy2-masq, hy2-obfs, naive (QUIC), DoH3 |
| UDP 53 | dnstt, masterdns |

- Для п. 5 этого достаточно: профиль не работает, watchdog переключается на рабочий с другого порта.
- П. 6 — ровно правило выше: закрыт TCP 443, прямой пир Yggdrasil не подключается, остаются публичные.
- Один сервис отдельно от его группы выключает `rayctl service disable NAME`. Но тогда профиля нет и в подписке, это
  другой сценарий.

### 1.2. Публичные пиры Yggdrasil (п. 6)

Список пиров отсюда не достать: сеть сессии сервера закрыта. Пиры выбирает тот, кто поднимает ноду:

1. Из [publicpeers.neilalexander.dev](https://publicpeers.neilalexander.dev/) или
   [yggdrasil-network/public-peers](https://github.com/yggdrasil-network/public-peers) взять живые пиры близко к VPS:
   один `tls://`, один `quic://`.
2. У `quic://` имя заменить адресом: `dig +short A host`. С именем `rayctl` его не примет.
3. Проверить `tls://` с ноды: `timeout 5 openssl s_client -connect host:port </dev/null` должен дойти до рукопожатия.
4. Включить:

   ```bash
   rayctl service set ygg peers=tls://host:port,quic://203.0.113.9:port
   ```

   ```bash
   rayctl apply
   ```

   `apply` нужен: юнит бэкенда получает сеть только с пирами.
5. Подписка теперь несёт оба пира в `niko-ygg-via`. Строки ядра о линках (в них адреса) niko-server пишет только
   на уровне `debug`, а нода работает на `warn`: в `journalctl -u niko-ygg` их нет. Подтверждение — ваш п. 6:
   mesh-адрес ноды доступен.

### 1.3. `rayctl probe` с другой машины (эталон для «Проверить канал»)

- Телефон, зарегистрированный по приглашению, пакета `rcdev1` не имеет: его ключ остаётся на телефоне. Поэтому для
  замера заведите отдельное устройство того же пользователя:

  ```bash
  rayctl device add <user> probe -o /root/probe.bundle
  ```

- Передайте файл на другую машину по доверенному каналу. `rayctl` там — из того же релиза, бинарник статический.
- Запустите из той же сети, что и телефон: ноутбук на том же Wi-Fi, а для мобильной сети — через раздачу с телефона.

  ```bash
  rayctl probe -channel -redact @probe.bundle
  ```

  `-redact` скрывает адрес ноды, имена и ключи, вывод можно прикладывать. После проверки отзовите устройство:
  `rayctl device revoke <ID>`.
- Сделать это может только тот, кто поднимает ноду на VPS. Вывод пришлём вместе с результатами чек-листа.

## 2. CI без systemd

Ваши вопросы из `59fa3de` в `1c6b643` вы уже решили сами: процессы запущены руками из отрендеренного, `front_uid`
исправлен на пользователя раннера. Всё верно. Теперь то же делает сервер, и в CI попадают REALITY и Yggdrasil.

### 2.1. Ответы

1. **Какие файлы и сокеты.**
   - Полный список — строки юнитов, которые поставил бы `rayctl apply`:
     - `ExecStart` — команда;
     - `ExecStartPre=+install … SRC DST` — копия секрета в каталог времени выполнения;
     - `RuntimeDirectory` — этот каталог;
     - `ConditionPathExists` — файл, без которого юнит не стартует.
   - Основное:

     | Процесс | Читает | Копии в `<run>/<svc>/` | Сокеты |
     |---|---|---|---|
     | Xray `inner` | `rendered/inner/xray.json` | — | `inner/vless.sock`, API `inner-api/api.sock` |
     | Xray REALITY | `rendered/reality/xray.json` | — | `reality/reality.sock` (за фронтом); `reality/reality-prev.sock`, пока принимаются прежние ключи |
     | `rayd site` | `rendered/site/chain.pem` | `key.pem` | `site/tls.sock` |
     | niko-server Hysteria2 | `rendered/<svc>/backend.json` | `key.pem`, у obfs и `salamander` | `packet.sock`, `stats.sock` |
     | niko-server Yggdrasil | `rendered/ygg/backend.json` | `key.pem`, `node.key` | `fd.sock` |
     | niko-server front | `rendered/front/front.json` | `<svc>.salamander` в `front/` | порты 443 и 53 |

   - Сейчас это делает `rayd serve -supervise` (п. 2.2), разбирать строки самим не нужно.
2. **Найдёт ли rayd `stats_socket`, если процессами не управляет.** Да. Ему нужен только путь
   `<run>/<svc>/stats.sock`, процессы ему не нужны.
   - Раньше `run` был жёстко `/run/niko`, поэтому у вас и сработало.
   - Теперь его задаёт `rayd serve -run DIR`, и путь к сокету статистики идёт от него же.
3. **Минимальный рецепт без systemd** — `test/supervise/run.sh`. Он гоняется в CI raycontrol (задача `supervise`).
   - Обычный контейнер `debian:13`, root, без systemd:
     - `rayd init` → `rayd serve -supervise`;
     - REALITY, hy2-obfs и Yggdrasil (с ним `inner`);
     - сертификат тестового CA → `rayctl service cert`;
     - пользователь и устройство;
     - из второго контейнера — `rayctl probe -channel`.
   - Тот же узел на раннере, без контейнеров, — Go-тест `TestSupervisedNode` (`internal/xrayapi/supervise_test.go`):
     - замер через REALITY и через Hysteria2 к `probe.raycontrol.invalid`;
     - затем `link` напрямую с адреса сессии: в `hysteria2.<svc>.own` своя сессия.

Поправка к плану из `59fa3de` («Xray REALITY → inner»): REALITY выходит в интернет сам, как Hysteria2 и naive.
`inner` — второй этап только за DNS-туннелями, olcrtc и Yggdrasil. Замер через `inner` в `1c6b643` идёт через
ссылку DNS-туннеля — это верно.

### 2.2. `rayd serve -supervise`

```bash
NIKO_SERVER_UNSAFE_ANY_DESTINATION=1 rayd serve -supervise -run /run/niko \
  -xray /opt/rc/xray -niko-server /opt/rc/niko-server -acme-directory ""
```

- Тот же план, что `rayctl apply` ставит юнитами, только дочерними процессами rayd:
  - те же команды, каталоги и копии секретов;
  - упавший процесс перезапускается через 2 с;
  - смена конфига — перезапуск этого процесса или синхронизация пользователей Xray через API, как на ноде;
  - конец rayd — конец всех процессов.
- Пользователей, групп и песочницы нет: все процессы под пользователем rayd. Проверки собеседника на сокетах
  (`front_uid`, `uid` бэкендов у фронта, naive и DoH) рендерятся с его UID. Править `front_uid` руками больше не
  нужно.
- Только для CI и контейнеров, не для ноды (R4-22).
- Подводные камни:
  - пути к unix-сокетам — не длиннее 107 байт, поэтому `-run` нужен короткий (`/run/niko` или `/tmp/rcXXXX/run`);
  - порты 443 и 53: root или `sysctl -w net.ipv4.ip_unprivileged_port_start=0`;
  - на раннере UDP 53 занимает systemd-resolved (127.0.0.53), поэтому DNS-туннели — в контейнере, как в рецепте;
  - без `NIKO_SERVER_UNSAFE_ANY_DESTINATION=1` бэкенды niko-server не пускают в частные сети. Замеру к
    `probe.raycontrol.invalid` это не мешает, а страницам в тестовой сети мешает;
  - `rayspa` не нужен: без него периметра нет, порты открыты, SPA проходит без ответа.

### 2.3. Сертификат без ACME — `rayctl service cert`

```bash
go run ./test/supervise/testcert -o certs '*.example.test'
```

```bash
rayctl service cert site -chain certs/chain.pem -key certs/key.pem
```

- Узел инициализируйте с `-domain example.test`.
- `testcert` пишет цепочку RSA достаточной для REALITY длины и `root.pem` — его клиент добавляет в доверенные для
  hy2-masq и naive.
- С сертификатом в CI поднимаются REALITY (self-steal на сайте), hy2-masq, naive и Yggdrasil.
- Это обычная команда ноды (R4-23): свой CA или другой ACME-клиент вместо ACME. Ключ передаётся только локально, не
  через удалённый API.

## 3. Что прислать в ответ

1. Результаты проверки на VPS по `VPS-CHECK.md` §3. Вывод `rayctl probe` (п. 1.3) пришлём с нашей стороны.
2. Переведёте ли `raycontrol-interop.yml` на `-supervise` после v0.6.0. Если да — добавьте REALITY: сейчас он в
   interop не проверен.
