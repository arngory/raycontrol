# 10. Нода с нуля: Debian 13 (trixie) + Cloudflare

От чистого VPS до ссылки, которую можно отдать клиенту. Команды выполняются от root на сервере, если не сказано
иначе. Пример: адрес `203.0.113.7`, домен `example.com`. Короткий список всех команд —
в [шпаргалке](cheatsheet.md).

> **Статус.** Установка, все сервисы и клиент Niko проверены в CI, но не в настоящей сети:
> - тест установки — в контейнерах с systemd (Debian 12/13, Ubuntu 24.04, Rocky 9/10), с замером из второго
>   контейнера;
> - туннели — на настоящих Xray и niko-server;
> - сертификаты — на Pebble (тестовый CA Let's Encrypt), Cloudflare — на имитации его API;
> - interop с клиентом Niko.
>
> На настоящем VPS с настоящими Let's Encrypt, Cloudflare и мобильной сетью первая проверка ещё впереди (§14).
> Пока она не пройдена, ставьте ноду для проверки, а не для людей, которые на неё рассчитывают.

## 0. Требования к VPS

| | Минимум | Рекомендуется |
|---|---|---|
| Процессор | 1 vCPU | 2 vCPU и больше, если Hysteria2 нужен быстрее ~250 Мбит/с |
| Память | 1 ГиБ | 2 ГиБ |
| Диск | 10 ГБ | 20 ГБ |
| Виртуализация | KVM (или другая с собственным ядром) | — |
| Архитектура | amd64 или arm64 | — |
| Сеть | статический публичный IPv4; входящий UDP не режется | плюс IPv6 |
| Система | Debian 13 | — |

**Откуда цифры.** Замер на облачном vCPU Xeon 2,1 ГГц, весь стек: REALITY, hy2-masq, hy2-obfs, naive, DoH, Yggdrasil,
dnstt, masterdns, API.

- **Память.** Процессы ноды в простое — около 225 МиБ, вместе с `rayspa` — около 240 МиБ. Под нагрузкой — на
  десяток МиБ больше. Debian 13 сам берёт 150–250 МиБ.
  - Отсюда 1 ГиБ — с запасом, а на 512 МиБ хватит только части сервисов (REALITY и DNS-туннели).
  - Меньше 900 МиБ — `rayctl install` предупредит.
- **Процессор** (CPU ноды на 1 ГиБ скачанного):
  - REALITY (через фронт) — около 3,5 с, то есть одно ядро тянет порядка 2 Гбит/с;
  - Hysteria2 (hy2-obfs через фронт) — около 32 с, то есть ~250–300 Мбит/с на ядро.
  - UDP-сервисы упираются в процессор раньше всего. Замер шёл на loopback, цифры ориентировочные.
- **Диск.** Релиз — около 135 МБ: бинарники и база AS. `rayctl update` держит прежнюю версию для отката, так что
  вместе около 300 МБ, плюс журналы systemd. База ноды — единицы МБ.

**Что ещё проверить у провайдера.**

- **Виртуализация.** Не OpenVZ и не LXC: периметру нужны своё ядро и nftables с NAT, наборами и NFLOG. Это
  проверяет `rayctl install`, но лучше знать заранее.
- **UDP.** Входящий UDP на 443 и 53 не режется — без него не работают Hysteria2, naive по QUIC, DoH3 и
  DNS-туннели. Некоторые провайдеры закрывают входящий UDP 53.
- **Трафик.** Квота в месяц и скорость порта: замеры канала клиента тоже тратят трафик, до 1 ГиБ на устройство в
  сутки.
- **Файрвол провайдера.** Security group, cloud firewall. Если он есть, его надо открыть (§5): своих правил
  провайдера нода не видит.

## 1. Что нужно ещё

- Вход на VPS по SSH-ключу. Адрес, с которого вы ставите ноду, станет аварийным доступом к SSH (`-admin`).
  Остальное после установки закрыто.
- Домен, делегированный в Cloudflare (у регистратора NS указывают на Cloudflare).
  - Поддомены ноды — случайные метки этого домена.
  - Проксирование Cloudflare (оранжевое облако) им не включается.
- API-токен Cloudflare: *My Profile → API Tokens → Create Token → шаблон «Edit zone DNS»*.
  - Права **Zone · DNS · Edit** и **Zone · Zone · Read**, Zone Resources — только эта зона.
  - Глобальный API-ключ не нужен и не подходит.

Без Cloudflare тоже можно. Записи тогда заводятся вручную (`rayctl dns` покажет, какие), а сертификат выпускается через
HTTP-01 в коротком окне на TCP 80.

## 2. Система

```bash
apt update && apt full-upgrade -y
```

```bash
apt install -y unattended-upgrades systemd-timesyncd
```

```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
```

Там должно быть `APT::Periodic::Unattended-Upgrade "1";`. Если нет — `dpkg-reconfigure unattended-upgrades` и ответ
«Yes». Удалённые уязвимости сетевого стека закрывает только новое ядро. Нода сокращает то, что до него доходит
(решение R4-9), но не заменяет обновления.

Часы должны идти верно: по ним считаются слоты SPA, срок приглашений и сертификаты.

```bash
timedatectl
```

Нужно `System clock synchronized: yes`. Если нет — подождите минуту после установки `systemd-timesyncd` или
проверьте, не закрыт ли у провайдера исходящий UDP 123.

Если после обновления появился `/var/run/reboot-required`:

```bash
reboot
```

На порту 443 ничего не должно слушать (nginx, apache из образа провайдера). Проверка:

```bash
ss -ltnup 'sport = :443'
```

## 3. Data plane

Ничего ставить не нужно.

- Релиз raycontrol несёт:
  - Xray, собранный из закреплённого коммита нашего форка;
  - niko-server, сверенный с хешами из `deploy/versions.env`.
- Всё это под одной подписью с `rayd`, `rayspa` и `rayctl`. Bootstrap проверяет подпись.
- `rayctl install` кладёт оба бинарника в `/usr/local/libexec/raycontrol/`. Чужие Xray и niko-server в
  `/usr/local/bin` (если они есть для другого софта) не трогаются.
- Состав конкретного релиза — файл `VERSIONS` в архиве.

## 4. Токен Cloudflare в файл

Не в командную строку: она попадает в историю и в `ps`.

```bash
umask 077; read -rsp 'Cloudflare token: ' T; printf '%s\n' "$T" > /root/cf.token; unset T; echo
```

## 5. Установка

```bash
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
```

```bash
less bootstrap.sh
```

```bash
bash bootstrap.sh -host 203.0.113.7 -domain example.com -cloudflare-token-file /root/cf.token -services reality,dnstt,masterdns
```

`-services` — что поднять сразу:
- `reality` — с доменом он ставится и без флага;
- `dnstt` и `masterdns` — DNS-туннели, резервный канал;
- `none` — ничего.

Остальные сервисы — §8.

Что делает установка:
1. Bootstrap ставит недостающее (curl, openssl, nftables, polkit), проверяет подпись релиза и запускает
   `rayctl install`.
2. `rayctl install` проверяет хост. Он предупреждает:
   - о неперезагруженном ядре и выключенных автообновлениях;
   - о несинхронизированных часах;
   - о памяти меньше 900 МиБ.
3. Затем он:
   - раскладывает data plane и поднимает периметр;
   - сохраняет токен в базе ноды;
   - создаёт в зоне `*.example.com A 203.0.113.7` и NS-делегирование туннелей;
   - заводит сервисы и запускает их.
4. В конце печатается **аварийный пакет устройства** (только SSH). Сохраните его офлайн, второй раз он не
   покажется.

Файл токена больше не нужен:

```bash
shred -u /root/cf.token
```

**Файрвол провайдера.** Последней строкой `rayctl install` (и каждый `rayctl apply`) печатает, что открыть в
файрволе провайдера перед хостом. Например: `tcp 22, tcp+udp 443, udp 53, tcp+udp 31012-31523, tcp+udp 46236`.

- Диапазон SPA и порт подписки у каждой ноды свои, случайные, поэтому список берите из вывода.
- TCP 80 в списке есть только без Cloudflare: он нужен окну HTTP-01.
- Если у провайдера файрвола нет — ничего делать не нужно. Можно и открыть у провайдера весь входящий трафик:
  периметр ноды сам закрывает всё, кроме SPA и открытого по SPA.

Проверка:

```bash
rayctl status
```

```bash
rayctl dns
```

`rayctl dns` показывает провайдера, нужные записи и проблемы. Проблема — это, например, чужая запись под тем же
именем или включённое проксирование: такие имена нода не трогает, исправьте их в панели Cloudflare.

> Проверить ветку до релиза. Положите в один каталог на сервере:
> - `rayd`, `rayspa`, `rayctl` — `go build ./cmd/...`;
> - `niko-server` — `scripts/niko-server.sh amd64 <каталог>/niko-server`;
> - `xray` — сборка из коммита в `deploy/versions.env`: `CGO_ENABLED=0 go build -trimpath -o xray ./main` в клоне
>   форка.
>
> Затем запустите bootstrap с `RAYCONTROL_LOCAL_DIR=<каталог>`. Подпись в этом режиме не проверяется: это только для
> проверки, не для рабочей ноды.

## 6. REALITY

Установка уже создала его.

- REALITY ворует TLS у собственного сайта-приманки ноды на случайном поддомене (self-steal).
- Сертификат `*.example.com` выпускается через DNS-01 примерно за минуту:

```bash
journalctl -u rayd -f
```

Ждите строку `certificate stored` (выйти — Ctrl-C). После этого rayd отрисует сайт и REALITY, и они запустятся:

```bash
systemctl status niko-site niko-reality
```

- Сайт отвечает на всё пустым `404` (решение R4-8).
- Порт 443 закрыт SPA: без доступа извне его не видно вовсе.

Если REALITY при установке не создавался (`-services none`):

```bash
rayctl service add reality reality
```

```bash
rayctl apply
```

## 7. DNS-туннели

Резервный канал через DNS-резолверы, когда закрыто всё остальное. С `-services …,dnstt,masterdns` они уже подняты.
Проверка:

```bash
rayctl dns
```

- Нода сама заводит имя NS-сервера и NS-делегирование зон туннелей.
- UDP 53 открыт всем: резолверы не умеют SPA.
- Стаб systemd-resolved на 53 нода выключает сама.

Добавить позже:

```bash
rayctl service add dnstt dns
```

```bash
rayctl apply
```

## 8. Остальные сервисы

Полный набор, как для проверки клиента (§14):

```bash
rayctl service add hy2-masq hy2-masq
```

```bash
rayctl service add hy2-obfs hy2-obfs
```

```bash
rayctl service add naive naive
```

```bash
rayctl service add doh doh
```

```bash
rayctl service add yggdrasil ygg
```

```bash
rayctl service add api api
```

```bash
rayctl apply
```

| Сервис | Порт | Что ему нужно |
|---|---|---|
| hy2-masq, hy2-obfs | UDP 443 за фронтом | hy2-masq — сертификат сайта, hy2-obfs — свой самоподписанный |
| naive | TCP 443 и UDP 443 (QUIC) | сертификат сайта |
| doh | TCP 443 и UDP 443 (DoH3) | сертификат сайта |
| yggdrasil | TCP 443 за фронтом | сертификат сайта; трафик идёт в `inner` |
| api | свой TCP-порт под SPA | — |

- Сертификат сайта с Cloudflare — один wildcard на все имена. Без Cloudflare каждое имя нужно завести записью A
  вручную (`rayctl dns`).
- Свой сертификат вместо ACME: `rayctl service cert site -chain F -key F`.
- Публичные пиры Yggdrasil (по умолчанию нет):

  ```bash
  rayctl service set ygg peers=tls://host:port,quic://203.0.113.9:port
  ```

  ```bash
  rayctl apply
  ```

  Пиры — с [publicpeers.neilalexander.dev](https://publicpeers.neilalexander.dev/), близко к VPS; `quic://` —
  только по IP.
- Сводка от клиентов — необязательная метрика, по умолчанию выключена: `rayctl summary on` (решение R4-21).

## 9. Пользователь, устройство и подписка для клиента

Клиенту передаётся **пакет устройства** `rcdev1:…`.

- В нём параметры SPA, ключ устройства, ключи подписи ноды и адрес подписки с закреплённым ключом.
- Ссылки на протоколы клиент получает сам, из подписанной подписки.
- При ротации ключей и имён (UUID раз в 30 дней, REALITY раз в 90) новые приходят туда же заранее.

```bash
rayctl user add -services reality,dns,mdns -expires 90d
```

Команда выдаст непрозрачное имя вида `u-k3f9-x2qa`. Все сервисы из §8:
`-services reality,hy2-masq,hy2-obfs,naive,doh,dns,mdns,ygg`; поменять потом — `rayctl user services NAME a,b`.

```bash
rayctl device add u-k3f9-x2qa phone -o /root/phone.bundle
```

- Пакет показывается один раз; `-o` пишет его в файл с правами 0600.
- Передайте его по доверенному каналу: лично или в мессенджере с E2E и исчезающими сообщениями, не почтой и не
  в облачный документ. Пакет — это и доступ, и ключ: у кого он есть, тот подключается.
- В клиенте Niko: импорт устройства, вставить пакет целиком или открыть файл.
- Вместо пакета можно дать приглашение: `rayctl device invite u-k3f9-x2qa phone` (нужен `api`, §8). Клиент сам
  зарегистрирует устройство, ключ останется только на телефоне.
- После передачи:

```bash
shred -u /root/phone.bundle
```

Одно устройство — один пакет: телефон и ноутбук получают разные (`device add … laptop`), так их можно отзывать
по отдельности. Отзыв:

```bash
rayctl device list u-k3f9-x2qa
```

```bash
rayctl device revoke <ID>
```

Отключить пользователя целиком:

```bash
rayctl user disable u-k3f9-x2qa
```

## 10. Проверка снаружи

С любой другой машины, где есть `rayctl` (тот же бинарник из релиза, он статический), по пакету проверяется то же, что
делает клиент:
- SPA;
- подписка с проверкой закреплённого ключа и обеих подписей;
- с `-channel` — ещё и канал: TCP в обе стороны и эхо UDP.

```bash
rayctl probe -channel @phone.bundle
```

С `-redact` вывод можно показать кому угодно: адреса и имена в нём заменены.

## 11. Работает ли нода и что делать, если нет

```bash
rayctl status
```

```bash
systemctl --no-pager list-units 'niko-*' rayd.service rayspa.service
```

```bash
journalctl -u rayd -p warning --since -1h
```

Очищенный отчёт для issue — `rayctl report -o report.txt` ([09-observability.md](09-observability.md)).

| Признак | Что проверить |
|---|---|
| Нет строки `certificate stored` | `journalctl -u rayd \| grep -i certif`. С Cloudflare — права токена (§1) и `rayctl dns`. Без него — записи A и TCP 80 у провайдера. Неудачи нода повторяет с растущей паузой: не перезапускайте rayd ради этого, лимиты Let's Encrypt — 5 неудач в час на имя |
| `rayctl probe` не проходит SPA | часы (`timedatectl`); диапазон SPA в файрволе провайдера (§5); сеть клиента режет UDP — `rayctl probe -carrier tcp` |
| Подписка есть, UDP-профили не работают | `rayctl probe -channel`: потери эха UDP — провайдер или сеть клиента режет UDP |
| `niko-*` перезапускается по кругу | `journalctl -u niko-<сервис> -n 50`; порт 443 занят чужим процессом (§2) |
| Ничего не открывается после `nft flush ruleset` или перезапуска firewalld | периметр rayspa восстанавливает сам за секунды; если нет — `systemctl restart rayspa` |

## 12. Резервная копия

В базе ноды все её ключи, поэтому копия шифруется парольной фразой (не короче 12 символов, спрашивается дважды) и
пишется с правами 0600. Держите её вне ноды, а фразу — отдельно от файла.

```bash
rayctl backup -o /root/node-$(date +%F).rcbak
scp root@NODE:/root/node-*.rcbak .      # с вашей машины; на ноде потом rm
```

Вернуть на той же ноде — `rayctl restore -i FILE`. Перенести на новый сервер: там шаги 2–5 с новым адресом, затем

```bash
rayctl restore -i node.rcbak -host NEW_IP
```

После переезда:
- Записи в Cloudflare переедут на новый адрес сами.
- Устройствам нужны новые пакеты (`rayctl device add`): в старых прежний адрес.
- Пользователи, их учётные данные и ключи сервисов остаются прежними.
- Старый сервер снимайте с `-keep-dns`, иначе он удалит записи, которые уже указывают на новый.
- До этого не запускайте обе ноды сразу: каждая раз в час правит записи под свой адрес.

```bash
rayctl uninstall -keep-dns     # на старом сервере
```

## 13. Администрирование со своей машины

На ноде включите удалённый API и сделайте приглашение для своего устройства:

```bash
rayctl service add api api && rayctl apply
rayctl device invite <ваш-пользователь> laptop -role admin
```

На своей машине (тот же `rayctl`, Linux или macOS) — регистрация по приглашению и дальше любые команды через API:

```bash
rayctl remote enroll -o laptop.rcdev 'rcinv1:…'
rayctl -remote laptop.rcdev status
rayctl -remote laptop.rcdev device invite alice phone      # приглашение для телефона alice — уже без SSH
```

- Файл `laptop.rcdev` — ключ устройства: права 0600, храните как SSH-ключ.
- Приглашение одноразовое и живёт сутки (`-ttl`).
- Только на ноде, не через API: `apply`, `update`, `backup`, `uninstall` и `service cert`.

## 14. Проверка клиента Niko на настоящей сети

Чек-лист клиента — `docs/server/VPS-CHECK.md` в `arngory/niko`: сервисы из §8, девять проверок на телефоне (мобильная
сеть и Wi-Fi). Подробности для сервера — [handoff/niko-r17-reply.md](handoff/niko-r17-reply.md) §1. Коротко:

- **Закрыть порт для адреса телефона** (переключение профилей). Своя таблица перед периметром:

  ```bash
  nft add table inet rc-test
  ```

  ```bash
  nft add chain inet rc-test block '{ type filter hook input priority -20; policy accept; }'
  ```

  ```bash
  nft add rule inet rc-test block ip saddr 198.51.100.7 tcp dport 443 drop
  ```

  - Адрес телефона — поле `address` в «Проверить канал» клиента или `nft list set inet raycontrol allow4`.
  - Порт закрывает сразу группу сервисов за фронтом:
    - TCP 443 — REALITY, naive, DoH, Yggdrasil;
    - UDP 443 — Hysteria2, naive QUIC, DoH3;
    - UDP 53 — DNS-туннели.
  - Снять: `nft delete table inet rc-test`.
- **Публичные пиры Yggdrasil** — §8.
- **Эталонный замер.** Телефон, добавленный по приглашению, пакета не имеет. Для замера заведите отдельное
  устройство:

  ```bash
  rayctl device add <user> probe -o /root/probe.bundle
  ```

  С машины в той же сети, что телефон:

  ```bash
  rayctl probe -channel -redact @probe.bundle
  ```

  После проверки — `rayctl device revoke <ID>`.

## 15. Дальше

- `rayctl update -check` — есть ли новый релиз.
- `rayctl update` — поставить его. Подпись проверяется, при сбое прежняя версия возвращается сама.
  `rayctl update -rollback` — вернуть её вручную.
- `rayctl service rotate reality` — новые ключи и имя REALITY раньше срока; с `-now` — сразу.
- `rayctl service set site answer=silent` — сайт вместо 404 молчит до таймаута; `rayctl apply` после.
- `rayctl metrics -o FILE` — счётчики для node_exporter (textfile collector) по своему таймеру: только числа.
- `rayctl uninstall` — убрать всё, включая записи raycontrol в Cloudflare; система вернётся к снимку до установки.
  Сначала `rayctl backup`, если ноду может понадобиться вернуть.
