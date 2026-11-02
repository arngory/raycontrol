# 10. Нода с нуля: Debian 13 (trixie) + Cloudflare

От чистого VPS до ссылки, которую можно отдать клиенту. Команды выполняются от root на сервере, если не сказано
иначе. Пример: адрес `203.0.113.7`, домен `example.com`. Короткий список всех команд —
в [шпаргалке](cheatsheet.md).

## 0. Что нужно

- VPS на Debian 13 с публичным IPv4, вход по SSH-ключу. Адрес, с которого вы ставите ноду, станет аварийным доступом к
  SSH (`-admin`); остальное после установки закрыто.
- Домен, делегированный в Cloudflare (у регистратора NS указывают на Cloudflare). Поддомены ноды — случайные
  метки этого домена, проксирование Cloudflare (оранжевое облако) им не включается.
- API-токен Cloudflare: *My Profile → API Tokens → Create Token → шаблон «Edit zone DNS»*, права
  **Zone · DNS · Edit** и **Zone · Zone · Read**, Zone Resources — только эта зона. Глобальный API-ключ не нужен и не
  подходит.

Без Cloudflare тоже можно: записи тогда заводятся вручную (`rayctl dns` покажет, какие), а сертификат выпускается
через HTTP-01 в коротком окне на TCP 80.

## 1. Система

```bash
apt update && apt full-upgrade -y
```

```bash
apt install -y unattended-upgrades
```

```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
```

Там должно быть `APT::Periodic::Unattended-Upgrade "1";`. Если нет — `dpkg-reconfigure unattended-upgrades` и ответ
«Yes». Удалённые уязвимости сетевого стека закрывает только новое ядро; нода сокращает то, что до него доходит
(решение R4-9), но не заменяет обновления. Если после обновления появился `/var/run/reboot-required`:

```bash
reboot
```

## 2. Data plane

Ничего ставить не нужно. Релиз raycontrol несёт Xray, собранный из закреплённого коммита нашего форка, и
niko-server, сверенный с хешами из `deploy/versions.env`. Всё это под одной подписью с `rayd`, `rayspa` и `rayctl`.
Bootstrap проверяет подпись, а `rayctl install` кладёт оба бинарника в `/usr/local/libexec/raycontrol/`. Чужие Xray и
niko-server в `/usr/local/bin` (если они есть для другого софта) не трогаются. Состав конкретного релиза — файл
`VERSIONS` в архиве.

## 3. Токен Cloudflare в файл

Не в командную строку: она попадает в историю и в `ps`.

```bash
umask 077; read -rsp 'Cloudflare token: ' T; printf '%s\n' "$T" > /root/cf.token; unset T; echo
```

## 4. Установка

```bash
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
```

```bash
less bootstrap.sh
```

```bash
bash bootstrap.sh -host 203.0.113.7 -domain example.com -cloudflare-token-file /root/cf.token -services reality,dnstt,masterdns
```

`-services` — что поднять сразу: `reality` (с доменом он ставится и без флага), `dnstt` и `masterdns` (DNS-туннели,
резервный канал), `none` — ничего.

Bootstrap ставит недостающее (curl, openssl, nftables, polkit), проверяет подпись релиза и запускает `rayctl install`.
Тот проверяет хост и предупреждает о неперезагруженном ядре и выключенных автообновлениях. Затем он раскладывает
data plane, поднимает периметр, сохраняет токен в базе ноды и создаёт в зоне `*.example.com A 203.0.113.7`
и NS-делегирование туннелей. После этого заводит сервисы и запускает их. В конце печатается
**аварийный пакет устройства** (только SSH): сохраните его офлайн, второй раз он не покажется. Файл токена больше
не нужен:

```bash
shred -u /root/cf.token
```

Проверка:

```bash
rayctl status
```

```bash
rayctl dns
```

`rayctl dns` показывает провайдера, нужные записи и проблемы. Проблема — это, например, чужая запись под тем же
именем или включённое проксирование: такие имена нода не трогает, исправьте их в панели Cloudflare.

> До выхода релиза v0.2.0 (в нём data plane, Cloudflare, ротация REALITY и всё из R4) bootstrap ставит предыдущий
> релиз. Чтобы проверить ветку раньше, положите в один каталог на сервере `rayd`, `rayspa`, `rayctl`
> (`go build ./cmd/...`), `niko-server` (`scripts/niko-server.sh amd64 <каталог>/niko-server`) и `xray` (сборка из
> коммита в `deploy/versions.env`: `CGO_ENABLED=0 go build -trimpath -o xray ./main` в клоне форка). Затем запустите
> bootstrap с `RAYCONTROL_LOCAL_DIR=<каталог>`. Подпись в этом режиме не проверяется: это только для проверки, не
> для рабочей ноды.

## 5. REALITY

Установка уже создала его. REALITY ворует TLS у собственного сайта-приманки ноды на случайном поддомене (self-steal).
Сертификат `*.example.com` выпускается через DNS-01 примерно за минуту:

```bash
journalctl -u rayd -f
```

Ждите строку `certificate stored` (выйти — Ctrl-C). После этого rayd отрисует сайт и REALITY, и они запустятся:

```bash
systemctl status niko-site niko-reality
```

Сайт отвечает на всё пустым `404` (решение R4-8). Порт 443 закрыт SPA: без доступа извне его не видно вовсе. Если
REALITY при установке не создавался (`-services none`):

```bash
rayctl service add reality reality
```

```bash
rayctl apply
```

## 6. DNS-туннели

Резервный канал через DNS-резолверы, когда закрыто всё остальное. С `-services …,dnstt,masterdns` они уже подняты;
проверка:

```bash
rayctl dns
```

Нода сама заводит имя NS-сервера и NS-делегирование зон туннелей. UDP 53 открыт всем: резолверы не умеют SPA.
Добавить позже:

```bash
rayctl service add dnstt dns
```

```bash
rayctl apply
```

## 7. Пользователь, устройство и подписка для клиента

Клиенту передаётся **пакет устройства** `rcdev1:…`. В нём параметры SPA, ключ устройства, ключи подписи ноды и адрес
подписки с закреплённым ключом. Ссылки на протоколы клиент получает сам, из подписанной подписки; при ротации
ключей и имён (UUID раз в 30 дней, REALITY раз в 90) они приходят туда же заранее.

```bash
rayctl user add -services reality,dns,mdns -expires 90d
```

Команда выдаст непрозрачное имя вида `u-k3f9-x2qa`.

```bash
rayctl device add u-k3f9-x2qa phone -o /root/phone.bundle
```

- Пакет показывается один раз; `-o` пишет его в файл с правами 0600.
- Передайте его по доверенному каналу: лично или в мессенджере с E2E и исчезающими сообщениями, не почтой и не
  в облачный документ. Пакет — это и доступ, и ключ: у кого он есть, тот подключается.
- В клиенте Niko: импорт устройства, вставить пакет целиком или открыть файл.
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

## 8. Проверка снаружи

С любой другой машины, где есть `rayctl` (тот же бинарник), по пакету проверяется то же, что делает клиент: SPA, потом
подписка с проверкой закреплённого ключа и обеих подписей.

```bash
rayctl probe @phone.bundle
```

С `-redact` вывод можно показать кому угодно: адреса и имена в нём заменены.

## 9. Дальше

- `rayctl report -o report.txt` — очищенный отчёт для issue; перед отправкой прочитайте
  ([09-observability.md](09-observability.md)).
- `rayctl service rotate reality` — новые ключи и имя REALITY раньше срока; с `-now` — сразу.
- `rayctl service set site answer=silent` — сайт вместо 404 молчит до таймаута; `rayctl apply` после.
- `rayctl uninstall` — убрать всё, включая записи raycontrol в Cloudflare; система вернётся к снимку до установки.
