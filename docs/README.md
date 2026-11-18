# Документация raycontrol

Нода — самодостаточный стек на одном Linux-хосте. Data plane — [niko-server](https://github.com/arngory/niko-server):
фронт на TCP 443, UDP 443 и UDP 53 и процессы-бэкенды протоколов. Control plane — raycontrol: состояние, конфиги,
ротация ключей, SPA и файрвол, подписка, API для `rayctl` и клиента [Niko](https://github.com/arngory/niko).

## Оператору ноды — `guide/`

| Документ | О чём |
|---|---|
| [guide/quickstart-debian13.md](guide/quickstart-debian13.md) | С голого сервера до пакета для клиента: требования, установка, сервисы, relay, пользователи, обновление, неполадки |
| [guide/cheatsheet.md](guide/cheatsheet.md) | Все команды `rayctl` на одной странице |

## Как устроено — `design/`

| Документ | О чём |
|---|---|
| [design/architecture.md](design/architecture.md) | Нода: niko-server (фронт и бэкенды) и raycontrol, внутренняя ступень, данные, ротация, API |
| [design/security-model.md](design/security-model.md) | Угрозы, закрытые порты и SPA v2, постквант, ротация, zero trust |
| [design/protocols.md](design/protocols.md) | Протоколы и транспорты, домены, порты |
| [design/traffic.md](design/traffic.md) | Какой трафик (TCP, UDP, DNS, ICMP) несёт каждый профиль |
| [design/observability.md](design/observability.md) | Журналы, метрики, отчёт для issue; телеметрии нет |
| [design/capacity.md](design/capacity.md) | Сколько пользователей тянет нода и где пределы |

## Контракт с клиентом — `spec/`

Нормативные спецификации с версией в имени; клиент ссылается на них по этим путям. Главные:
[spa-v2.md](spec/spa-v2.md) (стук, заморожен), [subscription-v1.md](spec/subscription-v1.md) (подписка),
[api-v1.md](spec/api-v1.md) (удалённый API и приглашения), [probe-v1.md](spec/probe-v1.md) (замер канала),
[app-update-v1.md](spec/app-update-v1.md) (зеркало релизов клиента). Черновики: client-min-v1, integrations-v1,
app-attest-v1, rules-v1. Полный список — в каталоге [spec/](spec/).

## Решения и план

- [decisions.md](decisions.md) — принятые решения с ID (`R4-42`, `A-3`…); при расхождении главнее остальных документов.
- [roadmap.md](roadmap.md) — направления работ и что впереди.
- [RELEASE.md](RELEASE.md) — как выходит и проверяется выпуск, ключи и окружения.
- [handoff/SYNC.md](handoff/SYNC.md) — общий файл состояния с клиентской сессией; остальное в `handoff/` — архив
  ответов и заметок для клиента.

## Исследования — `research/`

Разборы и обзоры на свою дату; архив, по нему не работают. Актуальное из них перенесено в `design/`, `decisions.md` или
спецификации.

| Документ | О чём |
|---|---|
| [research/transports.md](research/transports.md) | Транспорты для режима белых списков |
| [research/dns-resolvers.md](research/dns-resolvers.md) | Резолверы для DNS-туннелей |
| [research/asn-sources.md](research/asn-sources.md) | Источники IP → ASN для сводки клиентов и их лицензии |
| [research/cronet-build.md](research/cronet-build.md) | Своя сборка libcronet и naive |
| [research/naive-default.md](research/naive-default.md) | naive как профиль по умолчанию |
| [research/naive-sni-rotation.md](research/naive-sni-rotation.md) | Смена имени naive (реализовано в v0.29.0) |
| [research/platforms-and-hosts.md](research/platforms-and-hosts.md) | `rayctl` и нода вне Linux, LXC и OpenVZ, нода без публичного адреса |
| [research/mihomo-review.md](research/mihomo-review.md) | Что взять из mihomo для маршрутизации |
| [research/review.md](research/review.md) | Разбор безопасности, качества и производительности (2026-11-04) |
| [research/client-requirements.md](research/client-requirements.md) | Требования к клиенту до его первой версии |
| [research/questions.md](research/questions.md) | Вопросы перед реализацией (все закрыты) |
| [research/legacy-audit.md](research/legacy-audit.md) | Аудит bash-установщика v0 (`legacy/`) |
