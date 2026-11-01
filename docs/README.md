# raycontrol v2: проектная документация

Нода — самодостаточный серверный стек на одном хосте. Data plane — niko-server (форк sing-box): фронт-мультиплексоры
и отдельные процессы-бэкенды протоколов. Control plane — raycontrol: состояние, конфиги, ротация, SPA и файрвол, подписка,
API для CLI и клиента Niko. Все порты закрыты до SPA v2, постквант обязателен везде, где его поддерживает протокол,
ключи и доступы ротируются, у каждой установки свои случайные параметры, между компонентами — zero trust.

| Документ | О чём |
|---|---|
| [00-legacy-audit.md](00-legacy-audit.md) | Аудит текущей версии v0: находки с ID `L-xx`. |
| [01-architecture.md](01-architecture.md) | Нода: niko-server (фронт + бэкенды) и raycontrol, внутренняя ступень `inner`, данные, ротация, API. |
| [02-security-model.md](02-security-model.md) | Угрозы, полное закрытие портов, SPA v2, постквант, ротация, zero trust, аккаунты платформ. |
| [03-protocols.md](03-protocols.md) | Состав протоколов v1, домены, порты, отличия от SPEC. |
| [04-roadmap.md](04-roadmap.md) | Направления работ и этапы R0–R5, синхронизированные с SPEC niko-server. |
| [05-transports-research.md](05-transports-research.md) | Транспорты для белых списков: qWDTT, CSQTT, olcRTC, OpenFlux, dnstt, Slipstream, MasterDnsVPN, S3 Bypass. |
| [06-client-requirements.md](06-client-requirements.md) | Требования к клиенту для следующей фазы. |
| [07-questions.md](07-questions.md) | Вопросы перед реализацией (история; все закрыты). |
| [08-decisions.md](08-decisions.md) | **Принятые решения** — главнее остальных документов при расхождении. |
| [spec/spa-v2.md](spec/spa-v2.md) | Формат SPA v2 и пакета регистрации устройства (заморожен). |
| [handoff/niko-session.md](handoff/niko-session.md) | Что передать в сессию Niko: правки SPEC, контракт niko-server, доработки клиента. |

Статус: решения приняты (08), документы 01–04 переписаны под них. Data plane — [niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md), control plane — raycontrol.
Код v0 перенесён в `legacy/`. Этап R0 реализован: `rayd`, `rayctl`, хранилище, SPA v2.
