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
| [09-observability.md](09-observability.md) | Логи, телеметрия (её нет), отчёт для issue, QA, обезличенные идентификаторы. |
| [10-quickstart-debian13.md](10-quickstart-debian13.md) | Нода с нуля на Debian 13 с Cloudflare и выдача подписки клиенту. |
| [11-asn-sources.md](11-asn-sources.md) | Источники IP → ASN для сводки клиентов: базы и API, их лицензии и условия. |
| [cheatsheet.md](cheatsheet.md) | Все команды `rayctl` на одной странице. |
| [spec/spa-v2.md](spec/spa-v2.md) | Формат SPA v2 и пакета регистрации устройства (заморожен). |
| [spec/subscription-v1.md](spec/subscription-v1.md) | Подписка: запрос, подписи, ссылки с параметрами `niko-*` (заморожена). |
| [spec/api-v1.md](spec/api-v1.md) | Удалённый API: приглашения `rcinv1:`, регистрация, mTLS по ключу устройства, роли. |
| [RELEASE.md](RELEASE.md) | Ключ подписи и выпуск релизов. |
| [handoff/niko-session.md](handoff/niko-session.md) | Что передать в сессию Niko: правки SPEC, контракт niko-server, доработки клиента. |
| [handoff/niko-r1-reply.md](handoff/niko-r1-reply.md) | Ответ на документы R1 сессии Niko: TCP-носитель SPA, замечания к CONFIG и IPC. |
| [handoff/niko-r4-note.md](handoff/niko-r4-note.md) | Что изменилось на сервере в R4 и что нужно от клиента: `next`, импорт пакета, требования к пакетам. |
| [handoff/niko-r3-note.md](handoff/niko-r3-note.md) | Серверная часть R2/R3: профили Hysteria2, DoH, naive, регистрация по приглашению `rcinv1:`, что проверить в CI Niko. |
| [handoff/niko-r3-reply.md](handoff/niko-r3-reply.md) | Ответ на RAYCONTROL.md §9–§10: DoH напрямую на ноду, ссылка `rcinv1:` как URI, перенос niko-server в `arngory/niko-server`. |
| [handoff/niko-mux-note.md](handoff/niko-mux-note.md) | Фронт niko-server на 443: tcpmux и udpmux, Hysteria2 на sing-quic, naive-quic и DoH3, что поменять в CI Niko. |
| [handoff/niko-ygg-note.md](handoff/niko-ygg-note.md) | Yggdrasil на ноде (R4-15): профиль `niko-ygg`, конфиг ядра клиента, ротация ключа вместе с UUID. |
| [handoff/niko-probe-note.md](handoff/niko-probe-note.md) | Замер канала (R4-16, ответ на §13): TCP и эхо UDP на эндпоинте подписки, потолки Brutal, что дальше. |
| [handoff/niko-prompt-2026-11-03.md](handoff/niko-prompt-2026-11-03.md) | Промпт для сессии клиента: всё с прошлых закреплений (фронт, Yggdrasil, замер, Brutal), что сделать и что прислать. |

Статус: решения приняты (08), документы 01–04 переписаны под них. Data plane — [niko-server](https://github.com/arngory/niko-server) ([SPEC](https://github.com/arngory/niko-server/blob/main/docs/SPEC.md)), control plane — raycontrol; обе ведёт эта сессия.
Код v0 перенесён в `legacy/`. Этапы R0 и R1 реализованы, установка проверяется в CI на Debian 12/13, Ubuntu 24.04 и
Rocky Linux 9/10 (решение R2-1); niko-server живёт в [`arngory/niko-server`](https://github.com/arngory/niko-server) (релиз v0.7.0), raycontrol v0.3.0 выпущен.
