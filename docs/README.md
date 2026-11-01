# raycontrol v2: проектная документация

Нода raycontrol — самодостаточный серверный стек: набор изолированных микросервисов, каждый со своим срезом
инфраструктуры. Нода сводит разные ядра, протоколы, транспорты и способы маскировки в одну модель с единым API
для CLI и будущего кроссплатформенного клиента (режимы пользователя и администратора). Защита многоуровневая:
port-knocking → SPA → аутентификация в каждом сервисе, между компонентами — zero trust.

| Документ | О чём |
|---|---|
| [00-legacy-audit.md](00-legacy-audit.md) | Аудит текущей версии v0: находки с ID `L-xx`. |
| [01-architecture.md](01-architecture.md) | Нода и сервисы, единая модель трафика, внутренняя ступень `ray-core`, манифесты и плагины движков, данные. |
| [02-security-model.md](02-security-model.md) | Угрозы, эшелоны защиты, knock + SPA, периметр по классам входа, zero trust, учётные данные третьих сторон. |
| [03-protocols.md](03-protocols.md) | Direct-протоколы и движки, self-steal, карта портов. |
| [04-roadmap.md](04-roadmap.md) | Направления работ с привязкой к находкам аудита и этапы M0–M6. |
| [05-transports-research.md](05-transports-research.md) | Транспорты для белых списков: qWDTT, CSQTT, olcRTC, OpenFlux, dnstt, Slipstream, MasterDnsVPN, S3 Bypass. |
| [06-client-requirements.md](06-client-requirements.md) | Требования к клиенту для следующей фазы. |
| [07-questions.md](07-questions.md) | Вопросы перед реализацией (редакция 2, с учётом спецификации niko-server). |

Статус: черновик для согласования. Документы 01–04 будут пересмотрены после ответов на вопросы P-1…P-3
(связка с [niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)). Код v0 (`ray.sh`, `uninstall.sh`) пока остаётся на месте.
