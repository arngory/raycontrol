# 03. Протоколы и транспорты v1

Статус: **принят** (редакция 2, по решениям из [08-decisions.md](08-decisions.md)).
Подробности реализации протоколов — в SPEC niko-server; здесь — состав, порты и что меняется относительно SPEC.

## Состав v1

| Сервис | Реализация | Класс входа | Доступ | PQ |
|---|---|---|---|---|
| VLESS + REALITY + Vision, self-steal | Xray (форк) | direct, TCP 443 | SPA | X25519MLKEM768 + ML-DSA-65 |
| VLESS encryption (второй слой) | Xray (форк) | поверх REALITY | SPA | ML-KEM-768 |
| Hysteria2 masquerade | бэкенд niko-server | direct, UDP 443 | SPA | X25519MLKEM768 |
| Hysteria2 salamander | бэкенд niko-server | direct, UDP 443 | SPA | X25519MLKEM768 |
| NaiveProxy h2 и QUIC | бэкенд niko-server | direct, TCP/UDP 443 | SPA | X25519MLKEM768 |
| DoH / DoH3 | бэкенд niko-server | direct, TCP/UDP 443 | SPA | X25519MLKEM768 |
| Yggdrasil | бэкенд niko-server | direct, TCP 443 | SPA | проверить |
| dnstt | бэкенд niko-server (библиотека из форка) | dns, UDP 53 | открыт, ключ туннеля | через `inner` |
| MasterDnsVPN | бэкенд niko-server (библиотека из форка) | dns, UDP 53 | открыт, ключ туннеля | через `inner` |
| olcRTC | движок из форка | rendezvous (Jitsi, Телемост, WB Stream) | входящих нет | через `inner` |
| OpenFlux | движок из форка | rendezvous (сервисы документов) | входящих нет | через `inner` |
| Внутренняя ступень `inner` | бэкенд niko-server или Xray (08, «Следствие 5») | unix socket | только от движков | ML-KEM-768 |

Не в v1: XHTTP на сервере, TrustTunnel, qWDTT, S3 Bypass, TUIC, AmneziaWG, CSQTT, Trojan, VMess.

## Домены

- **Вариант A (по умолчанию)** из SPEC §2.2: свои поддомены для REALITY self-steal, naive и DoH, Hysteria2 masquerade,
  Yggdrasil; делегированные зоны для dnstt и MasterDnsVPN.
- Поддомены выбираются случайно при установке и ротируются (08, «Следствие 1»):
  - DNS: одна wildcard-запись `*.example.com A` + NS-делегирование зон DNS-туннелей, всё вручную у регистратора;
  - сертификаты: wildcard через DNS-01, если у провайдера есть API; иначе — по поддомену в коротком окне ACME.
- **Вариант B** (без домена, REALITY с чужой целью) остаётся из SPEC; naive, DoH и masquerade в нём не поднимаются.

## Порты

| Порт | Кто слушает | Доступ |
|---|---|---|
| TCP 443 | `niko-front` (tcpmux) | после SPA; для всех — только на время ACME |
| UDP 443 | `niko-front` (udpmux) | после SPA |
| UDP 53 | `niko-front` (dnsmux) | открыт, только свои зоны |
| UDP, ротируемый порт из диапазона установки | ядро → NFLOG → `rayspa` | SPA, ответа нет |
| TCP, порт из диапазона установки | `rayd`: подписка и API | после SPA |
| TCP 22 или свой | sshd, только ключи | после SPA; аварийный доступ — 08, D-6 |
| TCP 80 | не используется (только окно ACME HTTP-01, если выбран он) | — |
| TCP/UDP 853 | не открывается | — |

## Отличия от SPEC niko-server

Список изменений для SPEC — в [08-decisions.md](08-decisions.md), «Следствие 3». Кратко:

- неавторизованный адрес получает drop, а не приманку; приманка остаётся для тех, кто прошёл SPA, но не сервис (CGNAT);
- SPA v2 обрабатывает `rayspa`, а не udpmux;
- фронт и бэкенды — отдельные процессы;
- конфиги генерирует raycontrol;
- PQ в TLS обязателен.

## Прочие протоколы

Исследование транспортов белых списков — [05-transports-research.md](05-transports-research.md).
