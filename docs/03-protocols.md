# 03. Протоколы и движки

Статус: **черновик для согласования**. Сведения о сторонних проектах актуальны на октябрь 2026 года;
перед реализацией каждого адаптера версия и возможности сверяются с документацией движка.

## Решения на старте

| Протокол | Движок | Статус | Профиль |
|---|---|---|---|
| VLESS + REALITY + Vision, self-steal | Xray-core | **основной**, этап M1 | public, TCP 443 |
| Hysteria2, masquerade, свой SNI | apernet/hysteria (официальный) | **основной**, этап M1 | public, UDP 443 |
| Hysteria2, salamander | apernet/hysteria (официальный) | **основной**, этап M1 | gated, UDP (свой порт или диапазон) |
| VLESS + XHTTP (без Cloudflare) | Xray-core | опционально, этап M5 | по варианту деплоя |
| NaiveProxy | Caddy + forwardproxy@naive | кандидат, PoC в M5 | public (за fallback REALITY) |
| TrustTunnel | TrustTunnel endpoint (Rust) | кандидат, PoC в M5 | решается в PoC |
| TUIC v5 | sing-box или форк Itsusinn/tuic | отложен | — |
| dnstt | dnstt-server | крайний случай, M5 | public, UDP 53 |
| Trojan, VMess | — | **не переносим** | — |

## Общая схема: self-steal

Свой домен и свой сайт-приманка (Caddy) — единая «легенда» сервера:

```
TCP 80   caddy        — HTTP→HTTPS, ACME HTTP-01
TCP 443  xray REALITY — свои клиенты (auth REALITY) → VLESS+Vision
                      — все остальные → caddy (свой сайт, свой сертификат)
UDP 443  hysteria     — masquerade: на HTTP/3-запросы отвечает тот же сайт (proxy на caddy)
UDP N    hysteria     — salamander, gated
```

Сканер или цензор видит обычный сайт с сертификатом своего домена по HTTP/1.1, HTTP/2 и HTTP/3.

Почему self-steal, а не чужой сайт как цель REALITY: SNI, сертификат и IP согласованы между собой;
нет зависимости от чужого сайта; Hysteria masquerade отдаёт тот же контент.

## VLESS + REALITY + Vision (Xray)

- `dest` REALITY = caddy на loopback или unix socket; `serverNames` = свой домен.
- Ключи REALITY (x25519) и `shortIds` у инстанса свои; пользователи — UUID на этот инстанс.
- Пользователи добавляются и удаляются через gRPC API Xray без перезапуска; трафик через `StatsService`.
- Routing: `geoip:private` и служебные сети → blackhole (L-02); по желанию блокировка BitTorrent.
- Проверить в PoC: получение сертификата через TLS-ALPN-01 сквозь fallback REALITY к caddy;
  если не работает — HTTP-01 на TCP 80.

## Hysteria2: два инстанса

Один движок, два systemd-инстанса (`hysteria@masq`, `hysteria@obfs`) с разными конфигами,
пользователями и секретами. salamander и masquerade в одном инстансе несовместимы (L-41):
с obfs сервер перестаёт быть HTTP/3-сервером.

**`hysteria@masq` (public, UDP 443)**
- TLS: сертификат своего домена (через `LoadCredential=`).
- `masquerade.type: proxy` → сайт caddy (поддерживается unix socket), `rewriteHost: true`.
- Цель: на проверку отвечает тот же сайт, что и на TCP 443.

**`hysteria@obfs` (gated, свой UDP-порт)**
- `obfs.type: salamander`, пароль obfs свой у инстанса.
- Port hopping: сам Hysteria создаёт правила nftables и требует `CAP_NET_ADMIN`. Это противоречит изоляции
  и нашей таблице `inet raycontrol`. Предлагается: диапазон и редирект на один порт создаёт `rayspa`,
  а Hysteria слушает один порт без лишних прав.

**Общее для обоих**
- `auth.type: http` → колбэк в `rayd`: POST `{addr, auth, tx}`, ответ `{ok, id}`. Без shell и SQL (закрывает L-01).
- `trafficStats` со своим секретом: статистика и отключение пользователя.
- ACL: запрет приватных сетей (L-02).
- sysctl: увеличенные `net.core.rmem_max`/`wmem_max` для QUIC (L-53).

Xray тоже умеет Hysteria2 как inbound, но в документации нет salamander и masquerade, поэтому для обоих
инстансов берём официальный сервер.

## VLESS + XHTTP (опционально, без Cloudflare)

Варианты деплоя, выбор в M5:

1. **XHTTP поверх REALITY** на том же TCP 443 — без домена-посредника и CDN.
2. **XHTTP за своим caddy**: секретный путь на сайте-приманке проксируется в Xray через unix socket.
   Работает по HTTP/2 и HTTP/3 того же домена.
3. **CDN, не Cloudflare** — только если появится конкретная потребность; отдельный разбор.

Для вариантов 2 и 3 стоит рассмотреть VLESS Encryption (ML-KEM-768, Xray с сентября 2025):
она даёт шифрование, не зависящее от внешнего TLS. Ограничение: несовместима с `fallbacks`.

## NaiveProxy (кандидат)

- Сервер — Caddy, собранный с `forwardproxy@naive`. Caddy у нас уже есть как сайт-приманка,
  поэтому Naive добавляется почти без новых процессов.
- Клиент — сетевой стек Chromium: TLS-отпечаток настоящего браузера.
- Как уживается с REALITY на 443: Naive-клиент не проходит аутентификацию REALITY, и соединение уходит в
  fallback на caddy, который терминирует TLS и обслуживает Naive. **Проверить в PoC:** задержка,
  корректность HTTP/2 CONNECT через fallback.
- Учётные данные: basic auth на пользователя; Caddy перезагружает конфиг без разрыва соединений.

## TrustTunnel (кандидат)

- Протокол AdGuard VPN, открыт в январе 2026 года (Apache-2.0), сервер на Rust:
  [github.com/TrustTunnel/TrustTunnel](https://github.com/TrustTunnel/TrustTunnel).
- Транспорт: HTTP/1.1, HTTP/2, QUIC; трафик выглядит как обычный HTTPS.
- Клиенты: официальный CLI (Linux, macOS, Windows) и Flutter-клиент для iOS и Android — это плюс для пользователей
  без своего клиента.
- Учётные данные в `credentials.toml`, перезагрузка по SIGHUP — адаптер укладывается в общий контракт.
- Вопросы для PoC: собственный TLS-эндпоинт конкурирует за 443 (отдельный порт или SNI-маршрутизация);
  поведение при активной проверке не описано в документации; зрелость сервера.

## TUIC v5 (отложен)

Занимает ту же нишу, что Hysteria2 (QUIC). Оригинальный репозиторий EAimTY/tuic больше не развивается,
живые реализации — форк Itsusinn/tuic и sing-box. Возвращаемся к нему, только если Hysteria2 будут
блокировать точечно, а QUIC в целом останется доступен.

## dnstt (крайний случай)

- DNS-туннель (Noise поверх DNS через DoH/DoT/UDP-резолверы) для ситуации, когда остальное заблокировано.
- Требует делегирования NS-записи поддомена на сервер и публичного UDP 53; скорость низкая.
- Своей пользовательской аутентификации нет (только ключ сервера), поэтому за dnstt ставится
  сервис с аутентификацией (например, VLESS-инбаунд на loopback), а не открытый SOCKS.

## Прочие кандидаты (только для справки)

ShadowTLS v3, AnyTLS (sing-box), AmneziaWG. Не планируем, пока нет конкретной потребности.

## Карта портов по умолчанию

| Порт | Протокол | Кто слушает | Профиль |
|---|---|---|---|
| TCP 80 | HTTP | caddy | public |
| TCP 443 | TLS | xray (REALITY) → fallback caddy | public |
| UDP 443 | QUIC | hysteria@masq | public |
| UDP (настраивается) | salamander | hysteria@obfs | gated |
| UDP (настраивается) | SPA | ядро → NFLOG → rayspa | после knock |
| TCP (настраивается) | API | rayd | gated + mTLS |
| TCP 22 или свой | SSH | sshd | gated |
| UDP 53 | DNS | dnstt-server (если включён) | public |
