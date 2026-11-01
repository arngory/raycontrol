# raycontrol

Control plane for a self-contained proxy node. The data plane is
[niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)
(a sing-box fork); raycontrol keeps users and keys, renders configs, runs the
SPA-gated firewall, rotates keys and serves the subscription and API.

Status: **R1** — perimeter (SPA v2 over UDP and TCP), DNS tunnels with the
inner stage on Xray, signed subscriptions, installer. The niko-server binary
(front and backends) is not released yet; see [docs/04-roadmap.md](docs/04-roadmap.md).

## Install

On Debian 12/13 or Ubuntu 24.04, as root, from an SSH session (its address
becomes the emergency SSH access):

```
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh -host <public address> -domain <domain>
```

The bootstrap verifies the release signature (minisign), installs `rayd`,
`rayspa` and `rayctl` and runs `rayctl install`. Every port is closed
afterwards except SPA, DNS tunnels and SSH from the admin address. Recovery
from the provider console: `rayspa teardown`. Releases: [docs/RELEASE.md](docs/RELEASE.md).

[Русская версия ниже](#raycontrol-ru)

## Build

Go 1.26:

```
go build ./cmd/...
go test ./...
```

`scripts/gen.sh` regenerates the API code from `api/proto` with pinned tools.

## Try it locally

```
rayd init -db ./rayd.db -host 203.0.113.7
rayd serve -db ./rayd.db -socket ./rayd.sock &
rayctl -socket ./rayd.sock service add reality reality
rayctl -socket ./rayd.sock user add alice -services reality -expires 30d
rayctl -socket ./rayd.sock device add alice phone
```

The last command prints the device enrollment bundle (`rcdev1:...`) once.

## Documents

Design, decisions and specs are in [docs/](docs/README.md) (Russian). The SPA v2
wire format is frozen in [docs/spec/spa-v2.md](docs/spec/spa-v2.md) with test
vectors in `internal/spa/testdata/vectors.json`.

## Legacy

The v0 bash installer lives in [legacy/](legacy/) until v2 replaces it. Its
audit is [docs/00-legacy-audit.md](docs/00-legacy-audit.md); do not use it for
new installs.

---

<a id="raycontrol-ru"></a>

# raycontrol (RU)

Control plane самодостаточной прокси-ноды. Data plane — niko-server (форк sing-box);
raycontrol хранит пользователей и ключи, генерирует конфиги, ведёт файрвол со SPA,
ротирует ключи, отдаёт подписку и API.

- **Статус:** этап R1 — периметр (SPA v2 по UDP и TCP), DNS-туннели с внутренней ступенью на Xray, подписанные
  подписки, установщик. Бинарник niko-server ещё не выпущен.
- **Установка:** Debian 12/13 или Ubuntu 24.04, root, из SSH-сессии: `bash bootstrap.sh -host <адрес> -domain <домен>`
  (скрипт `install/bootstrap.sh` проверяет подпись релиза). Восстановление с консоли: `rayspa teardown`.
- **Сборка:** Go 1.26, `go build ./cmd/...`, `go test ./...`; API генерируется `scripts/gen.sh`.
- **Документы:** [docs/](docs/README.md); формат SPA v2 заморожен в [docs/spec/spa-v2.md](docs/spec/spa-v2.md).
- **v0:** bash-установщик перенесён в [legacy/](legacy/); для новых установок не использовать.

## License

GPL-3.0, see [LICENSE](LICENSE). / Лицензия GPL-3.0, см. [LICENSE](LICENSE).
