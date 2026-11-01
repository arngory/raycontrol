# raycontrol

Control plane for a self-contained proxy node. The data plane is
[niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)
(a sing-box fork); raycontrol keeps users and keys, renders configs, runs the
SPA-gated firewall, rotates keys and serves the subscription and API.

Status: **R0** — node state, `rayd`, `rayctl` and the SPA v2 format. Nothing is
deployed to a host yet; see [docs/04-roadmap.md](docs/04-roadmap.md).

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

- **Статус:** этап R0 — состояние ноды, `rayd`, `rayctl` и формат SPA v2. На хост пока ничего не ставится.
- **Сборка:** Go 1.26, `go build ./cmd/...`, `go test ./...`; API генерируется `scripts/gen.sh`.
- **Документы:** [docs/](docs/README.md); формат SPA v2 заморожен в [docs/spec/spa-v2.md](docs/spec/spa-v2.md).
- **v0:** bash-установщик перенесён в [legacy/](legacy/); для новых установок не использовать.
