# raycontrol

Control plane for a self-contained proxy node. The data plane is
[niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)
(a sing-box fork); raycontrol keeps users and keys, renders configs, runs the
SPA-gated firewall, rotates keys and serves the subscription and API.

Status: **R1** done — perimeter (SPA v2 over UDP and TCP), DNS tunnels with
the inner stage on Xray, signed subscriptions, installer. **R2** under way —
VLESS + REALITY + Vision on Xray (post-quantum key exchange and signature),
a decoy site per install as the self-steal target, certificates through ACME.
Data plane: niko-server-v0.1.1 (DNS front, dnstt and MasterDnsVPN backends);
see [docs/04-roadmap.md](docs/04-roadmap.md).

## Install

Any current Linux with systemd; tested on every push by a full install on
Debian 12/13, Ubuntu 24.04 and Rocky Linux 9/10. As root, from an SSH session
(its address becomes the emergency SSH access):

```
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh -host <public address> -domain <domain>
```

The bootstrap installs what is missing (curl, openssl, nftables, polkit) with
apt, dnf, zypper or pacman, verifies the release signature (minisign format,
checked with openssl), installs `rayd`, `rayspa` and `rayctl` to
`/usr/local/bin` and runs `rayctl install`, which checks the host first
(systemd, D-Bus, polkit, an nft and kernel that load the perimeter table).
Every port is closed afterwards except SPA, DNS tunnels and SSH from the admin
address. firewalld and ufw get the node's ports opened for them; rayspa still
decides who reaches which port. Recovery from the provider console:
`rayspa teardown`. Releases: [docs/RELEASE.md](docs/RELEASE.md).

On RHEL-family systems `sudo` drops `/usr/local/bin` from `PATH`: use
`sudo -i` or the full path `/usr/local/bin/rayctl`.

To check a node from outside the way a client does (SPA, then the signed
subscription), give a device bundle to `rayctl probe rcdev1:...` on any
machine.

## Administration

Everything the client API does, `rayctl` does on the node (as root, or as a
member of the `raycontrol` group):

```
rayctl status
rayctl user add -services reality,dns -expires 30d    # opaque name such as u-k3f9-x2qa
rayctl device add u-k3f9-x2qa phone                   # enrollment bundle, shown once
rayctl service add reality reality                    # self-steal on the node's decoy site
rayctl apply                                          # install what new services need
rayctl service rotate reality                         # new REALITY keys and name ahead of schedule
rayctl admin 198.51.100.7                             # addresses that reach SSH without SPA
rayctl report -o report.txt                           # redacted report for an issue
rayctl uninstall                                      # take everything back
```

`rayctl uninstall` reverts every change the install made, from a journal kept
since the first step: files, users, units, sysctl, resolv.conf, firewalld and
ufw rules; the test suite checks that the host matches its snapshot from
before the install. `-keep-state` keeps the database for a later install.
Nothing is ever sent anywhere by the node; see
[docs/09-observability.md](docs/09-observability.md).

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

- **Статус:** R1 готов — периметр (SPA v2 по UDP и TCP), DNS-туннели с внутренней ступенью на Xray, подписанные
  подписки, установщик. Идёт R2 — REALITY на Xray с постквантом, сайт-приманка для self-steal, сертификаты через ACME.
  Data plane — niko-server-v0.1.1.
- **Установка:** любой современный Linux с systemd; полная установка проверяется в CI на Debian 12/13, Ubuntu 24.04,
  Rocky Linux 9/10. Root, из SSH-сессии: `bash bootstrap.sh -host <адрес> -domain <домен>` (скрипт
  `install/bootstrap.sh` ставит зависимости через apt/dnf/zypper/pacman и проверяет подпись релиза). firewalld и ufw
  настраиваются сами. На RHEL-семействе `sudo` не видит `/usr/local/bin` — `sudo -i` или полный путь.
  Восстановление с консоли: `rayspa teardown`. Проверка ноды снаружи, как клиент: `rayctl probe rcdev1:...`.
- **Администрирование:** всё, что умеет API для клиента, на ноде умеет `rayctl` (пользователи, устройства, сервисы,
  `apply`, адреса администратора, `report` — очищенный отчёт для issue, `uninstall` — полный откат установки по журналу,
  проверенный сравнением со снимком системы). Нода ничего не отправляет наружу сама.
- **Сборка:** Go 1.26, `go build ./cmd/...`, `go test ./...`; API генерируется `scripts/gen.sh`.
- **Документы:** [docs/](docs/README.md); формат SPA v2 заморожен в [docs/spec/spa-v2.md](docs/spec/spa-v2.md).
- **v0:** bash-установщик перенесён в [legacy/](legacy/); для новых установок не использовать.

## License

GPL-3.0, see [LICENSE](LICENSE). / Лицензия GPL-3.0, см. [LICENSE](LICENSE).
