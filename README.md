# raycontrol

Control plane for a self-contained proxy node. The data plane is
[niko-server](https://github.com/arngory/niko/blob/claude/intelligent-allen-0oa8na/docs/server/SPEC.md)
(a sing-box fork); raycontrol keeps users and keys, renders configs, runs the
SPA-gated firewall, rotates keys and serves the subscription and API.

Status: **R1** done — perimeter (SPA v2 over UDP and TCP), DNS tunnels with
the inner stage on Xray, signed subscriptions, installer. **R2** — VLESS +
REALITY + Vision on Xray (post-quantum key exchange and signature) with
self-steal on the node's own decoy site, certificates through ACME. **R3** —
Hysteria2 twice (masquerade on UDP 443, salamander), DNS over HTTPS and
NaiveProxy (h2) behind REALITY, interim on Xray and rayd until the niko-server
front; the remote API behind SPA with mTLS and one-time invites. **R4** —
rotation of user credentials and REALITY keys and names, Cloudflare for DNS
records and wildcard certificates, uninstall back to the host's snapshot,
redacted reports, a kernel-side early drop, encrypted backups, local metrics. Data plane: niko-server-v0.1.1
(DNS front, dnstt and MasterDnsVPN backends); see
[docs/04-roadmap.md](docs/04-roadmap.md).

From a bare Debian 13 server to a bundle for the client, step by step:
[docs/10-quickstart-debian13.md](docs/10-quickstart-debian13.md) (Russian).
All commands on one page: [docs/cheatsheet.md](docs/cheatsheet.md).

## Install

Any current Linux with systemd; tested on every push by a full install on
Debian 12/13, Ubuntu 24.04 and Rocky Linux 9/10. As root, from an SSH session
(its address becomes the emergency SSH access):

```
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh -host <public address> -domain <domain> -cloudflare-token-file /root/cf.token -services reality,dnstt,masterdns
```

The release carries the data plane under the same signature: Xray built from
the pinned commit of our fork and niko-server checked against pinned hashes
(`deploy/versions.env`). `rayctl install` puts both in
`/usr/local/libexec/raycontrol` (an Xray the host has for other software is
left alone) and sets the services up: REALITY by default when a domain is
given, DNS tunnels on request.

With a Cloudflare API token (Zone.DNS:Edit and Zone.Zone:Read on the domain's
zone) the node keeps its own DNS records (a wildcard to its address, the NS
delegation of DNS tunnel zones; DNS only, marked "raycontrol", nothing else
touched) and gets one wildcard certificate through DNS-01, so no port opens
for ACME. Without it, `rayctl dns` lists the records to make by hand and
certificates go through HTTP-01 in a short window.

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
rayctl device add u-k3f9-x2qa phone -o phone.bundle   # enrollment bundle, once (file 0600)
rayctl service add reality reality                    # self-steal on the node's decoy site
rayctl apply                                          # install what new services need
rayctl service rotate reality                         # new REALITY keys and name ahead of schedule
rayctl service set site answer=silent                 # decoy site: 404 (default), 403, silent or pages
rayctl dns                                            # DNS provider, records the node needs, conflicts
rayctl update                                         # newest verified release in place, rolls back on failure
rayctl admin 198.51.100.7                             # addresses that reach SSH without SPA
rayctl report -o report.txt                           # redacted report for an issue
rayctl backup -o node.rcbak                           # every key of the node under a passphrase
rayctl restore -i node.rcbak [-host NEW_IP]           # back here, or onto a new host after install
rayctl metrics                                        # counts and times for Prometheus, no names
rayctl device invite alice phone                      # one-time rcinv1: invite, the client registers itself
rayctl remote enroll -o laptop.rcdev rcinv1:...       # elsewhere: an admin device from an invite
rayctl -remote laptop.rcdev status                    # any admin command through the remote API
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
  подписки, установщик. R2 — REALITY на Xray с постквантом и self-steal на своём сайте-приманке, сертификаты через
  ACME. R4 — ротация UUID и ключей/имён REALITY, Cloudflare для DNS-записей и wildcard-сертификата, удаление до снимка
  системы, очищенные отчёты, ранний отброс пакетов до стека ядра. Data plane — niko-server-v0.1.1.
- **С нуля на Debian 13:** [docs/10-quickstart-debian13.md](docs/10-quickstart-debian13.md); все команды —
  [docs/cheatsheet.md](docs/cheatsheet.md).
- **Установка:** любой современный Linux с systemd; полная установка проверяется в CI на Debian 12/13, Ubuntu 24.04,
  Rocky Linux 9/10. Root, из SSH-сессии: `bash bootstrap.sh -host <адрес> -domain <домен> -cloudflare-token-file <файл>` (скрипт
  `install/bootstrap.sh` ставит зависимости через apt/dnf/zypper/pacman и проверяет подпись релиза). firewalld и ufw
  настраиваются сами. На RHEL-семействе `sudo` не видит `/usr/local/bin` — `sudo -i` или полный путь.
  Восстановление с консоли: `rayspa teardown`. Проверка ноды снаружи, как клиент: `rayctl probe rcdev1:...`.
- **Администрирование:** всё, что умеет API для клиента, на ноде умеет `rayctl` (пользователи, устройства, сервисы,
  `apply`, адреса администратора, `report` — очищенный отчёт для issue, `backup`/`restore` — копия ноды под парольной
  фразой, `metrics` — счётчики без имён, `uninstall` — полный откат установки по журналу, проверенный сравнением со
  снимком системы). Нода ничего не отправляет наружу сама.
- **Сборка:** Go 1.26, `go build ./cmd/...`, `go test ./...`; API генерируется `scripts/gen.sh`.
- **Документы:** [docs/](docs/README.md); формат SPA v2 заморожен в [docs/spec/spa-v2.md](docs/spec/spa-v2.md).
- **v0:** bash-установщик перенесён в [legacy/](legacy/); для новых установок не использовать.

## License

GPL-3.0, see [LICENSE](LICENSE). / Лицензия GPL-3.0, см. [LICENSE](LICENSE).
