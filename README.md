# raycontrol

English | [Русский](README.ru.md)

Control plane of a self-contained proxy node on one Linux host. The data plane is
[niko-server](https://github.com/arngory/niko-server); raycontrol keeps users, devices and keys, renders the
configs, runs the SPA-gated firewall, rotates keys, and serves the signed subscription and the API for the
[Niko](https://github.com/arngory/niko) client. Every port stays closed to anyone who has not knocked first.

Releases: [latest](https://github.com/arngory/raycontrol/releases/latest), signed with minisign.

## Install

Any current Linux with systemd (CI installs on Debian 12/13, Ubuntu 24.04, Rocky Linux 9/10). As root, from an
SSH session; its address keeps SSH open:

```
curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh -host <public address> -domain <domain> -services reality,dnstt
```

The script verifies the release signature and the host, installs, and closes every port but SPA, the DNS tunnels
and SSH from your address. From the provider's console, `rayspa teardown` opens the host again.

Step by step, from a bare server to a client bundle: [docs/guide/quickstart-debian13.md](docs/guide/quickstart-debian13.md)
(Russian). Every command: [docs/guide/cheatsheet.md](docs/guide/cheatsheet.md).

## Use

```
rayctl status
rayctl user add -services reality -expires 30d   # prints the new user's name
rayctl device invite <user> phone                # one-time invite for the Niko app
rayctl update                                    # newest verified release, rolled back on failure
rayctl uninstall                                 # everything back as it was before the install
```

## Build

Go as in `go.mod`:

```
go build ./cmd/...
go test ./...
```

`scripts/gen.sh` regenerates the API code from `api/proto`.

## More

- [docs/README.md](docs/README.md): design, decisions and specifications (Russian).
- [CONTRIBUTING.md](CONTRIBUTING.md): branches, checks and releases.
- [docs/RELEASE.md](docs/RELEASE.md): how a release is made and verified.

License: GPL-3.0, see [LICENSE](LICENSE).
