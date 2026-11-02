#!/usr/bin/env bash
# raycontrol bootstrap: downloads a release, verifies its minisign signature
# and checksum, installs rayd, rayspa and rayctl, then runs "rayctl install"
# with the arguments given here (e.g. -host 203.0.113.7 -domain example.com).
#
#   curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
#   less bootstrap.sh
#   sudo bash bootstrap.sh -host <public address> [-domain <domain>]
#
# RAYCONTROL_VERSION=v0.2.0 pins a release; default is the latest one.
set -euo pipefail

REPO="arngory/raycontrol"
VERSION="${RAYCONTROL_VERSION:-latest}"
# minisign public key of raycontrol releases, key ID A9C7802E23B87A01
# (docs/RELEASE.md). Only this base64 line matters; the "untrusted comment"
# line of the .pub file is not part of the key.
PUBKEY="RWQBergjLoDHqeme5vyIuIRXJLjTj1EF3jR1nlWBVJO3rWxgy9SZj4bD"

die() {
	echo "bootstrap: $*" >&2
	exit 1
}

[[ $EUID -eq 0 ]] || die "run as root"
[[ $PUBKEY == RWQ_REPLACE* ]] && die "this copy has no release key yet, see docs/RELEASE.md"

# shellcheck source=/dev/null
. /etc/os-release
case "${ID}:${VERSION_ID}" in
debian:12 | debian:13 | ubuntu:24.04) ;;
*) die "untested system ${ID} ${VERSION_ID} (Debian 12/13, Ubuntu 24.04)" ;;
esac
case "$(uname -m)" in
x86_64) ARCH=amd64 ;;
aarch64) ARCH=arm64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl minisign nftables

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if [[ $VERSION == latest ]]; then
	base="https://github.com/${REPO}/releases/latest/download"
else
	base="https://github.com/${REPO}/releases/download/${VERSION}"
fi
tarball="raycontrol-linux-${ARCH}.tar.gz"
for f in "$tarball" SHA256SUMS SHA256SUMS.minisig; do
	curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$f" "$base/$f"
done

minisign -Vm "$tmp/SHA256SUMS" -P "$PUBKEY"
(cd "$tmp" && grep " ${tarball}\$" SHA256SUMS | sha256sum -c -)

tar -xzf "$tmp/$tarball" -C "$tmp"
install -m 0755 "$tmp/rayd" "$tmp/rayspa" "$tmp/rayctl" /usr/local/bin/
exec /usr/local/bin/rayctl install "$@"
