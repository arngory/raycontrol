#!/usr/bin/env bash
# Fetches a release for test/install/upgrade.sh (the latest, or VERSION):
# its linux/amd64 archive, verified as bootstrap.sh verifies it (minisign
# over SHA256SUMS), extracted to OUT_DIR, and the install/ directory of its
# commit (from VERSIONS) beside the binaries. Run from the repository (git
# archive). With RELEASE_DIR, the release's three files as published go
# there too: a node's rayctl updates from them (rayctl update -from) as from
# GitHub, signature and all.
#
#   test/install/previous.sh OUT_DIR [VERSION [RELEASE_DIR]]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install/bootstrap.sh
. "$here/../../install/bootstrap.sh"

usage="usage: previous.sh OUT_DIR [VERSION [RELEASE_DIR]]"
out=${1:?$usage}
want=${2:-latest}
keep=${3:-}
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/latest/download"
if [[ $want != latest ]]; then
	base="https://github.com/$REPO/releases/download/$want"
fi
for f in raycontrol-linux-amd64.tar.gz SHA256SUMS SHA256SUMS.minisig; do
	curl -fsSL --retry 8 --retry-delay 15 --retry-all-errors --retry-max-time 900 --connect-timeout 30 -o "$tmp/$f" "$base/$f"
done
verify_minisig "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.minisig" "$PUBKEY" || die "the release's signature does not verify"
(cd "$tmp" && grep ' raycontrol-linux-amd64.tar.gz$' SHA256SUMS | sha256sum -c --quiet -) || die "the archive's checksum does not match"
tar -xzf "$tmp/raycontrol-linux-amd64.tar.gz" -C "$out"
if [[ -n $keep ]]; then
	mkdir -p "$keep"
	cp "$tmp/raycontrol-linux-amd64.tar.gz" "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.minisig" "$keep/"
fi
read -r _ version commit < <(grep -m1 '^raycontrol ' "$out/VERSIONS")
[[ $want == latest || $version == "$want" ]] || die "asked for $want, VERSIONS says $version"
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "no commit in VERSIONS: $(head -1 "$out/VERSIONS")"
root="$(git -C "$here" rev-parse --show-toplevel)"
git -C "$root" cat-file -e "$commit^{commit}" 2>/dev/null || git -C "$root" fetch -q --depth=1 origin "$commit"
git -C "$root" archive "$commit" install | tar -x -C "$out"
echo "previous release: $version ($commit) in $out"
