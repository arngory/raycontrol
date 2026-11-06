#!/usr/bin/env bash
# Fetches the latest release for test/install/upgrade.sh: its linux/amd64
# archive, verified as bootstrap.sh verifies it (minisign over SHA256SUMS),
# extracted to OUT_DIR, and the install/ directory of its commit (from
# VERSIONS) beside the binaries. Run from the repository (git archive).
#
#   test/install/previous.sh OUT_DIR
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install/bootstrap.sh
. "$here/../../install/bootstrap.sh"

out=${1:?usage: previous.sh OUT_DIR}
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/latest/download"
for f in raycontrol-linux-amd64.tar.gz SHA256SUMS SHA256SUMS.minisig; do
	curl -fsSL --retry 3 -o "$tmp/$f" "$base/$f"
done
verify_minisig "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.minisig" "$PUBKEY" || die "the release's signature does not verify"
(cd "$tmp" && grep ' raycontrol-linux-amd64.tar.gz$' SHA256SUMS | sha256sum -c --quiet -) || die "the archive's checksum does not match"
tar -xzf "$tmp/raycontrol-linux-amd64.tar.gz" -C "$out"
read -r _ version commit < <(grep -m1 '^raycontrol ' "$out/VERSIONS")
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "no commit in VERSIONS: $(head -1 "$out/VERSIONS")"
root="$(git -C "$here" rev-parse --show-toplevel)"
git -C "$root" cat-file -e "$commit^{commit}" 2>/dev/null || git -C "$root" fetch -q --depth=1 origin "$commit"
git -C "$root" archive "$commit" install | tar -x -C "$out"
echo "previous release: $version ($commit) in $out"
