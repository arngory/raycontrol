#!/usr/bin/env bash
# Downloads the pinned slipstream-server release binary (arngory/slipstream,
# tag server-vX.Y.Z: static, musl) for an architecture and
# checks it against the SHA-256 pinned in deploy/versions.env (and the
# release's own SHA256SUMS). Used by CI and by the release workflow, which
# then ships it under raycontrol's signature.
#
#   scripts/slipstream-server.sh amd64 dist/slipstream-server
set -euo pipefail
cd "$(dirname "$0")/.."
arch=${1:?usage: slipstream-server.sh amd64|arm64 OUT}
out=${2:?usage: slipstream-server.sh amd64|arm64 OUT}
# shellcheck source=deploy/versions.env
. deploy/versions.env
case $arch in
amd64) want=$SLIPSTREAM_SERVER_SHA256_AMD64 ;;
arm64) want=$SLIPSTREAM_SERVER_SHA256_ARM64 ;;
*) echo "unknown architecture $arch" >&2; exit 1 ;;
esac
base="$SLIPSTREAM_SERVER_RELEASES/download/$SLIPSTREAM_SERVER_TAG"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
for f in "slipstream-server-linux-$arch" SHA256SUMS; do
	# GitHub's release storage has outages of minutes: wait them out.
	curl -fsSL --retry 8 --retry-delay 15 --retry-all-errors --retry-max-time 900 --connect-timeout 30 -o "$tmp/$f" "$base/$f"
done
(cd "$tmp" && grep " slipstream-server-linux-$arch\$" SHA256SUMS | sha256sum -c - >/dev/null)
echo "$want  $tmp/slipstream-server-linux-$arch" | sha256sum -c - >/dev/null || {
	echo "slipstream-server-linux-$arch does not match the hash pinned in deploy/versions.env" >&2
	exit 1
}
install -m 0755 "$tmp/slipstream-server-linux-$arch" "$out"
echo "slipstream-server $SLIPSTREAM_SERVER_TAG ($arch) verified"
