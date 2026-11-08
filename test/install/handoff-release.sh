#!/usr/bin/env bash
# Builds what the CI's upgrade job needs to test the update's handoff
# (docs/RELEASE.md): this tree twice, as v0.0.1 (the node's) and v0.0.2
# (a release), both with the releasetest tag (rayctl takes the release key
# from RAYCONTROL_TEST_RELEASE_KEY), and v0.0.2 as a release is published:
# the archive, SHA256SUMS signed with a throwaway minisign key, trusted
# comment "raycontrol v0.0.2". The data plane comes from BIN_DIR.
#
#   test/install/handoff-release.sh BIN_DIR OUT_DIR
#
# OUT_DIR/old: v0.0.1 with install/; OUT_DIR/new: v0.0.2; OUT_DIR/step/1:
# the release; OUT_DIR/key.pub: the public key's line.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
bin="$(cd "${1:?usage: handoff-release.sh BIN_DIR OUT_DIR}" && pwd)"
out=${2:?usage: handoff-release.sh BIN_DIR OUT_DIR}
mkdir -p "$out"
out="$(cd "$out" && pwd)"
command -v minisign >/dev/null || { echo "minisign is missing" >&2; exit 1; }

build() { # DIR VERSION
	mkdir -p "$1"
	for c in rayd rayspa rayctl; do
		(cd "$root" && CGO_ENABLED=0 go build -trimpath -tags releasetest -ldflags "-X main.version=$2" -o "$1/$c" "./cmd/$c")
	done
	for f in xray niko-server slipstream-server; do
		cp "$bin/$f" "$1/$f"
	done
	printf 'raycontrol %s %s\n' "$2" "$(git -C "$root" rev-parse HEAD)" >"$1/VERSIONS"
}
build "$out/old" v0.0.1
cp -r "$root/install" "$out/old/install"
build "$out/new" v0.0.2

rel="$out/step/1"
mkdir -p "$rel"
tar -czf "$rel/raycontrol-linux-amd64.tar.gz" -C "$out/new" rayd rayspa rayctl xray niko-server slipstream-server VERSIONS
(cd "$rel" && sha256sum raycontrol-linux-amd64.tar.gz >SHA256SUMS)
keys="$(mktemp -d)"
trap 'rm -rf "$keys"' EXIT
minisign -G -W -p "$keys/k.pub" -s "$keys/k.key" >/dev/null
minisign -S -s "$keys/k.key" -m "$rel/SHA256SUMS" -x "$rel/SHA256SUMS.minisig" -t "raycontrol v0.0.2" >/dev/null
sed -n 2p "$keys/k.pub" >"$out/key.pub"
echo "handoff release: v0.0.1 in $out/old, v0.0.2 in $out/new and, signed, in $rel"
