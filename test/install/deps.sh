#!/usr/bin/env bash
# Runs the bootstrap's install_deps on the bare base image of DISTRO and
# checks that every command the node needs is there afterwards.
#
#   test/install/deps.sh rocky10
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/install/lib.sh
. "$here/lib.sh"

distro=${1:?usage: deps.sh DISTRO}
base=${BASE[$distro]:-}
[[ -n $base ]] || die "unknown distro $distro (${!BASE[*]})"

# shellcheck disable=SC2016
script=$EXTRA_CA_SETUP'
set -eu
. /i/bootstrap.sh
before=""
for c in curl openssl nft pkcheck conntrack; do command -v "$c" >/dev/null || before="$before $c"; done
install_deps
for c in curl openssl nft pkcheck conntrack sha256sum tar base64 mktemp; do
	command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 1; }
done
echo "deps ok: $(nft --version), $(openssl version)"
# A refused host gets back what it had: what was missing is missing again.
remove_deps
for c in $before; do
	if command -v "$c" >/dev/null; then echo "remove_deps left $c" >&2; exit 1; fi
done
echo "removed again:$before"
'
net_args
log "install_deps on $base"
docker run --rm "${NET_ARGS[@]}" -v "$here/../../install:/i:ro" "$base" bash -c "$script"
