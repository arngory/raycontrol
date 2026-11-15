#!/usr/bin/env bash
# The release before, for test/relay/e2e.sh: its rayd as published (the
# archive verified as bootstrap.sh verifies it, test/install/previous.sh)
# and the api.test of its commit (from VERSIONS), whose exit and client
# e2e.sh runs against this tree's relay (spec/relay-update-remote-v1.md
# §12.2: an old rayd relay, an old exit).
#
#   test/relay/previous.sh OUT_DIR VERSION
#
# OUT_DIR/rayd and OUT_DIR/api.test. Run from the repository (git
# archive), go in PATH.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage="usage: previous.sh OUT_DIR VERSION"
out=${1:?$usage}
want=${2:?$usage}
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
"$here/../install/previous.sh" "$tmp/release" "$want" >/dev/null
cp "$tmp/release/rayd" "$out/rayd"
read -r _ version commit < <(grep -m1 '^raycontrol ' "$tmp/release/VERSIONS")
# previous.sh fetched the commit if this clone did not have it.
mkdir "$tmp/src"
root="$(git -C "$here" rev-parse --show-toplevel)"
git -C "$root" archive "$commit" | tar -x -C "$tmp/src"
(cd "$tmp/src" && go test -c -o "$out/api.test" ./internal/api)
echo "release before: $version ($commit): rayd and api.test in $out"
