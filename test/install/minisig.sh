#!/usr/bin/env bash
# Checks the bootstrap's openssl-based minisign verification against real
# minisign signatures: prehashed and legacy pass; a changed file, trusted
# comment or key and a garbage signature fail. Needs minisign and openssl.
#
#   test/install/minisig.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install/bootstrap.sh
. "$here/../../install/bootstrap.sh"

dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
cd "$dir"

minisign -G -W -p k.pub -s k.key >/dev/null
minisign -G -W -p other.pub -s other.key >/dev/null
key="$(sed -n 2p k.pub)"
other="$(sed -n 2p other.pub)"
printf 'abc  raycontrol-linux-amd64.tar.gz\n' >SHA256SUMS
cp SHA256SUMS legacy
minisign -S -s k.key -m SHA256SUMS -t "raycontrol test" >/dev/null
minisign -S -l -s k.key -m legacy -t "raycontrol test" >/dev/null
[[ $(sed -n 2p SHA256SUMS.minisig | base64 -d | head -c2) == ED ]] || die "minisign did not prehash"
[[ $(sed -n 2p legacy.minisig | base64 -d | head -c2) == Ed ]] || die "minisign -l did not sign legacy"

failures=0
expect() {
	local want=$1 name=$2
	shift 2
	if verify_minisig "$@"; then got=pass; else got=fail; fi
	if [[ $got == "$want" ]]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: $got, want $want"
		failures=$((failures + 1))
	fi
}

expect pass "prehashed" SHA256SUMS SHA256SUMS.minisig "$key"
expect pass "legacy" legacy legacy.minisig "$key"
expect fail "wrong key" SHA256SUMS SHA256SUMS.minisig "$other"

cp SHA256SUMS changed && printf 'x' >>changed
expect fail "changed file" changed SHA256SUMS.minisig "$key"
cp legacy changed && printf 'x' >>changed
expect fail "changed file, legacy" changed legacy.minisig "$key"

sed '3s/raycontrol test/raycontrol tesT/' SHA256SUMS.minisig >comment.minisig
expect fail "changed trusted comment" SHA256SUMS comment.minisig "$key"

{
	sed -n 1p SHA256SUMS.minisig
	head -c 74 /dev/urandom | base64 -w0
	echo
	sed -n '3,4p' SHA256SUMS.minisig
} >garbage.minisig
expect fail "garbage signature" SHA256SUMS garbage.minisig "$key"
expect fail "empty signature file" SHA256SUMS /dev/null "$key"

[[ $failures -eq 0 ]] || die "$failures checks failed"
echo "minisign verification: all checks passed"
