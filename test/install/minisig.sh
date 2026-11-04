#!/usr/bin/env bash
# Checks the bootstrap's openssl-based minisign verification against real
# minisign signatures: prehashed and legacy pass; a changed file, trusted
# comment or key and a garbage signature fail. Needs minisign and openssl;
# with Go, rayctl update's verification is checked on the same files.
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

# The release named by the trusted comment: the one asked for, not older
# than MIN_VERSION (S-4: a mirror must not swap releases).
minisign -S -s k.key -m SHA256SUMS -x v090.minisig -t "raycontrol v0.9.0" >/dev/null
minisign -S -s k.key -m SHA256SUMS -x v080.minisig -t "raycontrol v0.8.0" >/dev/null
minisign -S -s k.key -m SHA256SUMS -x v0100.minisig -t "raycontrol v0.10.0" >/dev/null
expect pass "signed v0.9.0" SHA256SUMS v090.minisig "$key"
version() {
	local want=$1 name=$2 sig=$3 v
	if v="$(signed_version "$sig")" && check_version "$v" >/dev/null; then got=pass; else got=fail; fi
	if [[ $got == "$want" ]]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: $got, want $want"
		failures=$((failures + 1))
	fi
}
# shellcheck disable=SC2034 # read by check_version in bootstrap.sh
MIN_VERSION=v0.9.0
# shellcheck disable=SC2034 # read by check_version in bootstrap.sh
VERSION=latest
version pass "latest, v0.9.0" v090.minisig
version pass "latest, v0.10.0" v0100.minisig
version fail "latest, v0.8.0 is older than the minimum" v080.minisig
version fail "not a release" SHA256SUMS.minisig
VERSION=v0.9.0
version pass "asked v0.9.0, got v0.9.0" v090.minisig
version fail "asked v0.9.0, got v0.10.0" v0100.minisig
VERSION=latest
version_lt v0.9.0 v0.10.0 || { echo "FAIL v0.9.0 < v0.10.0"; failures=$((failures + 1)); }
! version_lt v0.10.0 v0.9.0 || { echo "FAIL v0.10.0 > v0.9.0"; failures=$((failures + 1)); }
! version_lt v1.0.0 v1.0.0 || { echo "FAIL v1.0.0 == v1.0.0"; failures=$((failures + 1)); }

[[ $failures -eq 0 ]] || die "$failures checks failed"
echo "minisign verification: all checks passed"

# The same signatures through rayctl update's verification (Go).
if command -v go >/dev/null; then
	(cd "$here/../.." && MINISIGN_TEST_DIR="$dir" go test -count=1 -run TestVerifyMinisign ./internal/release) ||
		die "Go verification of minisign signatures failed"
fi
