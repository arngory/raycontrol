#!/usr/bin/env bash
# Runs bootstrap.sh's main() with the host's paths moved into a temporary
# tree, the download, the signature and the packages stubbed, and checks
# which installs the guard against going back refuses (going_back, R4-43):
# an older release over a node's database whose rayd names a newer one, or
# names none, refused (with -check too, exit 1); the same or a newer one,
# and a host with no database, installed.
#
#   test/install/bootstrap-guard.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/../../install/bootstrap.sh"
base="$(mktemp -d)"
trap 'rm -rf "$base"' EXIT
case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*)
	echo "skip: no release for $(uname -m)"
	exit 0
	;;
esac

failures=0
# run_case NAME WANT SIGNED RAYD DB ARGS...: WANT is installed, refused (by
# the guard, its message) or checked (-check passed); RAYD the installed
# rayd's version, none or fail.
run_case() {
	local name=$1 want=$2 fake_signed=$3 rayd=$4 db=$5
	shift 5
	local t="$base/$name"
	mkdir -p "$t/state" "$t/bin" "$t/systemd/system" "$t/fix/pkg"
	# shellcheck disable=SC2016 # sed's own $, not the shell's
	sed -e "s#/run/systemd/system#$t/systemd/system#g" -e "s#/var/lib/raycontrol#$t/state#g" \
		-e "s#/usr/local/bin#$t/bin#g" -e 's#^\t\[\[ \$EUID -eq 0 \]\] || die "run as root"$#\t:#' "$src" >"$t/bootstrap.sh"
	if [[ $db == yes ]]; then : >"$t/state/rayd.db"; fi
	# shellcheck disable=SC2016 # the stub's own $1
	case $rayd in
	none) ;;
	fail) printf '#!/bin/sh\nexit 1\n' >"$t/bin/rayd" ;;
	*) printf '#!/bin/sh\n[ "$1" = version ] && echo %s\n' "$rayd" >"$t/bin/rayd" ;;
	esac
	[[ ! -e $t/bin/rayd ]] || chmod +x "$t/bin/rayd"
	for b in rayd rayspa; do printf '#!/bin/sh\necho %s-new\n' "$b" >"$t/fix/pkg/$b"; done
	printf '#!/bin/sh\necho "rayctl $*" >>%s/rayctl.log\n' "$t" >"$t/fix/pkg/rayctl"
	chmod +x "$t/fix/pkg/"*
	tar -czf "$t/fix/raycontrol-linux-$arch.tar.gz" -C "$t/fix/pkg" rayd rayspa rayctl
	(cd "$t/fix" && sha256sum "raycontrol-linux-$arch.tar.gz" >SHA256SUMS && : >SHA256SUMS.minisig)
	(
		# shellcheck disable=SC1090,SC1091 # the copy made above
		. "$t/bootstrap.sh"
		# shellcheck disable=SC2329 # bootstrap.sh's main calls them
		fetch() { cp "$t/fix/$(basename "$1")" "$2"; }
		# shellcheck disable=SC2329
		verify_minisig() { return 0; }
		# shellcheck disable=SC2329
		signed_version() { echo "$fake_signed"; }
		# shellcheck disable=SC2329
		install_deps() { :; }
		main "$@"
	) >"$t/out" 2>&1
	local rc=$? got
	if grep -q '^rayctl install' "$t/rayctl.log" 2>/dev/null; then
		got=installed
	elif ((rc == 0)) && grep -q '^rayctl check' "$t/rayctl.log" 2>/dev/null; then
		got=checked
	elif ((rc != 0)) && grep -q 'goes back' "$t/out"; then
		got=refused
	else
		got="neither (exit $rc)"
	fi
	if [[ $got == "$want" ]]; then
		echo "ok   $name: $got"
	else
		echo "FAIL $name: $got, want $want"
		sed 's/^/     /' "$t/out"
		failures=$((failures + 1))
	fi
}

run_case fresh installed v0.30.2 none no -host 192.0.2.1
run_case back-over-v0.31.0 refused v0.30.2 v0.31.0 yes -host 192.0.2.1
run_case same-v0.31.0 installed v0.31.0 v0.31.0 yes -host 192.0.2.1
run_case forward installed v0.31.1 v0.31.0 yes -host 192.0.2.1
run_case keep-state-no-rayd refused v0.30.2 none yes -host 192.0.2.1
run_case keep-state-no-rayd-v0.30.9 refused v0.30.9 none yes -host 192.0.2.1 # the top of the v0.30 line
run_case keep-state-no-rayd-v0.31.0 installed v0.31.0 none yes -host 192.0.2.1
run_case rayd-fails refused v0.30.2 fail yes -host 192.0.2.1
run_case rayd-dev refused v0.30.2 dev yes -host 192.0.2.1
run_case rayd-sha refused v0.30.2 0123456789ab yes -host 192.0.2.1
run_case rayd-rc refused v0.30.2 v0.31.0-rc.1 yes -host 192.0.2.1
run_case check-back refused v0.30.2 v0.31.0 yes -check -host 192.0.2.1
run_case check-same checked v0.31.0 v0.31.0 yes -check -host 192.0.2.1

if ((failures > 0)); then
	echo "bootstrap guard: $failures checks failed"
	exit 1
fi
echo "bootstrap guard: all checks passed"
