#!/usr/bin/env bash
# The DNS tunnels' front shares UDP 53 with systemd-resolved's stub
# (niko-server v0.8.2 binds with SO_REUSEADDR, as resolved does): on a host
# with the real resolved, such as the CI runner, the stub keeps answering
# beside the front, binds again when resolved restarts beside it, and the
# front answers on every other address.
#
# As root: test/dns53/resolved.sh NIKO_SERVER
set -euo pipefail
nikosrv=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
dir=$(mktemp -d)
front=
stopped=()
cleanup() {
	if [ -n "$front" ]; then
		kill "$front" 2>/dev/null || true
	fi
	for unit in "${stopped[@]}"; do
		systemctl start "$unit" || echo "could not start $unit again" >&2
	done
	rm -rf "$dir"
}
trap cleanup EXIT

q() { python3 -I "$here/q.py" "$@"; }
fail() {
	echo "FAIL: $*" >&2
	[ -f "$dir/front.log" ] && sed 's/^/front: /' "$dir/front.log" >&2
	ss -Hlunp 'sport = :53' >&2 || true
	exit 1
}
# bound ADDR: a UDP socket on ADDR:53. resolved binds its stub to lo, which
# ss prints as 127.0.0.53%lo:53.
bound() {
	local re=${1//./\\.}
	ss -Hlun 'sport = :53' | awk '{print $4}' | grep -Eq "^${re}(%[^:]+)?:53$"
}
waitfor() {
	for _ in $(seq 50); do
		bound "$1" && return 0
		sleep 0.2
	done
	return 1
}
expect() { # expect SERVER NAME WANT: the answer's rcode and count start with WANT
	local got
	got=$(q "$1" "$2") || fail "no answer from $1 for $2"
	case "$got" in "$3"*) ;; *) fail "$1 for $2: $got, want $3" ;; esac
}

bound 127.0.0.53 || fail "no systemd-resolved stub on 127.0.0.53"

# Another listener on an address's UDP 53 keeps the front off 0.0.0.0:53
# unless it binds with SO_REUSEADDR as resolved does. Some runner images run
# one: "dns-resolver" on 127.0.0.100:53 (the front failed to bind beside
# it). On a node rayctl check refuses that (port udp 53, required); here a
# listener that is a systemd service is stopped for the test and started
# again after it, and any other fails the test by name: what it checks is
# the stub, not the runner's proxy.
while read -r line; do
	addr=$(awk '{print $4}' <<<"$line")
	case "$addr" in 127.0.0.53%*:53 | 127.0.0.53:53 | 127.0.0.54:53) continue ;; esac
	pid=$(grep -o 'pid=[0-9]*' <<<"$line" | head -n1 | cut -d= -f2)
	unit=
	if [ -n "$pid" ] && [ "$pid" != 1 ]; then
		unit=$(ps -o unit= -p "$pid" | tr -d ' ')
	fi
	case "$unit" in
	*.service)
		[ "$unit" != systemd-resolved.service ] || continue
		echo "note: $unit listens on $addr (no SO_REUSEADDR): stopped for the test" >&2
		systemctl stop "$unit"
		stopped+=("$unit")
		;;
	*) fail "another listener on UDP 53 that is no service to stop: $line" ;;
	esac
done < <(ss -Hlunp 'sport = :53')

cat >"$dir/front.json" <<JSON
{"schema": 1, "role": "front", "log": {"level": "info"},
 "backends": {"dns": {"socket": "$dir/packet.sock", "mode": "packet", "uid": 0}},
 "dns": {"listen": ["0.0.0.0:53"], "zones": [{"zone": "t.example.invalid", "backend": "dns"}]}}
JSON
"$nikosrv" front -c "$dir/front.json" >"$dir/front.log" 2>&1 &
front=$!
waitfor 0.0.0.0 || fail "the front did not bind 0.0.0.0:53 beside the stub"

# The stub answers on its own address (resolved makes up localhost), the
# front everywhere else (REFUSED outside its zones).
expect 127.0.0.53 localhost "NOERROR 1"
expect 127.0.0.1 example.org REFUSED

# resolved restarts beside the front: before v0.8.2 its stub could not bind
# again while the front held the port.
systemctl restart systemd-resolved.service
waitfor 127.0.0.53 || fail "the stub did not come back beside the front"
expect 127.0.0.53 localhost "NOERROR 1"
expect 127.0.0.1 example.org REFUSED
kill -0 "$front" || fail "the front stopped"

echo "ok: the front shares UDP 53 with systemd-resolved's stub"
