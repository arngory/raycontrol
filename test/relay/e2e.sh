#!/usr/bin/env bash
# The relay with its real parts (spec/relay-v1.md §3.1), in three network
# namespaces: client 198.51.100.2 - relay 198.51.100.1 / 203.0.113.1 - exit
# 203.0.113.2 (documentation ranges: the exit takes only public relay
# addresses). The exit is a node with a relay r1; the relay runs the real
# rayspa with -relay and the bundle the exit made, takes its perimeter from
# the exit's API and forwards TCP and UDP 443 to it after a knock with the
# device's K_relay. Needs root, ip and nft.
#
#   sudo test/relay/e2e.sh [api.test rayspa]
#
# Without arguments it builds both (go in PATH).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="$(mktemp -d)"
ns=(rc-e2e-c rc-e2e-r rc-e2e-x)
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	for n in "${ns[@]}"; do ip netns del "$n" 2>/dev/null || true; done
	rm -rf "$bin"
}
trap cleanup EXIT

if [[ -n ${1:-} && -n ${2:-} ]]; then
	cp "$1" "$bin/api.test"
	cp "$2" "$bin/rayspa"
else
	(cd "$here/../.." && go test -c -o "$bin/api.test" ./internal/api && go build -o "$bin/rayspa" ./cmd/rayspa)
fi
mkdir -m 0700 "$bin/shared"

for n in "${ns[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add rc-e2e-c type veth peer name rc-e2e-rc
ip link add rc-e2e-x type veth peer name rc-e2e-rx
ip link set rc-e2e-c netns rc-e2e-c
ip link set rc-e2e-rc netns rc-e2e-r
ip link set rc-e2e-rx netns rc-e2e-r
ip link set rc-e2e-x netns rc-e2e-x
ip -n rc-e2e-c addr add 198.51.100.2/24 dev rc-e2e-c
ip -n rc-e2e-r addr add 198.51.100.1/24 dev rc-e2e-rc
ip -n rc-e2e-r addr add 203.0.113.1/24 dev rc-e2e-rx
ip -n rc-e2e-x addr add 203.0.113.2/24 dev rc-e2e-x
for l in "rc-e2e-c rc-e2e-c" "rc-e2e-r rc-e2e-rc" "rc-e2e-r rc-e2e-rx" "rc-e2e-x rc-e2e-x"; do
	read -r n d <<<"$l"
	ip -n "$n" link set "$d" up
done
ip -n rc-e2e-c route add default via 198.51.100.1
ip netns exec rc-e2e-r sysctl -q -w net.ipv4.ip_forward=1

role() { # namespace role [env...]
	local n=$1 r=$2
	shift 2
	ip netns exec "$n" env RAYCONTROL_RELAY_E2E_ROLE="$r" RAYCONTROL_RELAY_DIR="$bin/shared" "$@" \
		"$bin/api.test" -test.run TestRelayE2ERole -test.v
}
role rc-e2e-x exit RAYCONTROL_RELAY_EXIT=203.0.113.2 RAYCONTROL_RELAY_SEEN=203.0.113.1 >"$bin/exit.log" 2>&1 &
pids+=($!)
for _ in $(seq 100); do
	grep -q "exit ready" "$bin/exit.log" && break
	sleep 0.2
done
ip netns exec rc-e2e-r "$bin/rayspa" run -relay "$bin/shared/relay.bundle" -nflog-group 8 >"$bin/relay.log" 2>&1 &
pids+=($!)
for _ in $(seq 100); do
	grep -q "snapshot applied" "$bin/relay.log" && break
	sleep 0.2
done
if ! role rc-e2e-c client RAYCONTROL_RELAY_ADDR=198.51.100.1 RAYCONTROL_RELAY_SEEN=203.0.113.1; then
	echo "--- exit"; cat "$bin/exit.log"
	echo "--- relay (rayspa)"; cat "$bin/relay.log"
	echo "--- relay ruleset"; ip netns exec rc-e2e-r nft list ruleset
	exit 1
fi
echo "relay e2e: PASS"
