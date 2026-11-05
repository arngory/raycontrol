#!/usr/bin/env bash
# A relay in the kernel (spec/relay-v1.md §3.1) between three network
# namespaces: client 10.88.0.2 - relay 10.88.0.1 / 10.88.1.1 - exit 10.88.1.2.
# The relay forwards TCP and UDP 443 to the exit by DNAT only for an address
# with an SPA grant, masqueraded: the exit sees the relay. Needs root, ip
# and nft.
#
#   sudo test/relay/run.sh [perimeter.test]
#
# Without an argument it builds the perimeter test binary (go in PATH).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bin="$(mktemp -d)"
ns=(rc-relay-c rc-relay-r rc-relay-x)
pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	for n in "${ns[@]}"; do ip netns del "$n" 2>/dev/null || true; done
	rm -rf "$bin"
}
trap cleanup EXIT

if [[ -n ${1:-} ]]; then
	cp "$1" "$bin/perimeter.test"
else
	(cd "$here/../.." && go test -c -o "$bin/perimeter.test" ./internal/perimeter)
fi

for n in "${ns[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add rc-c type veth peer name rc-rc
ip link add rc-x type veth peer name rc-rx
ip link set rc-c netns rc-relay-c
ip link set rc-rc netns rc-relay-r
ip link set rc-rx netns rc-relay-r
ip link set rc-x netns rc-relay-x
ip -n rc-relay-c addr add 10.88.0.2/24 dev rc-c
ip -n rc-relay-r addr add 10.88.0.1/24 dev rc-rc
ip -n rc-relay-r addr add 10.88.1.1/24 dev rc-rx
ip -n rc-relay-x addr add 10.88.1.2/24 dev rc-x
for l in "rc-relay-c rc-c" "rc-relay-r rc-rc" "rc-relay-r rc-rx" "rc-relay-x rc-x"; do
	read -r n d <<<"$l"
	ip -n "$n" link set "$d" up
done
ip -n rc-relay-c route add default via 10.88.0.1
ip netns exec rc-relay-r sysctl -q -w net.ipv4.ip_forward=1

run() { # namespace role [env...]
	local n=$1 role=$2
	shift 2
	ip netns exec "$n" env RAYCONTROL_RELAY_ROLE="$role" "$@" "$bin/perimeter.test" -test.run TestRelayRole -test.v
}
run rc-relay-x exit >"$bin/exit.log" 2>&1 &
pids+=($!)
run rc-relay-r relay RAYCONTROL_RELAY_EXIT=10.88.1.2 >"$bin/relay.log" 2>&1 &
pids+=($!)
for _ in $(seq 50); do
	grep -q "relay ready" "$bin/relay.log" && grep -q "exit ready" "$bin/exit.log" && break
	sleep 0.2
done
if ! run rc-relay-c client RAYCONTROL_RELAY_ADDR=10.88.0.1 RAYCONTROL_RELAY_SEEN=10.88.1.1; then
	echo "--- relay"; cat "$bin/relay.log"
	echo "--- exit"; cat "$bin/exit.log"
	echo "--- relay ruleset"; ip netns exec rc-relay-r nft list ruleset
	exit 1
fi
echo "relay: PASS"
