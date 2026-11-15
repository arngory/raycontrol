#!/usr/bin/env bash
# The relay with its real parts (spec/relay-v1.md §3.1), in three network
# namespaces: client 198.51.100.2 - relay 198.51.100.1 / 203.0.113.1 - exit
# 203.0.113.2 (documentation ranges: the exit takes only public relay
# addresses). The exit is a node with a relay r1; the relay runs the real
# rayspa with -relay and the bundle the exit made, takes its perimeter from
# the exit's API and forwards TCP and UDP 443 to it after a knock with the
# device's K_relay. It runs the real rayd relay too, the relay's probe
# endpoint (§9): down, the UDP echo and a report passed on to the exit.
#
# And the relay's update by its exit's word (spec/relay-update-remote-v1.md
# §12.2): the exit runs a release one minor version past rayd's, its last
# update done, and names it to the relay. rayd relay, with root's update
# files in a directory of the test's (-update-dir, -update-request: the
# host's /var/lib stays untouched), writes no request while root's policy
# is off and the exit shows the relay off; with remote on it writes the
# request (kind exit, the exit's update id and release, by exit), the exit
# shows it requested, and then what root's status says (written here as
# the relay's runner would), its error redacted. With the release before
# (OLD_API_TEST, OLD_RAYD, test/relay/previous.sh): the old rayd relay
# takes no offers and says nothing, the exit shows the relay unknown; an
# old exit has no ReportUpdate (Unimplemented) and the new rayd relay is
# quiet, and the relay forwards and answers probes as ever.
# Needs root, ip, nft and jq.
#
#   sudo test/relay/e2e.sh [api.test rayspa rayd [OLD_API_TEST OLD_RAYD]]
#
# rayd is a release build (-ldflags "-X main.version=vX.Y.Z"): a build that
# is no release updates by hand, and takes no offer. Without arguments it
# builds all three, rayd as v0.90.0 (go in PATH); without the old release's
# two the checks against it are left out, said so.
# shellcheck disable=SC2016 # $v, $x, $id in single quotes: jq's variables
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

if [[ -n ${1:-} && -n ${2:-} && -n ${3:-} ]]; then
	cp "$1" "$bin/api.test"
	cp "$2" "$bin/rayspa"
	cp "$3" "$bin/rayd"
else
	(cd "$here/../.." && go test -c -o "$bin/api.test" ./internal/api && go build -o "$bin/rayspa" ./cmd/rayspa &&
		go build -ldflags "-X main.version=v0.90.0" -o "$bin/rayd" ./cmd/rayd)
fi
old=""
if [[ -n ${4:-} && -n ${5:-} ]]; then
	old="$bin/old"
	mkdir "$old"
	cp "$4" "$old/api.test"
	cp "$5" "$old/rayd"
fi
command -v jq >/dev/null || { echo "relay e2e: jq is missing" >&2; exit 1; }
relay_version="$("$bin/rayd" version)"
if [[ ! $relay_version =~ ^v([0-9]+)\.([0-9]+)\.[0-9]+$ ]]; then
	echo "relay e2e: rayd is $relay_version, not a release: build it with -ldflags \"-X main.version=vX.Y.Z\"" >&2
	exit 1
fi
exit_version="v${BASH_REMATCH[1]}.$((BASH_REMATCH[2] + 1)).0"

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
# The exit could answer the client directly: the relay must still not route.
ip -n rc-e2e-x route add 198.51.100.0/24 via 203.0.113.1
ip netns exec rc-e2e-r sysctl -q -w net.ipv4.ip_forward=1

fail() {
	echo "relay e2e: FAIL: $*" >&2
	echo "--- exit"; cat "$bin/exit.log"
	echo "--- relay (rayspa)"; cat "$bin/relay.log"
	echo "--- relay (rayd relay)"; cat "$bin/probe.log" 2>/dev/null || true
	echo "--- relay ruleset"; ip netns exec rc-e2e-r nft list ruleset
	if [[ -f $bin/shared/update-status.json ]]; then echo "--- the exit's update status"; jq . "$bin/shared/update-status.json"; fi
	exit 1
}

# wait_for SECONDS WHAT COMMAND...: until COMMAND succeeds.
wait_for() {
	local limit=$1 what=$2
	shift 2
	for _ in $(seq $((limit * 5))); do
		if "$@"; then return 0; fi
		sleep 0.2
	done
	fail "$what (after ${limit}s)"
}

role() { # api.test namespace role [env...]
	local test=$1 n=$2 r=$3
	shift 3
	ip netns exec "$n" env RAYCONTROL_RELAY_E2E_ROLE="$r" RAYCONTROL_RELAY_DIR="$bin/shared" "$@" \
		"$test" -test.run TestRelayE2ERole -test.v
}

# start_exit API_TEST [env...]: an exit afresh, its bundle for r1 in shared.
exit_pid=""
start_exit() {
	local test=$1
	shift
	rm -rf "$bin/shared"
	mkdir -m 0700 "$bin/shared"
	# Not by role: the process itself, to stop it.
	ip netns exec rc-e2e-x env RAYCONTROL_RELAY_E2E_ROLE=exit RAYCONTROL_RELAY_DIR="$bin/shared" RAYCONTROL_RELAY_EXIT=203.0.113.2 \
		RAYCONTROL_RELAY_SEEN=203.0.113.1 "$@" "$test" -test.run TestRelayE2ERole -test.v >"$bin/exit.log" 2>&1 &
	exit_pid=$!
	pids+=("$exit_pid")
	wait_for 20 "the exit did not come up" grep -q "exit ready" "$bin/exit.log"
}

rayspa_pid=""
start_rayspa() {
	ip netns exec rc-e2e-r "$bin/rayspa" run -relay "$bin/shared/relay.bundle" -nflog-group 8 >"$bin/relay.log" 2>&1 &
	rayspa_pid=$!
	pids+=("$rayspa_pid")
	wait_for 20 "rayspa applied no snapshot" grep -q "snapshot applied" "$bin/relay.log"
}

# start_probe RAYD [args...]: the relay's probe endpoint, the same bundle,
# its own feed from the exit.
probe_pid=""
start_probe() {
	local rayd=$1
	shift
	ip netns exec rc-e2e-r "$rayd" relay -bundle "$bin/shared/relay.bundle" "$@" >"$bin/probe.log" 2>&1 &
	probe_pid=$!
	pids+=("$probe_pid")
}

stop() {
	local p
	for p in "$@"; do
		[[ -n $p ]] || continue
		kill "$p" 2>/dev/null || true
		wait "$p" 2>/dev/null || true
	done
}

# Root's update directory on the relay and rayd relay's request, the
# test's own.
upd="$bin/update"
updates() {
	rm -rf "$upd"
	mkdir -p "$upd/root" "$upd/rayd-relay"
	probe_update=(-update-request "$upd/rayd-relay/update-request" -update-dir "$upd/root")
}
request="$upd/rayd-relay/update-request"

# r1 JQ: whether the exit's GetUpdateStatus has relay r1 as the jq filter
# says ($v the relay's version, $x the exit's, $id the exit's update).
r1() {
	jq -e --arg v "$relay_version" --arg x "$exit_version" --arg id "${update_id:-}" ".relays[] | select(.name == \"r1\") | $1" \
		"$bin/shared/update-status.json" >/dev/null 2>&1
}

client() { # api.test
	if ! role "$1" rc-e2e-c client RAYCONTROL_RELAY_ADDR=198.51.100.1 RAYCONTROL_RELAY_SEEN=203.0.113.1 RAYCONTROL_RELAY_EXIT=203.0.113.2; then
		fail "the client through the relay"
	fi
}

# The exit, one minor version past the relay, its last update done: it
# names its release to r1.
start_exit "$bin/api.test" RAYCONTROL_RELAY_E2E_VERSION="$exit_version"
start_rayspa
update_id="$(sed -n "s/^exit: $exit_version, its update \([0-9a-f]*\) done$/\1/p" "$bin/exit.log")"
[[ -n $update_id ]] || fail "the exit's update id"
wait_for 10 "no update status from the exit" test -s "$bin/shared/update-status.json"

if [[ -n $old ]]; then
	# rayd relay of the release before: its feed takes no offers, it says
	# nothing of updates; the exit has the relay unknown, heard of all
	# the same.
	start_probe "$old/rayd"
	wait_for 30 "the old rayd relay holds no feed" grep -q "rayd relay up" "$bin/exit.log"
	sleep 3 # a rayd relay that takes offers has reported by now
	r1 '.state == "unknown" and .version == "" and .seen_at != "0"' || fail "r1 with the old rayd relay: not unknown"
	echo "relay e2e: rayd relay $("$old/rayd" version): the exit names it nothing, and has it unknown"
	stop "$probe_pid"
else
	echo "relay e2e: no release before given (OLD_API_TEST OLD_RAYD): the old rayd relay and the old exit not checked"
fi

# This rayd relay, root's policy not on (no file: off).
updates
start_probe "$bin/rayd" "${probe_update[@]}"
wait_for 30 "the exit does not have r1 off" r1 '.state == "off" and .remote == false and .version == $v and .target == $x'
grep -q "relay update: the exit's offer not taken" "$bin/probe.log" || fail "rayd relay does not say why it took no offer"
[[ ! -e $request ]] || fail "a request with remote off: $(cat "$request")"
echo "relay e2e: remote off: the offer of $exit_version taken by no request, the exit has r1 off"
wait_for 30 "rayd relay holds no feed" grep -q "rayd relay up" "$bin/exit.log"
client "$bin/api.test"

# Root turns remote on: rayd relay sees it at its next look (a minute)
# and asks root for the exit's release.
cat >"$upd/root/policy.json" <<'EOF'
{"remote": "on", "auto": "off", "window": "03:00-05:00"}
EOF
wait_for 90 "rayd relay wrote no request with remote on" test -s "$request"
jq -e --arg id "$update_id" --arg x "$exit_version" '.id == $id and .kind == "exit" and .version == $x and .by == "exit" and
	(.at | sub("\\.[0-9]+"; "") | fromdateiso8601) > now - 300' "$request" >/dev/null || fail "the request: $(cat "$request")"
wait_for 30 "the exit does not have r1 requested" r1 '.state == "requested" and .remote == true and .update_id == $id and .target == $x'
echo "relay e2e: remote on: rayd relay asked root for $exit_version ($(cat "$request")), the exit has r1 requested"

# Root takes it, as the relay's runner does: its status before the
# request goes, then how the update ended. The error names the exit and
# the relay's admin address, which neither the report nor the exit shows.
at="$(jq -r .at "$request")"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status() { # state reason error
	jq -n --arg id "$update_id" --arg from "$relay_version" --arg x "$exit_version" --arg at "$at" --arg started "$started" \
		--arg state "$1" --arg reason "$2" --arg error "$3" --arg ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{id: $id, state: $state, from: $from, to: $x, target: $x, release: $x, by: "exit", kind: "exit", requested: $at, started: $started}
		+ (if $state == "running" then {ended: "0001-01-01T00:00:00Z"} else {ended: $ended, reason: $reason, error: $error, held: [$x]} end)' \
		>"$upd/root/status.json.new"
	mv "$upd/root/status.json.new" "$upd/root/status.json"
}
status running "" ""
rm "$request"
wait_for 30 "the exit does not have r1 running" r1 '.state == "running" and .update_id == $id'
status rolled_back check "after the install: rayspa took no perimeter from its exit 203.0.113.2 (API port 2024); SSH from 192.0.2.1/32 only"
wait_for 30 "the exit does not have r1 rolled back" r1 '.state == "rolled_back" and .reason == "check" and .update_id == $id'
r1 '.error | test("rayspa took no perimeter") and (test("203\\.0\\.113\\.2|192\\.0\\.2\\.1") | not)' ||
	fail "the relay's error at the exit: $(jq -r '.relays[0].error' "$bin/shared/update-status.json")"
echo "relay e2e: root's running and rolled back reach the exit, the error without addresses: $(jq -r '.relays[0].error' "$bin/shared/update-status.json")"
stop "$probe_pid" "$rayspa_pid" "$exit_pid"

if [[ -n $old ]]; then
	# The exit of the release before: no offers, no ReportUpdate. This
	# rayd relay, remote on, asks nothing and stops calling; the relay
	# forwards and its probe endpoint works as ever.
	start_exit "$old/api.test"
	start_rayspa
	updates
	cat >"$upd/root/policy.json" <<'EOF'
{"remote": "on", "auto": "off", "window": "03:00-05:00"}
EOF
	start_probe "$bin/rayd" "${probe_update[@]}"
	wait_for 30 "rayd relay holds no feed of the old exit" grep -q "rayd relay up" "$bin/exit.log"
	client "$old/api.test"
	wait_for 30 "rayd relay does not say that the old exit takes no reports" grep -q "the exit takes no reports (older than this relay)" "$bin/probe.log"
	[[ $(grep -c "relay update: report not taken" "$bin/probe.log") == 0 ]] || fail "rayd relay calls the old exit's ReportUpdate again"
	[[ ! -e $request ]] || fail "a request with the old exit: $(cat "$request")"
	echo "relay e2e: the exit before (Unimplemented): rayd relay quiet, the relay forwards"
	stop "$probe_pid" "$rayspa_pid" "$exit_pid"
fi
echo "relay e2e: PASS"
