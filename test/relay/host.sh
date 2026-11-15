#!/usr/bin/env bash
# A relay updated by its exit's word, on systemd hosts
# (spec/relay-update-remote-v1.md §12.2): an exit installed as
# test/install/run.sh installs a node, a relay by bootstrap.sh -relay, a
# mirror of GitHub's releases and a client, on an internal Docker network
# of a documentation range (the exit takes only public relay addresses).
# The releases are this tree built as test releases (-tags releasetest:
# rayctl checks them with RAYCONTROL_TEST_RELEASE_KEY), signed with a
# throwaway minisign key as test/install/handoff-release.sh signs its own;
# the relay's update unit takes them from the mirror (RAYCONTROL_MIRRORS
# in a drop-in: GitHub does not answer on this network).
#
#   test/relay/host.sh BIN_DIR
#
# BIN_DIR holds the data plane, as for test/install/run.sh (xray,
# niko-server, slipstream-server; linux/amd64). Needs go, minisign, jq
# and the image raycontrol-test:debian13 (test/install/prepare.sh), from
# which an image with sshd is made: a relay opens SSH on sshd's one port.
# On a cgroup v1 host, TEST_CGROUP_ROOT as for run.sh; TEST_KEEP=1 leaves
# the containers running.
#
# The relay starts on v0.90.0, the exit too, and with root's policy off.
#  1. The exit updates by hand to v0.91.0 (rayctl update -from: the status
#     an update by hand writes, §11 p. 1) and names it to the relay: with
#     remote off nothing moves, and the exit shows the relay off. Root on
#     the relay turns remote on: rayd relay writes the request, the path
#     unit runs it, the relay downloads, verifies, installs and checks
#     v0.91.0, and the exit shows it done; a client knocks the relay with
#     K_relay and reaches the exit's 443 through it.
# rayd relay writes at most one request every 10 minutes (§3.5, step 7),
# so the rest are written as it writes them, by its user in its directory:
# root's side is what they test, from the path unit on.
#  2. v0.92.0, whose rayspa does not run: rolled back, the relay forwards.
#  3. v0.93.0 while the exit does not answer the relay: the install waits
#     for the exit's snapshot in vain, rolled back on the snapshot it had.
#  4. v0.94.0, the update killed (kill -9) halfway: the runner rolls back.
#  5. v0.95.0, the update unit stopped halfway: the update rolls back.
#  6. v0.96.0, the relay's power cut halfway (docker kill): the recover
#     unit rolls back after the boot.
#  7. v0.97.0, which the mirror serves as v0.93.0's signed files: refused
#     (signature), nothing changed.
#  8. remote off: a request waits, nothing runs it.
# After each, the relay runs v0.91.0 and forwards.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=test/install/lib.sh
. "$root/test/install/lib.sh"

usage="usage: host.sh BIN_DIR"
dp="$(cd "${1:?$usage}" && pwd)"
for f in xray niko-server slipstream-server; do
	[[ -x $dp/$f ]] || die "$dp/$f is missing"
done
for c in go minisign jq; do
	command -v "$c" >/dev/null || die "$c is missing"
done
base="raycontrol-test:debian13"
image="raycontrol-test:debian13-sshd"
docker image inspect "$base" >/dev/null 2>&1 || die "no $base: test/install/prepare.sh debian13"
net="rc-relayhost"
subnet="203.0.113.0/24"
exit_ip=203.0.113.2
relay_ip=203.0.113.3
mirror_ip=203.0.113.4
client_ip=203.0.113.5
ex=rc-rh-exit
rl=rc-rh-relay
mirror=rc-rh-mirror
unit=raycontrol-relay-update.service
path=raycontrol-relay-update.path

work=""
cleanup() {
	docker rm -f "$ex" "$rl" "$mirror" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	if [[ -n $work ]]; then rm -rf "$work"; fi
}
cleanup
work="$(mktemp -d)"
if [[ -z ${TEST_KEEP:-} ]]; then
	trap cleanup EXIT
fi

xe() { docker exec "$ex" "$@"; }
xr() { docker exec "$rl" "$@"; }

fail() {
	echo "FAIL (relay host): $*" >&2
	if docker inspect "$rl" >/dev/null 2>&1; then
		echo "--- relay: status, journal" >&2
		xr cat /var/lib/raycontrol-update/status.json >&2 || true
		xr rayctl update status >&2 || true
		xr journalctl --no-pager -n 300 -u rayspa -u rayd-relay -u raycontrol-relay-update -u raycontrol-relay-recover >&2 || true
		xr systemctl --failed --no-pager >&2 || true
		xr nft list ruleset >&2 || true
	fi
	if docker inspect "$ex" >/dev/null 2>&1; then
		echo "--- exit" >&2
		xe rayctl update status >&2 || true
		xe journalctl --no-pager -n 100 -u rayd >&2 || true
	fi
	if docker inspect "$mirror" >/dev/null 2>&1; then
		echo "--- mirror" >&2
		docker logs --tail 50 "$mirror" >&2 || true
	fi
	exit 1
}

# wait_for SECONDS WHAT COMMAND...: until COMMAND succeeds.
wait_for() {
	local limit=$1 what=$2 t0=$SECONDS
	shift 2
	while ! "$@"; do
		((SECONDS - t0 < limit)) || fail "$what (after ${limit}s)"
		sleep 1
	done
}

# The image: the test system with sshd, which a relay needs; made again
# when the test system was.
base_id="$(docker image inspect -f '{{.Id}}' "$base")"
if [[ $(docker image inspect -f '{{index .Config.Labels "rc.base"}}' "$image" 2>/dev/null) != "$base_id" ]]; then
	log "making $image"
	net_args
	docker rm -f rc-prep-sshd >/dev/null 2>&1 || true
	docker run --name rc-prep-sshd "${NET_ARGS[@]}" "$base" sh -c "$EXTRA_CA_SETUP"'
		set -eu
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -q
		apt-get install -y -q --no-install-recommends openssh-server' >/dev/null
	docker commit -c 'CMD ["/sbin/init"]' -c "LABEL rc.base=$base_id" rc-prep-sshd "$image" >/dev/null
	docker rm rc-prep-sshd >/dev/null
fi

# The releases: this tree as each version, the data plane beside it, the
# archive and SHA256SUMS signed as a release is.
log "building the test releases"
mkdir -p "$work/tools" "$work/keys" "$work/rel" "$work/mirror"
(cd "$root" && CGO_ENABLED=0 go build -o "$work/tools/" ./test/relay/knock ./test/relay/mirror) || die "the test's tools"
minisign -G -W -p "$work/keys/k.pub" -s "$work/keys/k.key" >/dev/null
key="$(sed -n 2p "$work/keys/k.pub")"
# build DIR VERSION: this tree as VERSION, with the data plane.
build() {
	mkdir -p "$1"
	local c
	for c in rayd rayspa rayctl; do
		(cd "$root" && CGO_ENABLED=0 go build -trimpath -tags releasetest -ldflags "-s -w -X main.version=$2" -o "$1/$c" "./cmd/$c") ||
			die "building $c $2"
	done
	cp "$dp/xray" "$dp/niko-server" "$dp/slipstream-server" "$1/"
	printf 'raycontrol %s %s\n' "$2" "$(git -C "$root" rev-parse HEAD)" >"$1/VERSIONS"
}
# sign DIR VERSION: SHA256SUMS of the archive in DIR, signed for VERSION.
sign() {
	(cd "$1" && sha256sum raycontrol-linux-amd64.tar.gz >SHA256SUMS)
	minisign -S -s "$work/keys/k.key" -m "$1/SHA256SUMS" -x "$1/SHA256SUMS.minisig" -t "raycontrol $2" >/dev/null
}
# release VERSION [broken]: VERSION built and published in $work/rel
# (rayctl update -from) and on the mirror; broken: its rayspa does not run.
release() {
	local v=$1 b="$work/build/$1" r="$work/rel/$1"
	build "$b" "$v"
	if [[ ${2:-} == broken ]]; then
		# shellcheck disable=SC2016 # the script's own $1
		printf '#!/bin/sh\n# A rayspa that does not run (relay host test).\n[ "$1" = version ] && { echo %s; exit 0; }\necho "rayspa: broken" >&2\nexit 1\n' \
			"$v" >"$b/rayspa"
		chmod 755 "$b/rayspa"
	fi
	mkdir -p "$r"
	tar -czf "$r/raycontrol-linux-amd64.tar.gz" -C "$b" rayd rayspa rayctl xray niko-server slipstream-server VERSIONS
	sign "$r" "$v"
	rm -rf "$b"
	publish "$v" "$r"
}
# publish VERSION DIR: DIR's files on the mirror as VERSION's.
publish() {
	local m="$work/mirror/https:/github.com/arngory/raycontrol/releases/download/$1"
	mkdir -p "$m"
	cp "$2"/SHA256SUMS "$2"/SHA256SUMS.minisig "$2"/raycontrol-linux-amd64.tar.gz "$m/"
}
build "$work/old" v0.90.0
for v in v0.91.0 v0.93.0 v0.94.0 v0.95.0 v0.96.0; do release "$v"; done
release v0.92.0 broken
# Another signed release where v0.97.0 should be.
publish v0.97.0 "$work/rel/v0.93.0"

docker network create --internal --subnet "$subnet" "$net" >/dev/null
# boot NAME IP [docker run args...]: a systemd container on the network.
boot() {
	local name=$1 ip=$2 cgroup=()
	shift 2
	if [[ -n ${TEST_CGROUP_ROOT:-} ]]; then
		mkdir -p "$TEST_CGROUP_ROOT/$name"
		cgroup=(-v "$TEST_CGROUP_ROOT/$name:/sys/fs/cgroup:rw")
	fi
	docker run -d --name "$name" --hostname "${name#rc-rh-}" --privileged --cgroupns=private --network "$net" --ip "$ip" \
		--tmpfs /run --tmpfs /run/lock "${cgroup[@]}" "$@" "$image" /sbin/init >/dev/null
	up "$name"
}
# up NAME: its systemd has booted.
up() {
	local state="" t0=$SECONDS
	while ((SECONDS - t0 < 120)); do
		state="$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)"
		if [[ $state == running || $state == degraded ]]; then
			docker exec "$1" timeout 120 systemctl is-system-running --wait >/dev/null || true
			return 0
		fi
		sleep 1
	done
	fail "$1: systemd did not come up: ${state:-no answer}"
}

log "the mirror at $mirror_ip"
docker run -d --name "$mirror" --network "$net" --ip "$mirror_ip" -v "$work/mirror:/srv:ro" -v "$work/tools:/opt/t:ro" "$base" \
	/opt/t/mirror -dir /srv -addr :8080 >/dev/null

log "the exit at $exit_ip: v0.90.0, a node"
boot "$ex" "$exit_ip" -v "$work/old:/opt/old:ro" -v "$work/rel:/opt/rel:ro" -v "$root/install:/opt/install:ro"
# As run.sh: a DNS tunnel at the install, the rest after it.
xe env RAYCONTROL_LOCAL_DIR=/opt/old bash /opt/install/bootstrap.sh -host "$exit_ip" -domain example.test -admin 192.0.2.1 -services dnstt |
	sed -E 's/rcdev1:[A-Za-z0-9_-]+/rcdev1:<redacted>/g' >/dev/null || fail "bootstrap of the exit"
# The relay's feed is on the remote API; REALITY and Hysteria2 are what
# a relay forwards (TCP and UDP 443).
xe rayctl service add api api >/dev/null || fail "service add api"
xe rayctl service add reality reality >/dev/null || fail "service add reality"
xe rayctl service add hy2-obfs hy2o >/dev/null || fail "service add hy2-obfs"
xe rayctl apply >/dev/null || fail "rayctl apply on the exit"
xe rayctl user add alice -services reality,hy2o >/dev/null || fail "user add"
xe rayctl device add alice phone | grep '^rcdev1:' >"$work/phone.rcdev" || fail "device add"
xe rayctl relay add r1 "$relay_ip" >/dev/null || fail "relay add"
xe rayctl relay bundle -admin 192.0.2.1 -o /root/r1.bundle r1 2>/dev/null || fail "relay bundle"
xe cat /root/r1.bundle >"$work/r1.bundle"
# What reaches the exit's 443 from the relay's address: the relay's
# forwarding, masqueraded (nothing listens on TCP 443 here, REALITY waits
# for its site's certificate: the exit answers with a reset).
xe sh -c 'nft add table inet rctest && nft add chain inet rctest pre "{ type filter hook prerouting priority -500; }" &&
	nft add rule inet rctest pre ip saddr '"$relay_ip"' tcp dport 443 counter' || fail "the exit's counter"
from_relay() { xe nft list chain inet rctest pre | sed -n 's/.* counter packets \([0-9]*\) .*/\1/p'; }

log "the relay at $relay_ip: v0.90.0, bootstrap.sh -relay"
boot "$rl" "$relay_ip" -v "$work/old:/opt/old:ro" -v "$root/install:/opt/install:ro"
docker exec -i "$rl" sh -c 'umask 077 && cat > /root/r1.bundle' <"$work/r1.bundle"
xr env RAYCONTROL_LOCAL_DIR=/opt/old bash /opt/install/bootstrap.sh -relay /root/r1.bundle >"$work/bootstrap-relay.log" 2>&1 ||
	{ cat "$work/bootstrap-relay.log" >&2; fail "bootstrap -relay"; }
xr systemctl is-active --quiet rayspa.service rayd-relay.service || fail "the relay does not run"
# The relay's update unit takes the test releases, from the mirror: a
# drop-in of the test's (an update keeps the unit's own file, not it).
xr sh -c "mkdir -p /etc/systemd/system/$unit.d && printf '[Service]\nEnvironment=RAYCONTROL_MIRRORS=http://$mirror_ip:8080/\nEnvironment=RAYCONTROL_TEST_RELEASE_KEY=%s\n' '$key' \
	>/etc/systemd/system/$unit.d/test.conf && systemctl daemon-reload" || fail "the update unit's drop-in"

# The client: the subscription from the exit (its payload lists the
# relay), then the relay's 443 with no knock, closed.
docker run --rm --network "$net" --ip "$client_ip" -v "$work:/w:ro" "$base" /w/old/rayctl probe -payload "$(cat "$work/phone.rcdev")" \
	>"$work/probe.out" || fail "the subscription: $(grep -v '^payload ' "$work/probe.out")"
sed -n 's/^payload //p' "$work/probe.out" >"$work/payload.json"
client() { docker run --rm --network "$net" --ip "$client_ip" -v "$work:/w:ro" "$base" /w/tools/knock -bundle /w/phone.rcdev -payload /w/payload.json "$@"; }
client -closed || fail "the relay's 443 answered with no knock"
# forwards WHEN: a knock with K_relay at the relay, and the exit sees the
# relay's address on its 443.
forwards() {
	local before out
	before="$(from_relay)"
	out="$(client 2>&1)" || fail "no way through the relay $1: $out"
	(($(from_relay) > before)) || fail "the exit saw nothing from the relay $1: $out"
	echo "$out"
}
forwards "on v0.90.0"

# The relay's state.
rstatus() { xr cat /var/lib/raycontrol-update/status.json 2>/dev/null || true; }
# ended ID: root's status of update ID has its outcome.
ended() { rstatus | jq -e --arg id "$1" 'select(.id == $id) | .state | IN("done", "rolled_back", "failed")' >/dev/null 2>&1; }
# outcome ID WHAT JQ: root's status of update ID ends as the filter says.
outcome() {
	wait_for 600 "$2: no outcome" ended "$1"
	rstatus | jq -e --arg id "$1" "$3" >/dev/null || fail "$2: $(rstatus)"
	log "$2: $(rstatus | jq -c '{state, reason, error}')"
}
# runs VERSION: the relay runs it, its units as remote on has them, no
# update left unfinished.
runs() {
	local b v
	for b in rayd rayspa rayctl; do
		v="$(xr "/usr/local/bin/$b" version 2>&1 | sed -n 1p)"
		[[ ${v#rayctl } == *"$1" ]] || fail "$b is $v, not $1"
	done
	xr systemctl is-active --quiet rayspa.service rayd-relay.service || fail "rayspa or rayd relay does not run"
	if [[ ${2:-on} == on ]]; then
		wait_for 30 "the path unit is not active" xr systemctl is-active --quiet "$path"
	fi
	! xr test -e /var/lib/raycontrol-install/previous/relay.unfinished || fail "the update's mark is left"
}
# r1 JQ: the exit's GetUpdateStatus has relay r1 as the filter says.
r1() { xe rayctl -json update status 2>/dev/null | jq -e '.relays[] | select(.name == "r1") | '"$1" >/dev/null 2>&1; }
# request VERSION: a request as rayd relay writes it
# (nodeupdate.WriteRequest): by its user, in its directory, whole; its id.
request() {
	local id
	id="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
	# shellcheck disable=SC2016 # expands in the container
	xr runuser -u rayd -- sh -c 'umask 027 && printf "%s" "$1" >/var/lib/rayd-relay/.update-request.new &&
		mv /var/lib/rayd-relay/.update-request.new /var/lib/rayd-relay/update-request' _ \
		"{\"id\":\"$id\",\"kind\":\"exit\",\"version\":\"$1\",\"by\":\"exit\",\"at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" ||
		fail "the request for $1"
	echo "$id"
}
# midway: the update has changed the relay and runs its install, looked
# at often: the install takes seconds.
midway() {
	local t0=$SECONDS
	until xr pgrep -f 'rayctl install -relay' >/dev/null; do
		((SECONDS - t0 < 120)) || fail "the update did not reach its install"
		sleep 0.2
	done
}
# feeds: the relay holds its two feeds (rayspa, rayd relay), and the exit
# none that is gone: one the exit still counts would take the place of a
# new one (two at most), and the next install would wait in vain.
# The relay's two feeds (rayspa's, rayd relay's) are up on both ends. The
# exit may still hold the dead connections of the processes the last
# update restarted (their FIN dropped as the perimeter went down) until
# keepalive ends them: a new feed of a kind ends the old one's stream at
# once, so only the relay's own connections are counted.
feeds() {
	local e r
	e="$(xe ss -Htn state established dst "$relay_ip" | awk '{print $4}' | sort)"
	r="$(xr ss -Htn state established dst "$exit_ip" | awk '{print $3}' | sort)"
	[[ $(grep -c . <<<"$r") == 2 && -z $(comm -13 <(echo "$e") <(echo "$r")) ]]
}
log "1. the exit updates by hand to v0.91.0 and names it to the relay"
out="$(xe env RAYCONTROL_TEST_RELEASE_KEY="$key" rayctl update -from /opt/rel/v0.91.0 -yes 2>&1)" || fail "the exit's update: $out"
grep -q "handed over by the rayctl of v0.90.0" <<<"$out" || fail "the exit's update was not handed to v0.91.0's rayctl: $out"
exit_update="$(xe cat /var/lib/raycontrol-update/status.json | jq -r 'select(.state == "done" and .kind == "local" and .to == "v0.91.0") | .id')"
[[ -n $exit_update ]] || fail "the exit's status: $(xe cat /var/lib/raycontrol-update/status.json)"
# Root on the relay has not turned remote on: nothing moves.
wait_for 180 "the exit does not show r1 off" r1 '.state == "off" and .remote == false and .version == "v0.90.0" and .target == "v0.91.0"'
! xr test -e /var/lib/rayd-relay/update-request || fail "a request with remote off"
[[ -z $(rstatus) ]] || fail "root ran something with remote off: $(rstatus)"
runs v0.90.0 off
log "remote off: the relay stays on v0.90.0, the exit shows it off"
xr rayctl update remote on >/dev/null || fail "rayctl update remote on"
# rayd relay sees root's policy at its next look (a minute): its request,
# root's update unit, the release from the mirror.
outcome "$exit_update" "the update by the exit's word" '.state == "done" and .kind == "exit" and .by == "exit" and .from == "v0.90.0" and .to == "v0.91.0"'
runs v0.91.0
[[ $(docker logs "$mirror" 2>&1) == *"/v0.91.0/raycontrol-linux-amd64.tar.gz"* ]] || fail "the relay did not download v0.91.0 from the mirror"
wait_for 180 "the exit does not show r1 done" r1 '.state == "done" and .version == "v0.91.0" and .updateId == "'"$exit_update"'"'
log "the exit: $(xe rayctl update status | grep '^relay')"
forwards "on v0.91.0"
wait_for 120 "the relay's feeds" feeds

log "2. v0.92.0, whose rayspa does not run"
id="$(request v0.92.0)"
outcome "$id" "a rayspa that does not run" '.state == "rolled_back" and (.reason == "install" or .reason == "check") and .held == ["v0.92.0"]'
runs v0.91.0
forwards "after the rollback"

log "3. v0.93.0 while the exit does not answer the relay"
wait_for 120 "the relay's feeds" feeds
xe sh -c 'nft add table inet rcdown && nft add chain inet rcdown in "{ type filter hook input priority -400; }" &&
	nft add rule inet rcdown in ip saddr '"$relay_ip"' drop' || fail "the exit's drop"
id="$(request v0.93.0)"
# The install waited its 45 s for the exit's first snapshot.
outcome "$id" "the exit away" '.state == "rolled_back" and .reason == "install" and
	(.ended | sub("\\.[0-9]+"; "") | fromdate) - (.started | sub("\\.[0-9]+"; "") | fromdate) >= 45'
runs v0.91.0
xe nft delete table inet rcdown
forwards "after the rollback, the exit back"
# The feeds the drop cut stay open at the exit until it hears the relay
# again.
wait_for 120 "the relay's feeds after the exit came back" feeds

log "4. v0.94.0, the update killed halfway"
id="$(request v0.94.0)"
midway
xr pkill -9 -f 'rayctl update -(yes|from) ' || fail "nothing to kill"
outcome "$id" "the update killed" '.state == "rolled_back" and .reason == "interrupted" and (.error | test("rolled back by its runner"))'
runs v0.91.0
forwards "after the runner's rollback"
wait_for 120 "the relay's feeds" feeds

log "5. v0.95.0, the update unit stopped halfway"
id="$(request v0.95.0)"
midway
t0=$SECONDS
xr timeout 240 systemctl stop "$unit" || fail "systemctl stop $unit did not end within 4 min (TimeoutStopSec is 5)"
log "systemctl stop: $((SECONDS - t0)) s"
outcome "$id" "the unit stopped" '.state == "rolled_back" and .reason == "interrupted" and (.unfinished | not)'
runs v0.91.0
forwards "after the rollback at the stop"
wait_for 120 "the relay's feeds" feeds

log "6. v0.96.0, the relay's power cut halfway"
id="$(request v0.96.0)"
midway
docker kill "$rl" >/dev/null
docker start "$rl" >/dev/null
up "$rl"
outcome "$id" "the power cut" '.state == "rolled_back" and .reason == "interrupted" and (.error | test("at the boot"))'
runs v0.91.0
forwards "after the recover unit"
wait_for 120 "the relay's feeds" feeds

log "7. v0.97.0, which the mirror serves as v0.93.0's signed files"
id="$(request v0.97.0)"
outcome "$id" "another release" '.state == "failed" and .reason == "signature" and .untouched'
runs v0.91.0

log "8. remote off"
xr rayctl update remote off >/dev/null || fail "rayctl update remote off"
! xr systemctl is-active --quiet "$path" || fail "the path unit runs with remote off"
id="$(request v0.98.0)"
sleep 10
xr test -e /var/lib/rayd-relay/update-request || fail "the request went with remote off"
if ended "$id" || [[ $(rstatus | jq -r .reason) != signature ]]; then fail "root ran a request with remote off: $(rstatus)"; fi
runs v0.91.0 off
forwards "with remote off"
log "PASS: the relay updated by its exit's word, and back from every failure"
