#!/usr/bin/env bash
# The update from the previous release, as a node in the field takes it:
# a node installed by the previous release's bootstrap.sh and set up by its
# rayctl is updated by that rayctl to this build (rayctl update -local),
# then checked like a client would and against a node this build installs
# afresh with the same steps. Both must come out the same: units, users,
# installed files, the rendered configuration (names, modes, owners, the
# structure of its JSON) and the subscription (profiles, link parameters,
# the payload's fields), values aside. A difference is a configuration
# that only a fresh install gets right.
#
#   test/install/upgrade.sh DISTRO BIN_DIR OLD_DIR [STEP_DIR]
#
# BIN_DIR as for run.sh, with slipstream-server (the archive has it since
# v0.16.0). OLD_DIR holds the previous release's binaries (rayd, rayspa,
# rayctl, niko-server, xray) and its install/ directory.
#
# STEP_DIR, when given, holds releases as published, one a subdirectory
# (SHA256SUMS, its signature, the archive: previous.sh RELEASE_DIR), taken
# in the order of their names: the node's rayctl updates to each in turn
# (rayctl update -from: verified and extracted by the rayctl on the node,
# as from GitHub), and the last one's rayctl updates to this build. That
# is the path docs/RELEASE.md gives a node whose rayctl cannot take the
# latest archive itself (before v0.15.0: names it does not know,
# slipstream-server since v0.16.0): v0.15.0, then the latest release.
#
# The handoff (test/install/handoff-release.sh): TEST_RELEASE_KEY is the
# key a releasetest build of rayctl checks the steps with;
# EXPECT_HANDOFF=1 wants each step done by the release's own rayctl;
# STEPS_ONLY=1 ends with the steps, BIN_DIR being the last one.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/install/lib.sh
. "$here/lib.sh"

usage="usage: upgrade.sh DISTRO BIN_DIR OLD_DIR [STEP_DIR]"
distro=${1:?$usage}
bin="$(cd "${2:?$usage}" && pwd)"
old="$(cd "${3:?$usage}" && pwd)"
step=""
steps=()
if [[ -n ${4:-} ]]; then
	step="$(cd "$4" && pwd)"
	for d in "$step"/*/; do
		d=$(basename "$d")
		for f in SHA256SUMS SHA256SUMS.minisig raycontrol-linux-amd64.tar.gz; do
			[[ -f $step/$d/$f ]] || die "$step/$d/$f is missing"
		done
		steps+=("$d")
	done
	((${#steps[@]} > 0)) || die "no releases in $step"
fi
image="raycontrol-test:$distro"
net="rc-upgrade-$distro"
for f in rayd rayspa rayctl niko-server xray; do
	[[ -x $bin/$f ]] || die "$bin/$f is missing"
	[[ -x $old/$f ]] || die "$old/$f is missing"
done
[[ -x $bin/slipstream-server ]] || die "$bin/slipstream-server is missing"
[[ -f $old/install/bootstrap.sh ]] || die "$old/install/bootstrap.sh is missing"
work=""
node=""

x() { docker exec "$node" "$@"; }
# xk runs a command with the test release key, if any.
xk() { docker exec ${TEST_RELEASE_KEY:+-e "RAYCONTROL_TEST_RELEASE_KEY=$TEST_RELEASE_KEY"} "$node" "$@"; }

fail() {
	echo "FAIL ($distro, upgrade): $*" >&2
	if [[ -n $node ]]; then
		x journalctl --no-pager -n 200 -u rayd -u rayspa -u 'niko-*' >&2 || true
		x systemctl --failed --no-pager >&2 || true
	fi
	exit 1
}

cleanup() {
	docker rm -f "rc-upgraded-$distro" "rc-fresh-$distro" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	if [[ -n $work ]]; then rm -rf "$work"; fi
}
cleanup
work="$(mktemp -d)"
if [[ -z ${TEST_KEEP:-} ]]; then
	trap cleanup EXIT
fi

# boot starts a node container NAME with this build at /opt/rc and the
# previous release at /opt/old, and sets $node and $ip.
boot() {
	node=$1
	local cgroup=() state=""
	if [[ -n ${TEST_CGROUP_ROOT:-} ]]; then
		mkdir -p "$TEST_CGROUP_ROOT/$node"
		cgroup=(-v "$TEST_CGROUP_ROOT/$node:/sys/fs/cgroup:rw")
	fi
	docker run -d --name "$node" --hostname node --privileged --cgroupns=private --network "$net" \
		--tmpfs /run --tmpfs /run/lock "${cgroup[@]}" \
		-v "$bin:/opt/rc:ro" -v "$old:/opt/old:ro" -v "$here/../../install:/opt/install:ro" \
		-v "${step:-$old}:/opt/step:ro" "$image" /sbin/init >/dev/null
	for _ in $(seq 90); do
		state="$(x systemctl is-system-running 2>/dev/null || true)"
		if [[ $state == running || $state == degraded ]]; then
			break
		fi
		sleep 1
	done
	[[ $state == running || $state == degraded ]] || fail "systemd did not come up: ${state:-no answer}"
	x timeout 120 systemctl is-system-running --wait >/dev/null || true
	ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node")"
}

wait_active() {
	local u
	for u in "$@"; do
		for _ in $(seq 30); do
			if x systemctl is-active --quiet "$u"; then
				continue 2
			fi
			sleep 1
		done
		fail "$u is not active"
	done
}

# install_node DIR: bootstrap.sh of DIR/install with the binaries of DIR,
# then the same services, user and device on both nodes. The device's
# bundle goes to $work/$node.bundle.
install_node() {
	local dir=$1
	local inst=/opt/install
	[[ $dir == /opt/old ]] && inst=/opt/old/install
	x env RAYCONTROL_LOCAL_DIR="$dir" bash "$inst/bootstrap.sh" -host "$ip" -domain example.test -admin 192.0.2.1 -services dnstt |
		sed -E 's/rcdev1:[A-Za-z0-9_-]+/rcdev1:<redacted>/g' >/dev/null || fail "bootstrap from $dir"
	wait_active rayd.service rayspa.service
	x rayctl service add masterdns mdns >/dev/null || fail "service add masterdns"
	x rayctl service set dns auth=required >/dev/null || fail "service set dns auth"
	x rayctl service add hy2-obfs hy2o >/dev/null || fail "service add hy2-obfs"
	x rayctl service add api api >/dev/null || fail "service add api"
	# Waiting for the site's certificate (none on this network): units and
	# users are there, the processes are not.
	x rayctl service add reality reality >/dev/null || fail "service add reality"
	x rayctl service add naive naive >/dev/null || fail "service add naive"
	x rayctl service add yggdrasil ygg >/dev/null || fail "service add yggdrasil"
	x rayctl apply >/dev/null || fail "rayctl apply"
	wait_active niko-inner.service niko-dns.service niko-mdns.service niko-hy2o.service niko-front.service
	# A traffic limit, only recorded before v0.22.0: enforced after the
	# update as on a fresh node (spec/traffic-limit-v1.md §8, 2).
	x rayctl user add alice -services dns,mdns,hy2o -limit 50G >/dev/null 2>&1 || fail "user add"
	x rayctl device add alice laptop | grep '^rcdev1:' >"$work/$node.bundle" || fail "device add"
}

# client runs this build's rayctl probe from another container.
client() {
	docker run --rm --network "$net" -v "$bin:/opt/rc:ro" "$image" /opt/rc/rayctl probe "$@"
}

# probe checks the node like a client and keeps the subscription's payload
# in $work/$node.payload.json.
probe() {
	local out
	out="$(client -channel -payload "$(cat "$work/$node.bundle")")" || fail "probe ($1): $(grep -v '^payload ' <<<"$out")"
	[[ $out == *"channel udp: 50 sent, 50 back"* ]] || fail "no UDP echo ($1): $(grep -v '^payload ' <<<"$out")"
	sed -n 's/^payload //p' <<<"$out" >"$work/$node.payload.json"
	[[ -s $work/$node.payload.json ]] || fail "no payload ($1)"
	grep -v '^payload ' <<<"$out" | grep -E '^(seq|  )' || true
}

# shape writes what the comparison takes of the node to $work/$node.shape.
shape() {
	mkdir -p "$work/$node"
	# shellcheck disable=SC2016 # expands in the container
	x sh -c '
	echo "== units"; systemctl list-unit-files "niko-*" "ray*" --no-legend --plain | awk "{print \$1, \$2}" | sort
	echo "== active"; systemctl list-units "niko-*" "ray*" --state=active --no-legend --plain | awk "{print \$1}" | sort
	echo "== users"; getent passwd | awk -F: "\$1 ~ /^(niko|ray)/ {print \$1, \$6, \$7}" | sort
	echo "== groups"; getent group | awk -F: "\$1 ~ /^(niko|ray)/ {print \$1, \$4}" | sort
	# Units and settings in full, ports and UIDs (4 digits and more) aside,
	# and the reserved ports, whose order and merges the random ones make;
	# binaries by their hash.
	for f in /etc/systemd/system/niko-* /etc/systemd/system/ray* /etc/sysctl.d/*raycontrol* /etc/tmpfiles.d/raycontrol.conf \
		/etc/systemd/resolved.conf.d/raycontrol.conf; do
		[ -e "$f" ] || continue
		echo "== $(stat -c "%n %a %U %G" "$f")"
		sed -E "s/^(# reserved by raycontrol: |net\.ipv4\.ip_local_reserved_ports = ).*/\1PORTS/; s/[0-9]{4,}/N/g" "$f"
	done
	echo "== binaries"
	for f in /usr/local/bin/ray* /usr/local/libexec/raycontrol/*; do
		[ -e "$f" ] && echo "$(stat -c "%n %a %U %G" "$f") $(sha256sum < "$f" | cut -c1-16)"
	done
	echo "== rendered"; find /var/lib/raycontrol/rendered -printf "%P %m %u %g %y\n" | sort
	echo "== run"; find /run/niko -printf "%P %m %u %g %y\n" | sort
	' >"$work/$node.shape" || fail "shape"
	x tar -C /var/lib/raycontrol/rendered -cf - . | tar -C "$work/$node" -xf - || fail "rendered files"
	python3 "$here/shape.py" "$work/$node" "$work/$node.payload.json" >>"$work/$node.shape" || fail "shape.py"
}

docker network create --internal "$net" >/dev/null
log "$distro: the previous release, $(grep -m1 raycontrol "$old/VERSIONS" || echo "$old")"
boot "rc-upgraded-$distro"
install_node /opt/old
probe "previous release"

for d in "${steps[@]}"; do
	log "$distro: rayctl update -from the release in $d, by the rayctl on the node ($(x rayctl status | grep -m1 '^version' || true))"
	# With the handoff, as an update by request runs it: the release's
	# rayctl tells how it ended in the result file (docs/RELEASE.md).
	res=()
	[[ -n ${EXPECT_HANDOFF:-} ]] && res=(env RAYCONTROL_UPDATE_RESULT=/root/update-result.json)
	x rm -f /root/update-result.json
	out="$(xk "${res[@]}" /usr/local/bin/rayctl update -from "/opt/step/$d" -yes 2>&1)" || fail "rayctl update to the release in $d: $out"
	echo "$out" | grep -E '^(release|raycontrol|installed|rolling|update)' || true
	if [[ -n ${EXPECT_HANDOFF:-} ]]; then
		grep -q 'updates the node, handed over by the rayctl of' <<<"$out" || fail "the update to the release in $d was not handed to its rayctl"
		result="$(x cat /root/update-result.json)" || fail "no update result"
		grep -q '"state":"done"' <<<"$result" || fail "update result: $result"
		echo "result: $result"
	fi
	wait_active rayd.service rayspa.service niko-inner.service niko-dns.service niko-mdns.service niko-hy2o.service niko-front.service
	probe "after the release in $d"
done
if [[ -z ${STEPS_ONLY:-} ]]; then
	log "$distro: rayctl update by the previous release's rayctl"
	out="$(x /usr/local/bin/rayctl update -local /opt/rc -yes 2>&1)" || fail "rayctl update: $out"
	echo "$out" | grep -E '^(raycontrol|service|rolling|update)' || true
	# A node from far back keeps its services' weaker modes (an update
	# leaves them: their clients may not do more yet), and the update says
	# what a new service has. The operator's step, then the node is a
	# fresh install's.
	while read -r name kv; do
		[[ -n $name ]] || continue
		log "$distro: as the update advises: rayctl service set $name $kv"
		x rayctl service set "$name" "$kv" >/dev/null || fail "rayctl service set $name $kv"
	done < <(sed -nE 's/^service ([a-z0-9-]+): .*\(rayctl service set <name> ([a-z_]+=[a-z]+).*$/\1 \2/p' <<<"$out")
fi
for b in rayd rayspa rayctl; do
	x cmp -s "/opt/rc/$b" "/usr/local/bin/$b" || fail "$b is not this build's after the update"
done
for b in niko-server xray slipstream-server; do
	x cmp -s "/opt/rc/$b" "/usr/local/libexec/raycontrol/$b" || fail "$b is not this build's after the update"
done
wait_active rayd.service rayspa.service niko-inner.service niko-dns.service niko-mdns.service niko-hy2o.service niko-front.service
# rayd renders what the settings changed by itself; give it a moment.
sleep 3
# This build's apply has nothing left to change: the update applied it.
again="$(x rayctl apply)" || fail "rayctl apply after the update"
if grep -E '^(wrote|restarting)' <<<"$again"; then
	fail "the update left changes to apply"
fi
if [[ -z ${STEPS_ONLY:-} ]]; then
	usage="$(x rayctl user usage alice)"
	[[ $usage == *alice*50G*"monthly, day 1"*active* ]] || fail "the limit recorded before the update does not hold: $usage"
fi
probe "updated"
shape

log "$distro: a fresh install of this build"
boot "rc-fresh-$distro"
install_node /opt/rc
probe "fresh"
shape

log "$distro: the updated node against the fresh one"
if ! diff -u "$work/rc-fresh-$distro.shape" "$work/rc-upgraded-$distro.shape"; then
	fail "the updated node differs from a fresh install (- fresh, + updated)"
fi
log "$distro: the update from the previous release gives what a fresh install gives"
