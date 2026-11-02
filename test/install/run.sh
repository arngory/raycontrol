#!/usr/bin/env bash
# Installs a node in a systemd container of DISTRO (raycontrol-test:DISTRO
# from prepare.sh) through install/bootstrap.sh and checks it from a second
# container the way a client would. Both sit on an internal Docker network:
# rayspa's table lives in the node container's own network namespace.
#
#   test/install/run.sh debian13 BIN_DIR
#
# BIN_DIR holds rayd, rayspa, rayctl, niko-server and xray (linux/amd64).
# On a cgroup v1 host, TEST_CGROUP_ROOT names a writable cgroup2 mount for
# the container's systemd (systemd 256+ needs cgroup v2).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/install/lib.sh
. "$here/lib.sh"

distro=${1:?usage: run.sh DISTRO BIN_DIR}
bin="$(cd "${2:?usage: run.sh DISTRO BIN_DIR}" && pwd)"
image="raycontrol-test:$distro"
net="rc-test-$distro"
node="rc-node-$distro"
for f in rayd rayspa rayctl niko-server xray; do
	[[ -x $bin/$f ]] || die "$bin/$f is missing"
done

x() { docker exec "$node" "$@"; }

dump() {
	echo "--- journal" >&2
	x journalctl --no-pager -n 300 -u rayd -u rayspa -u 'niko-*' >&2 || true
	echo "--- failed units" >&2
	x systemctl --failed --no-pager >&2 || true
	# shellcheck disable=SC2016 # expands in the container
	x sh -c 'for u in $(systemctl list-units --failed --plain --no-legend "niko-*" "ray*" | cut -d" " -f1); do systemctl status --no-pager -n 30 "$u"; done' >&2 || true
	echo "--- ruleset" >&2
	x nft list ruleset >&2 || true
}

fail() {
	echo "FAIL ($distro): $*" >&2
	dump
	exit 1
}

cleanup() {
	docker rm -f "$node" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
}
cleanup
# TEST_KEEP=1 leaves the node running for a look inside (docker exec).
if [[ -z ${TEST_KEEP:-} ]]; then
	trap cleanup EXIT
fi

boot() {
	local state=""
	for _ in $(seq 90); do
		state="$(x systemctl is-system-running 2>/dev/null || true)"
		if [[ $state == running || $state == degraded ]]; then
			return 0
		fi
		sleep 1
	done
	fail "systemd did not come up: ${state:-no answer}"
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

wait_table() {
	for _ in $(seq 10); do
		if x nft list table inet raycontrol >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	fail "rayspa did not restore its table after: $1"
}

# client runs rayctl probe from another container on the same network.
client() {
	docker run --rm --network "$net" -v "$bin:/opt/rc:ro" "$image" /opt/rc/rayctl probe "$@"
}

docker network create --internal "$net" >/dev/null
cgroup=()
if [[ -n ${TEST_CGROUP_ROOT:-} ]]; then
	mkdir -p "$TEST_CGROUP_ROOT/$node"
	cgroup=(-v "$TEST_CGROUP_ROOT/$node:/sys/fs/cgroup:rw")
fi
log "$distro: booting the node"
docker run -d --name "$node" --hostname node --privileged --cgroupns=private --network "$net" \
	--tmpfs /run --tmpfs /run/lock "${cgroup[@]}" \
	-v "$bin:/opt/rc:ro" -v "$here/../../install:/opt/install:ro" "$image" /sbin/init >/dev/null
boot
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node")"
# shellcheck disable=SC2016 # expands in the container
x sh -c '. /etc/os-release; echo "$PRETTY_NAME, $(systemctl --version | head -1), $(nft --version)"'

case $distro in
ubuntu*) x ufw --force enable ;;
esac

log "$distro: bootstrap"
x install -m 0755 /opt/rc/niko-server /opt/rc/xray /usr/local/bin/
x env RAYCONTROL_LOCAL_DIR=/opt/rc bash /opt/install/bootstrap.sh -host "$ip" -domain example.test -admin 192.0.2.1 ||
	fail "bootstrap"
wait_active rayd.service rayspa.service
wait_table "rayspa start"
[[ $(x nft list chain inet raycontrol input) == *"policy drop;"* ]] || fail "input chain is not policy drop"

# Some sandboxes cannot mount systemd credentials; the backends need them.
# CI sets TEST_STRICT=1 so that this never passes as a skip there.
dataplane=(niko-inner.service niko-dns.service niko-mdns.service niko-front.service)
x sh -c 'echo raycontrol > /run/credential-probe'
# shellcheck disable=SC2016 # expands in the unit
if ! x systemd-run --wait --quiet --unit credential-probe -p LoadCredential=probe:/run/credential-probe \
	sh -c 'test -s "$CREDENTIALS_DIRECTORY/probe"'; then
	x journalctl --no-pager -n 40 >&2 || true
	[[ -z ${TEST_STRICT:-} ]] || fail "systemd credentials do not work here"
	echo "SKIP: systemd credentials do not work in this environment; data-plane units are not checked" >&2
	dataplane=(niko-inner.service)
fi

log "$distro: DNS tunnels"
x rayctl service add dnstt dns >/dev/null
x rayctl service add masterdns mdns >/dev/null
x rayctl apply || fail "rayctl apply"
wait_active "${dataplane[@]}"
if [[ ${#dataplane[@]} -gt 1 ]]; then
	[[ $(x ss -Hulpn 'sport = :53') == *niko-server* ]] || fail "the front does not listen on UDP 53"
fi
again="$(x rayctl apply)"
if grep -E '^(wrote|restarting)' <<<"$again"; then
	fail "a second apply changed things"
fi

x rayctl user add alice -services dns,mdns >/dev/null
device() { x rayctl device add alice "$1" | awk '/enrolled/ {id=$2} /^rcdev1:/ {print id, $0}'; }
read -r phone_id phone < <(device phone)
read -r _ laptop < <(device laptop)
[[ $phone == rcdev1:* && $laptop == rcdev1:* ]] || fail "no bundles"

log "$distro: probe from outside"
out="$(client "$phone")" || fail "probe over UDP: $out"
echo "$out"
grep -q '  dns (service' <<<"$out" || fail "no dns profile in the subscription"
x rayctl device revoke "$phone_id"
if out="$(client "$phone")"; then
	fail "revoked device still reaches the node: $out"
fi
client -carrier tcp "$laptop" || fail "probe over the TCP carrier"

log "$distro: host firewall reloads and flush ruleset"
case $distro in
debian*) x systemctl restart nftables.service && wait_table "nftables restart" ;;
ubuntu*) x ufw reload && wait_table "ufw reload" ;;
rocky*) x firewall-cmd --reload && wait_table "firewalld reload" ;;
esac
client "$laptop" >/dev/null || fail "probe after the firewall reload"
x nft flush ruleset
wait_table "nft flush ruleset"
client "$laptop" >/dev/null || fail "probe after flush ruleset"

log "$distro: reboot"
docker restart "$node" >/dev/null
boot
wait_active rayd.service rayspa.service "${dataplane[@]}"
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node")"
client -addr "$ip" "$laptop" >/dev/null || fail "probe after reboot"

log "$distro: PASS"
