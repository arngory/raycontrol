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

# snapshot records what an install may touch, to compare before and after
# rayctl uninstall: users, groups, every file and link under /etc, enabled
# units, the nftables ruleset (without counters), the sysctl values raycontrol
# sets, host firewalls, /var/lib and /usr/local/bin. Files Docker manages and
# the shadow-utils backups (passwd-) are left out.
snapshot() {
	# shellcheck disable=SC2016 # expands in the container
	x sh -c '
	{
		echo "== users"; getent passwd | sort
		echo "== groups"; getent group | sort
		echo "== files"
		find /etc -xdev \( -path /etc/hostname -o -path /etc/hosts -o -path /etc/resolv.conf -o -path /etc/machine-id \
			-o -path /etc/ld.so.cache -o -name "*-" \) -prune -o -type f -print0 | sort -z | xargs -0 sha256sum
		echo "== links"
		find /etc -xdev -type l -printf "%p -> %l\n" | sort
		echo "== units"; systemctl list-unit-files --state=enabled --no-legend | sort
		# Without counters and without the rules of Docker'"'"'s DNS (127.0.0.11),
		# whose ports change with every container start.
		echo "== nft"; nft list ruleset | sed -E "s/counter packets [0-9]+ bytes [0-9]+/counter/" | grep -v 127.0.0.11
		echo "== sysctl"; xargs sysctl < /root/sysctl.keys 2>&1
		echo "== firewalld"; if systemctl is-active --quiet firewalld; then firewall-cmd --list-all-zones; fi
		echo "== ufw"; if command -v ufw >/dev/null; then ufw status verbose; fi
		echo "== var/lib"; ls /var/lib
		echo "== bin"; ls /usr/local/bin
		# Missing on some systems before the install: recorded, not fatal
		# (the status of the last command is the status of the snapshot).
		echo "== libexec"; ls /usr/local/libexec 2>&1 || true
	} > "$1" 2>&1' snapshot "$1"
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

# ufw enable writes its rate-limit rules into user6.rules without loading
# them; restarting the unit loads the host's ufw files as a boot does, so
# the snapshot below is a state the host itself would come back to.
case $distro in
ubuntu*) x ufw --force enable >/dev/null && x systemctl restart ufw.service ;;
esac

log "$distro: bootstrap"
# The host as it is before raycontrol: wait for the boot to finish (ufw
# loads its rules from a oneshot unit) and for firewalld to answer.
x timeout 120 systemctl is-system-running --wait >/dev/null || true
# shellcheck disable=SC2016 # expands in the container
x sh -c 'if systemctl is-enabled -q firewalld 2>/dev/null; then for i in $(seq 60); do firewall-cmd --state >/dev/null 2>&1 && break; sleep 1; done; fi'
# The sysctl keys raycontrol sets, from its source, for the snapshots.
# shellcheck disable=SC2016 # backticks of the Go source, not a command
sed -n '/^const sysctl = `/,/^`/p' "$here/../../internal/deploy/deploy.go" | grep -o '^net\.[a-z0-9_.]*' |
	docker exec -i "$node" sh -c 'cat > /root/sysctl.keys'
snapshot /root/before.snap
# The emergency bundle bootstrap prints stays out of the (public) CI log.
# The data plane (xray, niko-server) comes from /opt/rc like a release's;
# one DNS tunnel is set up by the install itself, the other one below.
x env RAYCONTROL_LOCAL_DIR=/opt/rc bash /opt/install/bootstrap.sh -host "$ip" -domain example.test -admin 192.0.2.1 -services dnstt |
	sed -E 's/rcdev1:[A-Za-z0-9_-]+/rcdev1:<redacted>/g' || fail "bootstrap"
for b in xray niko-server; do
	[[ $(x stat -c '%a %U' "/usr/local/libexec/raycontrol/$b") == "755 root" ]] || fail "$b not installed by bootstrap"
done
wait_active rayd.service rayspa.service
wait_table "rayspa start"
[[ $(x nft list chain inet raycontrol input) == *"policy drop;"* ]] || fail "input chain is not policy drop"
# The sysctl settings work from the install on, not from the next boot.
if x grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control; then
	[[ $(x sysctl -n net.ipv4.tcp_congestion_control) == bbr ]] || fail "sysctl not applied at install"
fi

dataplane=(niko-inner.service niko-dns.service niko-mdns.service niko-front.service)

log "$distro: DNS tunnels"
x rayctl service add masterdns mdns >/dev/null
x rayctl apply || fail "rayctl apply"
wait_active "${dataplane[@]}"
[[ $(x ss -Hulpn 'sport = :53') == *niko-server* ]] || fail "the front does not listen on UDP 53"
# The backend's key: a copy in its runtime directory, for its user only.
[[ $(x stat -c '%a %U' /run/niko/dns/noise.key) == "400 niko-dns" ]] || fail "dnstt key copy is not 0400 niko-dns"
again="$(x rayctl apply)"
if grep -E '^(wrote|restarting)' <<<"$again"; then
	fail "a second apply changed things"
fi

x rayctl user add alice -services dns,mdns >/dev/null
# export: the subscription's links, audited (P-10).
exported="$(x rayctl user export alice)"
[[ $(grep -c '^vless://' <<<"$exported") == 2 ]] || fail "rayctl user export: $exported"
[[ $(x rayctl audit -n 1) == *user.export* ]] || fail "export is not audited"
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
# Channel probes (R4-16) after SPA: TCP both ways and the UDP echo, whose
# port SPA opens with the subscription's.
out="$(client -channel "$laptop")" || fail "channel probe: $out"
[[ $out == *"channel udp: 50 sent, 50 back; lost up 0, down 0"* ]] || fail "channel probe over UDP: $out"
[[ $out == *"channel link: "*" connections of this address on 443"* ]] || fail "no link stats: $out"

# Client summaries (R4-21): off until turned on; one report per network a
# day; the node shows networks with fewer than k reports only as a total.
svc="$(sed -n 's/^  dns (service \([0-9]*\))$/\1/p' <<<"$out" | head -1)"
[[ -n $svc ]] || fail "no dns service id in: $out"
report="{\"v\":1,\"net\":\"wifi\",\"obs\":[{\"svc\":$svc,\"result\":\"works\",\"udp\":\"0-1\"}]}"
if out="$(client -report "$report" "$laptop")"; then fail "a report taken while summaries are off: $out"; fi
[[ $out == *"HTTP 404"* ]] || fail "report while off: $out"
x rayctl summary on >/dev/null || fail "rayctl summary on"
out="$(client -report "$report" "$laptop")" || fail "report: $out"
[[ $out == *"report taken"* ]] || fail "report not taken: $out"
if out="$(client -report "$report" "$laptop")"; then fail "a second report the same day was taken: $out"; fi
[[ $out == *"HTTP 429"* ]] || fail "second report: $out"
summary="$(x rayctl summary)"
[[ $summary == *"from smaller networks"*"1 reports"* ]] || fail "rayctl summary: $summary"
x rayctl summary off >/dev/null

log "$distro: remote API"
x rayctl service add api api >/dev/null
# REALITY with its site and naive behind it: units, users and the naive
# socket directory are installed (no certificate on this network, so the
# processes wait for one) and go away with the uninstall.
x rayctl service add reality reality >/dev/null
x rayctl service add naive naive >/dev/null
# Yggdrasil the same way: its unit waits for the site's certificate (R4-15).
x rayctl service add yggdrasil ygg >/dev/null
# hy2-obfs needs no certificate of the site: it really runs, a niko-server
# backend behind the front's UDP 443 (udpmux, R3-4).
x rayctl service add hy2-obfs hy2o >/dev/null
x rayctl apply >/dev/null || fail "rayctl apply for the API, REALITY, naive, Yggdrasil and Hysteria2"
units="$(x systemctl cat niko-ygg.service)" || fail "no unit for Yggdrasil"
[[ $units == *PrivateNetwork=yes* && $units == *SupplementaryGroups=niko-inner* ]] || fail "the Yggdrasil unit is not unix-only with inner: $units"
[[ $(x id -nG niko-front) == *niko-ygg* ]] || fail "the front cannot reach the Yggdrasil socket"
# Public peers (R4-18): the unit goes out to the internet with them, and back
# to no network without.
x rayctl service set ygg peers=tls://192.0.2.10:443 >/dev/null || fail "rayctl service set ygg peers"
x rayctl apply >/dev/null || fail "rayctl apply with Yggdrasil peers"
units="$(x systemctl cat niko-ygg.service)"
[[ $units != *PrivateNetwork=yes* && $units == *"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"* && $units == *IPAddressDeny=localhost* ]] ||
	fail "the Yggdrasil unit with peers: $units"
x rayctl service set ygg peers=none >/dev/null
x rayctl apply >/dev/null || fail "rayctl apply without Yggdrasil peers"
[[ $(x systemctl cat niko-ygg.service) == *PrivateNetwork=yes* ]] || fail "the Yggdrasil unit kept its network"
[[ $(x stat -c '%a %U %G' /run/niko/naive-in) == "2750 niko-naive niko-front" ]] || fail "no socket directory for naive (the front passes connections there)"
units="$(x systemctl cat niko-naive.service)" || fail "no unit for naive"
[[ $units == *" -probe 127.0.0.1:"* && $units == *IPAddressAllow=127.0.0.1* ]] || fail "naive does not lead the probe name to the endpoint: $units"
wait_active niko-hy2o.service niko-front.service
[[ $(x ss -Hulpn 'sport = :443') == *niko-server* ]] || fail "the front does not listen on UDP 443"
[[ $(x stat -c '%a %U' /run/niko/front/hy2o.salamander) == "400 niko-front" ]] || fail "the front's salamander copy is not 0400 niko-front"
invite="$(x rayctl device invite alice console -role admin | grep -o 'rcinv1:[A-Za-z0-9_-]*')" || fail "no invite"
# From the client's container: register a device from the invite, then
# administer the node through the API with it, and give it a new key.
# shellcheck disable=SC2016 # expands in the client container
docker run --rm --network "$net" -v "$bin:/opt/rc:ro" "$image" sh -ec '
	/opt/rc/rayctl remote enroll -o /root/console.rcdev "$1"
	/opt/rc/rayctl -remote /root/console.rcdev status
	/opt/rc/rayctl -remote /root/console.rcdev user add carol
	/opt/rc/rayctl -remote /root/console.rcdev remote rotate
	/opt/rc/rayctl -remote /root/console.rcdev remote whoami
	if /opt/rc/rayctl -remote /root/console.rcdev backup; then exit 1; fi
	if /opt/rc/rayctl remote enroll -o /root/again.rcdev "$1"; then echo "an invite worked twice"; exit 1; fi
' _ "$invite" | sed -E 's/rc(dev|inv)1:[A-Za-z0-9_-]+/rc\11:<redacted>/g' || fail "remote API from the client"
[[ $(x rayctl user list) == *carol* ]] || fail "the user made through the remote API is missing"
[[ $(x rayctl audit) == *"alice/console (remote)"* ]] || fail "the remote admin is not in the audit log"
[[ $(x rayctl device list alice) == *registered* ]] || fail "the remote device is not listed as registered"

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

log "$distro: report"
x /usr/local/bin/rayctl report -logs info -o /root/report.txt > /dev/null || fail "rayctl report"
report="$(x cat /root/report.txt)"
for section in "== versions" "== system" "== node" "== units" "checks"; do
	[[ $report == *"$section"* ]] || fail "report lacks $section"
done
for leak in "$ip" example.test rcdev1: rcinv1: "$phone_id"; do
	if [[ $report == *"$leak"* ]]; then
		fail "report leaks $leak"
	fi
done

log "$distro: update and rollback"
# The same binaries as a release would bring them (test mode, no
# signature): replaced, restarted, applied, checked; then put back.
x /usr/local/bin/rayctl update -local /opt/rc -yes || fail "rayctl update"
x test -s /var/lib/raycontrol-install/previous/rayd || fail "update kept no previous binaries"
wait_active rayd.service rayspa.service "${dataplane[@]}"
# Channel probes still work after the restart (UDP echo included).
out="$(client -channel -addr "$ip" "$laptop")" || fail "probe after update: $out"
[[ $out == *"channel udp: 50 sent, 50 back"* ]] || fail "no UDP echo after update: $out"
x /usr/local/bin/rayctl update -rollback || fail "rayctl update -rollback"
wait_active rayd.service rayspa.service "${dataplane[@]}"
client -addr "$ip" "$laptop" >/dev/null || fail "probe after rollback"
# A release whose rayd does not start: the update puts the previous
# binaries back by itself.
x sh -c 'mkdir -p /root/broken && cp /opt/rc/* /root/broken/ && printf "#!/bin/sh\nexit 1\n" > /root/broken/rayd && chmod 755 /root/broken/rayd'
if x /usr/local/bin/rayctl update -local /root/broken -yes; then
	fail "an update with a broken rayd succeeded"
fi
wait_active rayd.service rayspa.service "${dataplane[@]}"
client -addr "$ip" "$laptop" >/dev/null || fail "probe after the automatic rollback"
x rm -rf /root/broken

log "$distro: backup, restore and metrics"
x sh -c 'umask 077 && echo "a test passphrase" > /root/pass'
x /usr/local/bin/rayctl backup -o /root/node.rcbak -passphrase-file /root/pass || fail "rayctl backup"
[[ $(x stat -c %a /root/node.rcbak) == 600 ]] || fail "the backup is not 0600"
if x grep -qa -e SQLite -e alice /root/node.rcbak; then
	fail "the backup is readable without the passphrase"
fi
x rayctl user add bob >/dev/null
x /usr/local/bin/rayctl restore -i /root/node.rcbak -passphrase-file /root/pass -yes || fail "rayctl restore"
users="$(x rayctl user list)"
[[ $users == *alice* && $users != *bob* ]] || fail "restore did not bring back the state of the backup: $users"
wait_active rayd.service rayspa.service "${dataplane[@]}"
client -addr "$ip" "$laptop" >/dev/null || fail "probe after restore"
# Three users: alice, carol from the remote API, the operator's own.
metrics="$(x /usr/local/bin/rayctl metrics)" || fail "rayctl metrics"
for m in 'raycontrol_users{state="active"} 3' 'raycontrol_services{kind="dnstt",enabled="true"} 1' \
	'raycontrol_early_drops_packets_total{reason="ipv4-fragment"}'; do
	[[ $metrics == *"$m"* ]] || fail "metrics lack $m: $metrics"
done
x rm -f /root/node.rcbak /root/pass

log "$distro: uninstall"
x /usr/local/bin/rayctl uninstall -yes || fail "rayctl uninstall"
snapshot /root/after.snap
# Compared here: minimal images (Rocky 9) have no diff.
if ! diff -u <(x cat /root/before.snap) <(x cat /root/after.snap) >&2; then
	fail "the host after uninstall differs from before the install (diff above)"
fi
for p in /usr/local/bin/rayd /usr/local/bin/rayctl /usr/local/libexec/raycontrol /var/lib/raycontrol /var/lib/raycontrol-install /etc/systemd/system/rayd.service; do
	if x test -e "$p"; then
		fail "$p is still there after uninstall"
	fi
done

log "$distro: PASS"
