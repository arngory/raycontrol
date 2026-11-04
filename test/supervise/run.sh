#!/usr/bin/env bash
# A node without systemd: rayd serve -supervise in a plain container runs
# the data plane as its own child processes from the rendered files, the
# plan rayctl apply would install as units. A second container probes it
# like a client. The minimal recipe for a client's CI (docs/handoff).
#
#   test/supervise/run.sh BIN [IMAGE]
#
# BIN holds rayd, rayctl, xray and niko-server (v0.7 or later); IMAGE is
# any glibc image (default debian:13). Needs docker and go (testcert).
set -euo pipefail

bin="$(cd "${1:?usage: run.sh BIN [IMAGE]}" && pwd)"
image="${2:-debian:13}"
here="$(cd "$(dirname "$0")" && pwd)"
net="rc-sv-$$"
node="rc-sv-node-$$"
work="$(mktemp -d)"

log() { printf '\n== %s\n' "$*"; }
fail() {
	echo "FAIL: $*" >&2
	docker exec "$node" cat /var/log/rayd.log >&2 2>/dev/null || true
	exit 1
}
cleanup() {
	docker rm -f "$node" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

x() { docker exec "$node" "$@"; }
client() { docker run --rm --network "$net" -v "$bin:/opt/rc:ro" "$image" /opt/rc/rayctl probe "$@"; }

log "node: a plain container, root, no systemd"
docker network create --internal "$net" >/dev/null
docker run -d --name "$node" --network "$net" -v "$bin:/opt/rc:ro" "$image" sleep infinity >/dev/null
ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$node")"

# The default paths: the state in /var/lib/raycontrol, the API socket in
# /run/raycontrol, the data plane's sockets in /run/niko (-run).
x mkdir -p /var/lib/raycontrol /run/raycontrol
x /opt/rc/rayd init -host "$ip" -domain example.test >/dev/null
# NIKO_SERVER_UNSAFE_ANY_DESTINATION: the tunnels may reach this private
# network (a test network has no public addresses); never on a real node.
x sh -c 'NIKO_SERVER_UNSAFE_ANY_DESTINATION=1 nohup /opt/rc/rayd serve -supervise \
	-xray /opt/rc/xray -niko-server /opt/rc/niko-server -acme-directory "" >/var/log/rayd.log 2>&1 & echo $! >/run/rayd.pid'
for _ in $(seq 50); do x test -S /run/raycontrol/rayd.sock && break; sleep 0.2; done
x test -S /run/raycontrol/rayd.sock || fail "rayd did not open its API socket"

log "services, the site's certificate, a user and a device"
x /opt/rc/rayctl service add reality reality >/dev/null
x /opt/rc/rayctl service add hy2-obfs hy2o >/dev/null
x /opt/rc/rayctl service add yggdrasil ygg >/dev/null
# A test CA in place of ACME: REALITY (self-steal), Yggdrasil, hy2-masq and
# naive take the site's certificate. Clients that verify it trust root.pem.
(cd "$here/../.." && go run ./test/supervise/testcert -o "$work" '*.example.test')
docker cp "$work/chain.pem" "$node:/root/chain.pem"
docker cp "$work/key.pem" "$node:/root/key.pem"
x /opt/rc/rayctl service cert site -chain /root/chain.pem -key /root/key.pem || fail "rayctl service cert"
x /opt/rc/rayctl user add alice -services reality,hy2o,ygg >/dev/null
bundle="$(x /opt/rc/rayctl device add alice laptop | grep '^rcdev1:')" || fail "no bundle"

log "the data plane under rayd"
for sock in /run/niko/inner/vless.sock /run/niko/site/tls.sock /run/niko/hy2o/stats.sock /run/niko/ygg/fd.sock; do
	for _ in $(seq 100); do x test -S "$sock" && break; sleep 0.2; done
	x test -S "$sock" || fail "no $sock"
done
x grep 'supervise: started' /var/log/rayd.log | sed 's/^.*unit=/  /'
# A config change restarts the process it concerns: the users file of
# Hysteria2 is read again by the backend itself; Xray gets users over its API.
x /opt/rc/rayctl user add bob -services hy2o,reality >/dev/null

log "a client from another container"
out="$(client -channel "$bundle")" || fail "probe: $out"
echo "$out"
[[ $out == *"channel down:"* && $out == *"channel udp: 50 sent, 50 back"* ]] || fail "channel probe: $out"
[[ $out == *"channel link: "* ]] || fail "no link from the client's address: $out"
links="$(x /opt/rc/rayctl user export alice)"
[[ $(grep -c '^vless://' <<<"$links") -ge 1 && $(grep -c '^hysteria2://' <<<"$links") == 1 ]] || fail "links: $links"

log "stop: rayd takes its processes with it"
# shellcheck disable=SC2016 # expands in the container
x sh -c 'kill "$(cat /run/rayd.pid)"'
for _ in $(seq 50); do x sh -c 'pidof xray niko-server' >/dev/null || break; sleep 0.2; done
if x sh -c 'pidof xray niko-server' >/dev/null; then fail "data plane left running after rayd"; fi
echo "ok"
