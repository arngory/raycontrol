#!/usr/bin/env bash
# Builds raycontrol-test:DISTRO: the base image with systemd and what a
# server of that family usually has, including its default host firewall
# (nftables.service on Debian, ufw on Ubuntu, firewalld on Rocky). The
# bootstrap's own package installation is tested by deps.sh.
#
#   test/install/prepare.sh debian13
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/install/lib.sh
. "$here/lib.sh"

distro=${1:?usage: prepare.sh DISTRO}
base=${BASE[$distro]:-}
[[ -n $base ]] || die "unknown distro $distro (${!BASE[*]})"
image="raycontrol-test:$distro"

# shellcheck disable=SC2016
script=$EXTRA_CA_SETUP'
set -eu
. /etc/os-release
case "$ID" in
debian|ubuntu)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -q
	extra=nftables
	if [ "$ID" = ubuntu ]; then extra="nftables ufw"; fi
	apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus iproute2 procps \
		ca-certificates curl openssl polkitd $extra
	if [ -f /extra-ca.crt ]; then cp /extra-ca.crt /usr/local/share/ca-certificates/extra.crt && update-ca-certificates >/dev/null; fi
	# Debian: the stock /etc/nftables.conf ("flush ruleset") loads at boot.
	if [ "$ID" = debian ]; then systemctl enable nftables.service; fi
	;;
rocky)
	# curl-minimal of the base image provides curl; the full curl conflicts on 9.
	dnf install -y -q systemd dbus iproute procps-ng openssl nftables polkit firewalld \
		shadow-utils util-linux
	systemctl enable firewalld.service
	;;
*)
	echo "unknown family $ID" >&2
	exit 1
	;;
esac
# Units that cannot work in a container.
systemctl mask systemd-firstboot.service systemd-udevd.service systemd-modules-load.service \
	sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount >/dev/null 2>&1 || true
'

net_args
name="raycontrol-prep-$distro"
docker rm -f "$name" >/dev/null 2>&1 || true
log "preparing $image from $base"
docker run --name "$name" "${NET_ARGS[@]}" "$base" sh -c "$script"
docker commit -c 'CMD ["/sbin/init"]' "$name" "$image" >/dev/null
docker rm "$name" >/dev/null
log "$image ready"
