# shellcheck shell=bash
# shellcheck disable=SC2034 # used by the scripts that source this file
# Shared helpers of the install tests. Sourced by prepare.sh, deps.sh, run.sh.

# Base images of the tested systems (docs/08-decisions.md, R2-1).
declare -A BASE=(
	[debian12]=debian:bookworm
	[debian13]=debian:trixie
	[ubuntu2404]=ubuntu:24.04
	[rocky9]=rockylinux/rockylinux:9
	[rocky10]=rockylinux/rockylinux:10
)

die() {
	echo "install-test: $*" >&2
	exit 1
}

log() { echo "==> $*"; }

# net_args fills NET_ARGS for containers that download packages. CI runners
# reach the internet from the default bridge. Behind a proxy that only the
# host reaches, set TEST_PKG_NETWORK=host and TEST_EXTRA_CA to its CA bundle;
# such containers never install firewall rules, so the host network is safe
# there and only there.
net_args() {
	NET_ARGS=()
	if [[ -n ${TEST_PKG_NETWORK:-} ]]; then
		NET_ARGS+=(--network "$TEST_PKG_NETWORK")
	fi
	local v
	for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy NO_PROXY; do
		if [[ -n ${!v:-} ]]; then
			NET_ARGS+=(-e "$v=${!v}")
		fi
	done
	if [[ -n ${TEST_EXTRA_CA:-} ]]; then
		NET_ARGS+=(-v "$TEST_EXTRA_CA:/extra-ca.crt:ro")
	fi
}

# EXTRA_CA_SETUP trusts /extra-ca.crt, if mounted, before anything uses TLS.
# shellcheck disable=SC2016
EXTRA_CA_SETUP='
if [ -f /extra-ca.crt ]; then
	if [ -d /etc/pki/ca-trust/source/anchors ]; then
		cp /extra-ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust
	else
		mkdir -p /usr/local/share/ca-certificates
		cp /extra-ca.crt /usr/local/share/ca-certificates/extra.crt
		# Debian images get ca-certificates with the first install below.
		if command -v update-ca-certificates >/dev/null; then update-ca-certificates >/dev/null; fi
	fi
fi
'
