#!/usr/bin/env bash
# raycontrol bootstrap: downloads a release, verifies its minisign signature
# and checksum, installs rayd, rayspa and rayctl, then runs "rayctl install"
# with the arguments given here (e.g. -host 203.0.113.7 -domain example.com).
# The release carries the data plane too (Xray built from the pinned fork,
# niko-server checked against pinned hashes) under the same signature;
# rayctl install puts it in /usr/local/libexec/raycontrol and sets the
# services up (REALITY by default when a domain is given).
#
#   curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
#   less bootstrap.sh
#   sudo bash bootstrap.sh -host <public address> [-domain <domain>]
#
# Before it installs anything of raycontrol it checks the host (rayctl check,
# docs/08-decisions.md, R4-24): what is required, what is advised. A host that
# cannot run a node is refused, and the packages this run installed are
# removed again. -check, as the first argument, only checks and leaves the
# host as it was:
#
#   sudo bash bootstrap.sh -check [-host <address>] [-services reality,dnstt]
#
# -remove-v0 first takes away raycontrol v0 (ray.sh, "Ray-AIO"), which holds
# port 443 and drops the node's traffic: a backup of it goes to /root, then
# only what v0 installed is removed (rayctl legacy, R4-26). With
# -purge-v0-packages also the packages only v0 needed (certbot, PostgreSQL,
# qrencode; each only if nothing else uses it):
#
#   sudo bash bootstrap.sh -remove-v0 -host <public address> [-domain <domain>]
#
# -relay <bundle file> makes the host a relay in front of an exit instead of a
# node (spec/relay-v1.md §3.1): only rayspa, forwarding in the kernel. The
# bundle comes from "rayctl relay bundle <name>" on the exit; it holds the
# relay's private key, so it is copied to the relay host only:
#
#   sudo bash bootstrap.sh -relay relay.bundle
#
# Works on any systemd-based Linux with apt, dnf, zypper or pacman; tested on
# Debian 12/13, Ubuntu 24.04 and Rocky Linux 9/10 (the check tells about the
# rest). The signature is checked with openssl, so minisign is not needed.
#
# RAYCONTROL_VERSION=v0.9.0 pins a release; default is the latest one. The
# version is read from the signature, so a mirror cannot swap one release for
# another, and nothing older than MIN_VERSION is installed.
# RAYCONTROL_MIRRORS="https://mirror.example/ ..." are URL prefixes tried when
# github.com does not answer (RU, CN); the signature check makes any mirror
# safe to use. The defaults are public GitHub proxies.
# RAYCONTROL_LOCAL_DIR=<dir> installs rayd, rayspa and rayctl from <dir>
# without downloading or verifying anything: for tests only.
set -euo pipefail

REPO="arngory/raycontrol"
VERSION="${RAYCONTROL_VERSION:-latest}"
# minisign public key of raycontrol releases, key ID A9C7802E23B87A01
# (docs/RELEASE.md). Only this base64 line matters; the "untrusted comment"
# line of the .pub file is not part of the key.
PUBKEY="RWQBergjLoDHqeme5vyIuIRXJLjTj1EF3jR1nlWBVJO3rWxgy9SZj4bD"
# MIN_VERSION is the oldest release this script installs: the first one with
# every rayctl command it calls. It is raised too when a release closes a
# hole, so that a mirror cannot hand out an older signed release as the
# latest one (docs/RELEASE.md).
MIN_VERSION="v0.10.0"
# RELAY_MIN_VERSION is the first release that can be a relay (-relay).
RELAY_MIN_VERSION="v0.10.1"

die() {
	echo "bootstrap: $*" >&2
	exit 1
}

log() { echo "bootstrap: $*"; }

MIRRORS="${RAYCONTROL_MIRRORS-https://ghfast.top/ https://gh-proxy.com/}"

# fetch URL FILE downloads with timeouts and retries: GitHub first, over
# IPv4 too (broken IPv6 is common on VPS), then through the mirrors.
fetch() {
	local url=$1 out=$2 prefix
	local opts=(-fsSL --proto '=https' --tlsv1.2 --connect-timeout 15 --retry 2 --retry-delay 2
		--speed-limit 1024 --speed-time 60 -o "$out")
	curl "${opts[@]}" "$url" && return 0
	curl -4 "${opts[@]}" "$url" && return 0
	for prefix in $MIRRORS; do
		log "github.com did not answer, trying ${prefix} (the signature still protects the files)"
		curl "${opts[@]}" "${prefix}${url}" && return 0
	done
	return 1
}

# verify_minisig FILE SIGFILE PUBKEY checks a minisign signature with openssl:
# Ed25519 over BLAKE2b-512(FILE) ("ED", minisign's default) or over FILE
# ("Ed", legacy), then the global signature over the trusted comment.
# Every step returns explicitly: set -e does not apply inside a function
# called from a condition, so it must not be relied on here.
verify_minisig() {
	local dir ok=1
	dir="$(mktemp -d)"
	_verify_minisig "$1" "$2" "$3" "$dir" && ok=0
	rm -rf "$dir"
	return "$ok"
}

_verify_minisig() {
	local file=$1 sigfile=$2 pubkey=$3 dir=$4 trusted
	printf '%s' "$pubkey" | base64 -d >"$dir/pk" 2>/dev/null || return 1
	[[ $(stat -c %s "$dir/pk") -eq 42 && $(head -c2 "$dir/pk") == Ed ]] || return 1
	# SubjectPublicKeyInfo of an Ed25519 key: fixed prefix, then the key.
	{
		printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
		tail -c32 "$dir/pk"
	} >"$dir/pk.der" || return 1
	openssl pkey -pubin -inform DER -in "$dir/pk.der" -out "$dir/pk.pem" 2>/dev/null || return 1

	sed -n 2p "$sigfile" | base64 -d >"$dir/sig" 2>/dev/null || return 1
	[[ $(stat -c %s "$dir/sig") -eq 74 ]] || return 1
	cmp -s <(head -c10 "$dir/sig" | tail -c8) <(head -c10 "$dir/pk" | tail -c8) || return 1
	tail -c64 "$dir/sig" >"$dir/ed" || return 1
	case "$(head -c2 "$dir/sig")" in
	ED) openssl dgst -blake2b512 -binary "$file" >"$dir/msg" || return 1 ;;
	Ed) cp "$file" "$dir/msg" || return 1 ;;
	*) return 1 ;;
	esac
	openssl pkeyutl -verify -pubin -inkey "$dir/pk.pem" -rawin -in "$dir/msg" -sigfile "$dir/ed" >/dev/null 2>&1 || return 1

	trusted="$(sed -n 3p "$sigfile")"
	[[ $trusted == "trusted comment: "* ]] || return 1
	{
		cat "$dir/ed"
		printf '%s' "${trusted#trusted comment: }"
	} >"$dir/gmsg" || return 1
	sed -n 4p "$sigfile" | base64 -d >"$dir/gsig" 2>/dev/null || return 1
	openssl pkeyutl -verify -pubin -inkey "$dir/pk.pem" -rawin -in "$dir/gmsg" -sigfile "$dir/gsig" >/dev/null 2>&1 || return 1
}

# signed_version SIGFILE prints the release named by a verified signature's
# trusted comment ("trusted comment: raycontrol v0.9.0").
signed_version() {
	local t
	t="$(sed -n 3p "$1")"
	[[ $t == "trusted comment: raycontrol "* ]] || return 1
	t=${t#trusted comment: raycontrol }
	[[ $t =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
	printf '%s\n' "$t"
}

# version_lt A B: release A (vX.Y.Z) is older than release B.
version_lt() {
	local a b i
	IFS=. read -ra a <<<"${1#v}"
	IFS=. read -ra b <<<"${2#v}"
	for i in 0 1 2; do
		if ((10#${a[i]} != 10#${b[i]})); then
			((10#${a[i]} < 10#${b[i]}))
			return
		fi
	done
	return 1
}

# check_version SIGNED says why the signed release cannot be installed: it is
# not the one asked for (RAYCONTROL_VERSION), or it is older than MIN_VERSION.
check_version() {
	local signed=$1
	if [[ $VERSION != latest && $signed != "$VERSION" ]]; then
		echo "asked for $VERSION, the signature says $signed"
		return 1
	fi
	if version_lt "$signed" "$MIN_VERSION"; then
		echo "the release is $signed, older than $MIN_VERSION, the oldest this bootstrap.sh installs"
		return 1
	fi
}

# install_deps installs what is missing: curl, openssl, nft and polkit (rayd
# restarts data-plane units through polkit). INSTALLED_PKGS records them as
# manager:name,name for rayctl uninstall -purge-packages.
INSTALLED_PKGS=""
install_deps() {
	local missing=()
	command -v curl >/dev/null || missing+=(curl)
	command -v openssl >/dev/null || missing+=(openssl)
	command -v nft >/dev/null || missing+=(nftables)
	command -v pkcheck >/dev/null || missing+=(polkit)
	if [[ ${#missing[@]} -eq 0 ]]; then
		return
	fi
	log "installing ${missing[*]}"
	local pkgs=() p
	if command -v apt-get >/dev/null; then
		for p in "${missing[@]}"; do [[ $p == polkit ]] && pkgs+=(polkitd) || pkgs+=("$p"); done
		export DEBIAN_FRONTEND=noninteractive
		# A fresh VPS often runs unattended-upgrades first: wait for its lock.
		local lock=(-o DPkg::Lock::Timeout=300)
		apt-get "${lock[@]}" update -q
		apt-get "${lock[@]}" install -y -q ca-certificates "${pkgs[@]}"
		INSTALLED_PKGS="apt:$(IFS=,; echo "${pkgs[*]}")"
	elif command -v dnf >/dev/null; then
		dnf install -y -q ca-certificates "${missing[@]}"
		INSTALLED_PKGS="dnf:$(IFS=,; echo "${missing[*]}")"
	elif command -v zypper >/dev/null; then
		zypper --non-interactive install ca-certificates "${missing[@]}"
		INSTALLED_PKGS="zypper:$(IFS=,; echo "${missing[*]}")"
	elif command -v pacman >/dev/null; then
		pacman -Sy --noconfirm --needed ca-certificates "${missing[@]}"
		INSTALLED_PKGS="pacman:$(IFS=,; echo "${missing[*]}")"
	else
		die "install ${missing[*]} with your package manager and run again"
	fi
}

# remove_deps takes back what install_deps installed in this run.
remove_deps() {
	[[ -n $INSTALLED_PKGS ]] || return 0
	local manager=${INSTALLED_PKGS%%:*} names
	IFS=, read -ra names <<<"${INSTALLED_PKGS#*:}"
	log "removing what this run installed: ${names[*]}"
	case $manager in
	apt) apt-get -o DPkg::Lock::Timeout=300 remove -y -q "${names[@]}" ;;
	dnf) dnf remove -y -q "${names[@]}" ;;
	zypper) zypper --non-interactive remove "${names[@]}" ;;
	pacman) pacman -R --noconfirm "${names[@]}" ;;
	esac || log "could not remove ${names[*]}; remove them with $manager"
	INSTALLED_PKGS=""
}

# cleanup runs on exit. Until rayctl install takes them over (it records them
# for rayctl uninstall), the packages this run installed are the
# bootstrap's: a refusal, a failure or -check removes them.
HANDED_OVER=0
CHECK_ONLY=0
REMOVE_V0=0
PURGE_V0=0
RELAY_BUNDLE=""
cleanup() {
	local status=$?
	if [[ -n ${BOOT_TMP:-} ]]; then rm -rf "$BOOT_TMP"; fi
	if [[ $HANDED_OVER == 0 ]] && [[ $status -ne 0 || $CHECK_ONLY == 1 ]]; then
		remove_deps
	fi
}

main() {
	while [[ $# -gt 0 ]]; do
		case $1 in
		-check) CHECK_ONLY=1 ;;
		-remove-v0) REMOVE_V0=1 ;;
		-purge-v0-packages) REMOVE_V0=1 PURGE_V0=1 ;;
		-relay)
			[[ -n ${2:-} ]] || die "-relay needs the bundle file (rayctl relay bundle on the exit)"
			RELAY_BUNDLE=$2
			shift
			;;
		*) break ;;
		esac
		shift
	done
	if [[ $CHECK_ONLY == 1 && $REMOVE_V0 == 1 ]]; then
		die "-check changes nothing and -remove-v0 removes raycontrol v0: use one of them"
	fi
	if [[ -n $RELAY_BUNDLE ]]; then
		[[ $CHECK_ONLY == 0 && $REMOVE_V0 == 0 ]] || die "-relay installs a relay: without -check or -remove-v0"
		[[ -r $RELAY_BUNDLE ]] || die "cannot read the relay bundle $RELAY_BUNDLE"
		RELAY_BUNDLE="$(cd "$(dirname "$RELAY_BUNDLE")" && pwd)/$(basename "$RELAY_BUNDLE")"
		# Before the node's binaries are replaced by the release's.
		[[ ! -e /var/lib/raycontrol/rayd.db ]] || die "this host is a node (/var/lib/raycontrol/rayd.db): a relay goes on a host of its own"
		# One relay install at a time: not even binaries swapped under one.
		if command -v flock >/dev/null && ! flock -n /run/raycontrol-relay-install.lock true; then
			die "another rayctl install -relay is running on this host"
		fi
	fi
	if [[ $VERSION != latest ]]; then
		[[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "RAYCONTROL_VERSION is vX.Y.Z, not $VERSION"
		if version_lt "$VERSION" "$MIN_VERSION"; then
			die "this bootstrap.sh installs $MIN_VERSION or newer; for $VERSION take the one of that release: https://raw.githubusercontent.com/${REPO}/${VERSION}/install/bootstrap.sh"
		fi
	fi
	[[ $EUID -eq 0 ]] || die "run as root"
	[[ -d /run/systemd/system ]] || die "systemd is required"
	case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64) ARCH=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	# Global: the EXIT trap runs after main has returned.
	BOOT_TMP="$(mktemp -d)"
	trap cleanup EXIT
	install_deps
	local tmp=$BOOT_TMP
	if [[ -n ${RAYCONTROL_LOCAL_DIR:-} ]]; then
		log "installing from $RAYCONTROL_LOCAL_DIR without verification (test mode)"
		cp "$RAYCONTROL_LOCAL_DIR"/{rayd,rayspa,rayctl} "$tmp/"
		for f in xray niko-server; do
			if [[ -f $RAYCONTROL_LOCAL_DIR/$f ]]; then cp "$RAYCONTROL_LOCAL_DIR/$f" "$tmp/"; fi
		done
	else
		local base tarball f
		if [[ $VERSION == latest ]]; then
			base="https://github.com/${REPO}/releases/latest/download"
		else
			base="https://github.com/${REPO}/releases/download/${VERSION}"
		fi
		tarball="raycontrol-linux-${ARCH}.tar.gz"
		for f in "$tarball" SHA256SUMS SHA256SUMS.minisig; do
			fetch "$base/$f" "$tmp/$f" || die "cannot download $f"
		done
		verify_minisig "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.minisig" "$PUBKEY" || die "release signature does not verify"
		local signed why
		signed="$(signed_version "$tmp/SHA256SUMS.minisig")" || die "the signature names no raycontrol release"
		why="$(check_version "$signed")" || die "$why"
		log "release $signed, signature verified"
		(cd "$tmp" && grep " ${tarball}\$" SHA256SUMS | sha256sum -c -) || die "checksum mismatch"
		tar -xzf "$tmp/$tarball" -C "$tmp"
	fi

	# A relay: rayspa and rayctl only, no host check for a node; rayctl
	# install -relay checks what a relay needs and stops rayspa again if the
	# exit gives it no perimeter.
	if [[ -n $RELAY_BUNDLE ]]; then
		if [[ -z ${RAYCONTROL_LOCAL_DIR:-} ]] && version_lt "$signed" "$RELAY_MIN_VERSION"; then
			die "the release is $signed; a relay needs $RELAY_MIN_VERSION or newer"
		fi
		install -m 0755 "$tmp/rayspa" "$tmp/rayctl" /usr/local/bin/
		if command -v restorecon >/dev/null; then
			restorecon /usr/local/bin/rayspa /usr/local/bin/rayctl || true
		fi
		HANDED_OVER=1
		/usr/local/bin/rayctl install -relay "$RELAY_BUNDLE" ${INSTALLED_PKGS:+-packages "$INSTALLED_PKGS"}
		return
	fi

	# raycontrol v0 goes first, when asked: it holds 443 and its nftables
	# table drops the node's traffic. The release's own rayctl backs it up,
	# then removes only what v0 installed.
	if [[ $REMOVE_V0 == 1 ]]; then
		# The rest of the host first: if it cannot run a node anyway, v0 and
		# its firewall stay where they are.
		local pre=0
		"$tmp/rayctl" check -allow-v0 "$@" || pre=$?
		case $pre in
		0) ;;
		126) die "cannot run programs from $tmp (mounted noexec?): run again with TMPDIR set to a directory that allows it" ;;
		*) die "this host cannot run a node even without raycontrol v0 (see above); v0 was left as it was" ;;
		esac
		local purge=()
		if [[ $PURGE_V0 == 1 ]]; then purge=(-purge-packages); fi
		"$tmp/rayctl" legacy -remove -yes "${purge[@]}" || die "raycontrol v0 was not removed completely (see above)"
	fi

	# -check lists what -remove-v0 would take (rayctl legacy only reads).
	if [[ $CHECK_ONLY == 1 ]]; then
		"$tmp/rayctl" legacy || true
	fi

	# The host first, with the release's own rayctl: nothing of raycontrol
	# is installed yet.
	local status=0
	"$tmp/rayctl" check "$@" || status=$?
	case $status in
	0) ;;
	126) die "cannot run programs from $tmp (mounted noexec?): run again with TMPDIR set to a directory that allows it" ;;
	2) die "the arguments are not right (see above)" ;;
	*) die "this host cannot run a node (see above); it was left as it was" ;;
	esac
	if [[ $CHECK_ONLY == 1 ]]; then
		log "check only: nothing installed"
		return 0
	fi

	install -m 0755 "$tmp/rayd" "$tmp/rayspa" "$tmp/rayctl" /usr/local/bin/
	# SELinux (RHEL family): binaries get the label of their place, not of $tmp.
	if command -v restorecon >/dev/null; then
		restorecon /usr/local/bin/rayd /usr/local/bin/rayspa /usr/local/bin/rayctl || true
	fi
	# The data plane from the same verified release, staged for rayctl.
	local dataplane=()
	if [[ -f $tmp/xray || -f $tmp/niko-server ]]; then
		dataplane=(-dataplane "$tmp")
	else
		log "the release has no data plane (xray, niko-server): install them later"
	fi
	# From here rayctl install owns the packages: it records them, and
	# rayctl uninstall -purge-packages takes them back.
	HANDED_OVER=1
	/usr/local/bin/rayctl install -checked ${INSTALLED_PKGS:+-packages "$INSTALLED_PKGS"} "${dataplane[@]}" "$@"
}

# Sourcing the file (tests) only defines the functions.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
