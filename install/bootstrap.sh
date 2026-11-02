#!/usr/bin/env bash
# raycontrol bootstrap: downloads a release, verifies its minisign signature
# and checksum, installs rayd, rayspa and rayctl, then runs "rayctl install"
# with the arguments given here (e.g. -host 203.0.113.7 -domain example.com).
#
#   curl -fsSL https://raw.githubusercontent.com/arngory/raycontrol/main/install/bootstrap.sh -o bootstrap.sh
#   less bootstrap.sh
#   sudo bash bootstrap.sh -host <public address> [-domain <domain>]
#
# Works on any systemd-based Linux with apt, dnf, zypper or pacman; tested on
# Debian 12/13, Ubuntu 24.04 and Rocky Linux 9/10 (rayctl install checks the
# rest). The signature is checked with openssl, so minisign is not needed.
#
# RAYCONTROL_VERSION=v0.2.0 pins a release; default is the latest one.
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
	local pkgs=()
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

main() {
	[[ $EUID -eq 0 ]] || die "run as root"
	[[ -d /run/systemd/system ]] || die "systemd is required"
	case "$(uname -m)" in
	x86_64) ARCH=amd64 ;;
	aarch64) ARCH=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	install_deps

	# Global: the EXIT trap runs after main has returned.
	BOOT_TMP="$(mktemp -d)"
	trap 'rm -rf "$BOOT_TMP"' EXIT
	local tmp=$BOOT_TMP
	if [[ -n ${RAYCONTROL_LOCAL_DIR:-} ]]; then
		log "installing from $RAYCONTROL_LOCAL_DIR without verification (test mode)"
		cp "$RAYCONTROL_LOCAL_DIR"/{rayd,rayspa,rayctl} "$tmp/"
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
		(cd "$tmp" && grep " ${tarball}\$" SHA256SUMS | sha256sum -c -) || die "checksum mismatch"
		tar -xzf "$tmp/$tarball" -C "$tmp"
	fi
	install -m 0755 "$tmp/rayd" "$tmp/rayspa" "$tmp/rayctl" /usr/local/bin/
	# SELinux (RHEL family): binaries get the label of their place, not of $tmp.
	if command -v restorecon >/dev/null; then
		restorecon /usr/local/bin/rayd /usr/local/bin/rayspa /usr/local/bin/rayctl || true
	fi
	/usr/local/bin/rayctl install ${INSTALLED_PKGS:+-packages "$INSTALLED_PKGS"} "$@"
}

# Sourcing the file (tests) only defines the functions.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
fi
