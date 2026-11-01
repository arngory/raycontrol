#!/usr/bin/env bash

set -uo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

step() {
    echo -e "\n${YELLOW}--- $1 ---${NC}"
}

remove_file_if_exists() {
    local file_path=$1
    if [[ -e "$file_path" ]]; then
        rm -rf "$file_path"
        echo "Removed: $file_path"
    else
        echo "Not found (OK): $file_path"
    fi
}

remove_dir_if_exists() { remove_file_if_exists "$1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Must be run as root.${NC}" >&2
    exit 1
fi

step "Ray-AIO Smart Uninstaller"

cat <<-EOF
This script will:
1) Disable & stop Ray-AIO services and PostgreSQL
2) Flush firewall rules
3) Drop the PostgreSQL database and user
4) Remove certificates & configuration files
5) (Optionally) Remove dependencies and the XanMod kernel
EOF

read -rp "Proceed with uninstallation? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    echo "Cancelled."
    exit 1
fi

DOMAIN=""
INSTALL_CONF="/etc/ray-aio/install.conf"
if [[ -f "$INSTALL_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$INSTALL_CONF" || true
fi

step "Phase 1: Shutting Down and Cleaning Up Services"

step "Stopping & Disabling Services"
for svc in xray hysteria-server postgresql; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "Stopping $svc..."
        systemctl stop "$svc" || true
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        echo "Disabling $svc..."
        systemctl disable "$svc" || true
    fi
done

step "Flushing Firewall Rules"
if command -v nft >/dev/null; then
    nft flush ruleset || true
    nft -s list ruleset > /etc/nftables.conf || true
    echo "Cleared NFTables rules; saved empty config."
else
    echo "nft command not found; skipping."
fi

step "Dropping PostgreSQL Database and User"
SECRETS_DIR="/root/.secrets"
DB_CONF="${SECRETS_DIR}/db.conf"
if [[ -f "$DB_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$DB_CONF" || true
elif [[ -f "/etc/ray-aio/install.conf" ]]; then
    # shellcheck source=/dev/null
    source "/etc/ray-aio/install.conf" || true
fi

if [[ -n "${PG_DB_NAME:-}" && -n "${PG_USER:-}" ]]; then
    echo "Dropping database '$PG_DB_NAME' and user '$PG_USER'..."
    # Ensure PostgreSQL service is running to accept connections at drop time
    systemctl is-active --quiet postgresql || {
        echo "PostgreSQL not running, starting service temporarily..."
        systemctl start postgresql || { echo "Failed to start PostgreSQL service."; exit 1; }
        STOP_PG=true
    }

    # Retry dropping DB and user with timeout
    for i in {1..5}; do
        if sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$PG_DB_NAME\";"; then
            break
        else
            echo "Failed to drop database, retrying in 2 seconds..."
            sleep 2
        fi
    done

    for i in {1..5}; do
        if sudo -u postgres psql -c "DROP USER IF EXISTS \"$PG_USER\";"; then
            break
        else
            echo "Failed to drop user, retrying in 2 seconds..."
            sleep 2
        fi
    done

    # If started PostgreSQL above, stop it now
    if [[ $STOP_PG == true ]]; then
        echo "Stopping PostgreSQL service started temporarily..."
        systemctl stop postgresql || true
    fi

    echo "PostgreSQL cleanup complete."
else
    echo "PostgreSQL config not found or DB name/user variables not set; skipping database drop."
fi

step "Phase 2: Removing Files and Configurations"

step "Removing Systemd Unit Files"
remove_file_if_exists "/etc/systemd/system/xray.service"
remove_file_if_exists "/etc/systemd/system/hysteria-server.service"
systemctl daemon-reload || true

step "Removing Let's Encrypt Certificate"
if [[ -n "${DOMAIN}" ]] && command -v certbot >/dev/null; then
    if certbot certificates --cert-name "$DOMAIN" >/dev/null; then
        certbot delete --non-interactive --cert-name "$DOMAIN" || true
        echo "Deleted certificate for $DOMAIN."
    else
        echo "No certificate found for '$DOMAIN'."
    fi
else
    echo "Domain variable not set or certbot not found; skipping certificate removal."
fi
remove_file_if_exists "/etc/letsencrypt/renewal-hooks/post/reload_services.sh"

step "Removing Binaries, Configs, and Logs"
remove_file_if_exists "/usr/local/bin/xray"
remove_file_if_exists "/usr/local/bin/hysteria-server"
remove_file_if_exists "/usr/local/bin/raycontrol"
remove_file_if_exists "/usr/local/bin/apply_nftables_xray.sh"
remove_dir_if_exists "/etc/ray-aio"
remove_dir_if_exists "/var/backups/ray-aio"
remove_dir_if_exists "/etc/xray"
remove_dir_if_exists "/var/log/xray"
remove_dir_if_exists "/etc/hysteria"
remove_dir_if_exists "/root/.secrets"
remove_file_if_exists "/var/log/raycontrol.log"

step "Phase 3: Removing Packages"

CORE_DEPS=(
    curl wget unzip jq nftables certbot qrencode
    python3-certbot-dns-cloudflare uuid-runtime
    socat gawk dnsutils bc bsdmainutils
    postgresql postgresql-client postgresql-contrib
)

echo "The following packages were installed as dependencies:"
echo -e "${YELLOW}${CORE_DEPS[*]}${NC}"
echo "Removing these may affect other applications on the system."
read -rp "Do you want to remove these packages? [y/N]: " RM_DEPS
if [[ "${RM_DEPS,,}" == "y" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "${CORE_DEPS[@]}" || true
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true
    echo -e "${GREEN}Dependencies removed.${NC}"
else
    echo "Skipped dependency removal."
fi

step "Optional: XanMod Kernel"
if [[ -f "/etc/apt/sources.list.d/xanmod-kernel.list" ]]; then
    read -rp "Do you want to remove the XanMod repository and any installed XanMod kernels? [y/N]: " RX
    if [[ "${RX,,}" == "y" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "linux-xanmod-*" || true
        remove_file_if_exists "/etc/apt/sources.list.d/xanmod-kernel.list"
        remove_file_if_exists "/etc/apt/trusted.gpg.d/xanmod-kernel.gpg"
        apt-get update || true
        echo -e "${YELLOW}A reboot is required to switch to the previous kernel.${NC}"
    else
        echo "Skipped XanMod removal."
    fi
else
    echo "XanMod repository not found; skipping."
fi

step "Uninstallation Complete"
echo -e "${GREEN}All known Ray-AIO script artifacts have been removed.${NC}"
echo "Please reboot the system if you removed a kernel."
