#!/usr/bin/env bash
set -euo pipefail

# --- Argument Parsing ---
DEBUG=false
VERBOSE_FLAG=""
if [[ "${1:-}" == "--debug" || "${1:-}" == "--verbose" ]]; then
    DEBUG=true
    VERBOSE_FLAG=$1
    set -x
    shift
fi

# --- Configuration: Paths ---
RAY_AIO_DIR="/etc/ray-aio"
SETTINGS_FILE="$RAY_AIO_DIR/settings.json"
INSTALL_CONF="$RAY_AIO_DIR/install.conf"
LOG_FILE="/var/log/raycontrol.log"
RAYCONTROL_PATH="/usr/local/bin/raycontrol"
APPLY_NFTABLES_SCRIPT="/usr/local/bin/apply_nftables_xray.sh"
XRAY_DIR="/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
XRAY_CONFIG="$XRAY_DIR/config.json"
XRAY_CONFIG_TPL="$XRAY_DIR/config.json.tpl"
XRAY_BIN="/usr/local/bin/xray"
XRAY_SERVICE="/etc/systemd/system/xray.service"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONFIG="$HYSTERIA_DIR/config.yaml"
HYSTERIA_AUTH_SCRIPT="$HYSTERIA_DIR/auth.sh"
HYSTERIA_DB_CONF="$HYSTERIA_DIR/db.conf"
HYSTERIA_BIN="/usr/local/bin/hysteria-server"
HYSTERIA_SERVICE="/etc/systemd/system/hysteria-server.service"
SECRETS_DIR="/root/.secrets"
CLOUDFLARE_INI="$SECRETS_DIR/cloudflare.ini"
DB_CONF="$SECRETS_DIR/db.conf"
LE_POST_HOOK_DIR="/etc/letsencrypt/renewal-hooks/post"
LE_POST_HOOK_SCRIPT="$LE_POST_HOOK_DIR/reload_services.sh"
TMP_DIR="$(mktemp -d)"
TEMP_AWK="${TMP_DIR}/check_x86_v_level.awk"
ORIG_DIR="$PWD"

# --- Configuration: urls ---

# hysteria2
RAW_TAG=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r .tag_name)
ENC_TAG=${RAW_TAG//\//%2F}
HYSTERIA_URL_BIN="https://github.com/apernet/hysteria/releases/download/${ENC_TAG}/hysteria-linux-amd64"
HYSTERIA_URL_HASHES="https://github.com/apernet/hysteria/releases/download/${ENC_TAG}/hashes.txt"

# xray
XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)
TEMP_ZIP="${TMP_DIR}/Xray-linux-64.zip"
TEMP_DGST="${TMP_DIR}/Xray-linux-64.zip.dgst"



# --- Configuration: Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- Logging Functions ---
log_msg() {
    local level_color="$1"; local level_text="$2"; local message="$3"
    local timestamp; timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level_text] $message" | tee -a "$LOG_FILE" > /dev/null
    echo -e "${level_color}[$timestamp] [$level_text] ${message}${NC}"
}
log_info() { log_msg "$GREEN" "INFO" "$1"; }
log_warn() { log_msg "$YELLOW" "WARN" "$1"; }
log_error() { log_msg "$RED" "ERROR" "$1" >&2; }

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

trap 'cleanup' ERR

cleanup() {
    set +e
    log_error "--- An error occurred. Rolling back changes... ---"

    if systemctl is-active --quiet nftables; then
        log_warn "Flushing firewall rules..."
        nft flush ruleset
    fi

    if command -v xray &>/dev/null; then
        systemctl disable --now xray &>/dev/null
        rm -f "$XRAY_BIN" "$XRAY_SERVICE" "$XRAY_CONFIG_TPL" "$XRAY_CONFIG"
    fi

    if command -v hysteria-server &>/dev/null; then
        systemctl disable --now hysteria-server &>/dev/null
        rm -f "$HYSTERIA_BIN" "$HYSTERIA_SERVICE"
    fi

    if command -v psql &>/dev/null && [ -f "$DB_CONF" ]; then
        log_warn "Dropping PostgreSQL database and user..."
        # shellcheck source=/dev/null
        source "$DB_CONF"
        if [[ -n "${PG_DB_NAME:-}" && -n "${PG_USER:-}" ]]; then
           sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$PG_DB_NAME\";" &>/dev/null
           sudo -u postgres psql -c "DROP USER IF EXISTS \"$PG_USER\";" &>/dev/null
        fi
        log_warn "Purging PostgreSQL packages..."
        DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove postgresql* &>/dev/null
    fi

    systemctl daemon-reload

    log_warn "Removing configuration directories..."
    rm -rf "$RAY_AIO_DIR" "$XRAY_DIR" "$HYSTERIA_DIR" "$SECRETS_DIR" "$LE_POST_HOOK_DIR"

    if [[ -n "${XANMOD_PKG_NAME_INSTALLED:-}" ]]; then
        log_warn "Uninstalling XanMod Kernel package: ${XANMOD_PKG_NAME_INSTALLED}"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "$XANMOD_PKG_NAME_INSTALLED"
    fi

    log_warn "Removing temporary files..."
    rm -f "$TEMP_AWK" "$TEMP_ZIP" "$RAYCONTROL_PATH"

    cd "$ORIG_DIR"
    rm -rf "${TMP_DIR}"
    log_warn "Rollback complete. The system may require manual cleanup."
    exit 1
}

validate_port() {
    local port_val="$1"; local port_name="$2"; local min_val="${3:-1}"
    if ! [[ "$port_val" =~ ^[0-9]+$ ]] || (( port_val < min_val || port_val > 65535 )); then
        log_error "Port '$port_name' ($port_val) must be a valid number between $min_val and 65535."; exit 1
    fi
}

if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root."; exit 1
fi

cd "${TMP_DIR}"

log_info "--- Installing Core Dependencies ---"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget unzip jq nftables certbot qrencode python3-certbot-dns-cloudflare uuid-runtime openssl socat gawk dnsutils bc coreutils watch postgresql postgresql-client bsdmainutils

read -rp "Domain (e.g. your.domain.com): " DOMAIN
read -rp "Cloudflare API Token: " CF_API_TOKEN
read -rp "Let’s Encrypt email: " EMAIL

log_info "--- Verifying Cloudflare API Token ---"
CF_ZONE_ID_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json")
if ! echo "$CF_ZONE_ID_RESPONSE" | jq -e '.success' &>/dev/null; then
    ERROR_MSG=$(echo "$CF_ZONE_ID_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null || echo "Unknown error")
    log_error "Cloudflare API token is invalid or lacks 'Zone.Read' permissions. API response: $ERROR_MSG"; exit 1
fi
log_info "Cloudflare API Token appears to be valid."

echo
log_warn "Specify three distinct TCP ports for Port Knocking (e.g. 10001 10002 10003):"
read -rp "Knock ports: " K1 K2 K3
read -rp "Port for VLESS/XTLS (TCP, 200–65535, default 443): " PORT_VLESS; PORT_VLESS=${PORT_VLESS:-443}
read -rp "Port for Trojan (TCP, 200–65535, default 8443): " PORT_TROJAN; PORT_TROJAN=${PORT_TROJAN:-8443}
read -rp "Port for Hysteria2 (UDP, 200-65535, default 3478): " PORT_HYSTERIA; PORT_HYSTERIA=${PORT_HYSTERIA:-3478}

validate_port "$K1" "K1"; validate_port "$K2" "K2"; validate_port "$K3" "K3"
if [[ "$K1" == "$K2" || "$K2" == "$K3" || "$K1" == "$K3" ]]; then
  log_error "Knock ports must be three distinct numbers."; exit 1
fi
validate_port "$PORT_VLESS" "PORT_VLESS" 200
validate_port "$PORT_TROJAN" "PORT_TROJAN" 200
validate_port "$PORT_HYSTERIA" "PORT_HYSTERIA" 200

echo
read -rp "Install XanMod kernel for BBRv3 and other optimizations? [y/N]: " INSTALL_XANMOD

log_info "--- Pre-flight Checks ---"
SSH_PORT=$(ss -Htnlp | awk '/sshd/ && /LISTEN/ { sub(".*:", "", $4); print $4; exit }')
log_info "Detected SSH port: $SSH_PORT"
for P_VAR in PORT_VLESS PORT_TROJAN; do
    VAL=${!P_VAR}
    if ss -Htlpn "sport = :$VAL" | grep -q .; then log_error "TCP Port $VAL is already in use."; exit 1; fi
    log_info "TCP Port $VAL is available."
done
if ss -Hlupn "sport = :$PORT_HYSTERIA" | grep -q .; then log_error "UDP Port $PORT_HYSTERIA is already in use."; exit 1; fi
log_info "UDP Port $PORT_HYSTERIA is available."

echo
log_warn "--- Installation Summary ---"
echo "Domain:             $DOMAIN"
echo "VLESS Port (TCP):   $PORT_VLESS"
echo "Trojan Port (TCP):  $PORT_TROJAN"
echo "Hysteria2 Port (UDP):$PORT_HYSTERIA"
echo "Knock Ports:        $K1, $K2, $K3"
if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then echo "Install XanMod:     Yes"; fi
echo -e "${YELLOW}----------------------------${NC}\n"

read -rp "Proceed with installation? [y/N]: " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then echo "Installation cancelled."; trap - ERR; exit 0; fi

mkdir -p "$RAY_AIO_DIR" "/var/backups/ray-aio" "$SECRETS_DIR" "$HYSTERIA_DIR"

cat > "$INSTALL_CONF" <<EOF
DOMAIN="$DOMAIN"
PORT_VLESS="$PORT_VLESS"
PORT_TROJAN="$PORT_TROJAN"
PORT_HYSTERIA="$PORT_HYSTERIA"
SSH_PORT="$SSH_PORT"
K1="$K1"
K2="$K2"
K3="$K3"
EOF

cat > "$SETTINGS_FILE" <<EOF
{
  "alpn": ["h2", "http/1.1"],
  "vless_flow": "xtls-rprx-vision"
}
EOF
VLESS_FLOW=$(jq -r '.vless_flow' "$SETTINGS_FILE")
XRAY_ALPN=$(jq -c '.alpn' "$SETTINGS_FILE")

log_info "--- Setting up PostgreSQL Database ---"
PG_USER="ray_aio_user"
PG_DB_NAME="ray_aio_db"
PG_PASSWORD=$(head -c32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
cat > "$DB_CONF" <<EOF
PG_HOST="localhost"
PG_PORT="5432"
PG_USER="$PG_USER"
PG_DB_NAME="$PG_DB_NAME"
PG_PASSWORD="$PG_PASSWORD"
EOF
chmod 600 "$DB_CONF"
cp "$DB_CONF" "$HYSTERIA_DB_CONF"
chown nobody:nogroup "$HYSTERIA_DB_CONF"
chmod 600 "$HYSTERIA_DB_CONF"

systemctl enable --now postgresql

if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$PG_DB_NAME"; then
    log_warn "Database '$PG_DB_NAME' already exists. Dropping it..."
    sudo -u postgres psql -c "DROP DATABASE \"$PG_DB_NAME\";"
fi
if sudo -u postgres psql -tqc "SELECT 1 FROM pg_roles WHERE rolname = '$PG_USER';" | grep -q 1; then
    log_warn "Role '$PG_USER' already exists. Dropping it..."
    sudo -u postgres psql -c "DROP ROLE IF EXISTS \"$PG_USER\";"
fi

sudo -u postgres psql -c "CREATE DATABASE \"$PG_DB_NAME\";"
sudo -u postgres psql -c "CREATE USER \"$PG_USER\" WITH PASSWORD '$PG_PASSWORD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$PG_DB_NAME\" TO \"$PG_USER\";"
sudo -u postgres psql -d "$PG_DB_NAME" -c \
  "GRANT USAGE, CREATE ON SCHEMA public TO \"$PG_USER\";"
export PGPASSWORD=$PG_PASSWORD
psql -h localhost -U "$PG_USER" -d "$PG_DB_NAME" -c "
  CREATE TABLE xray_users (
    id SERIAL PRIMARY KEY,
    type VARCHAR(10) NOT NULL CHECK (type IN ('vless','trojan')),
    user_id VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE hysteria_users (
    id SERIAL PRIMARY KEY,
    password VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
  );
"
unset PGPASSWORD
log_info "PostgreSQL user '$PG_USER' and database '$PG_DB_NAME' created."
log_info "PostgreSQL is configured for local network connections only by default via pg_hba.conf."

if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    log_info "--- Setting up XanMod Repository ---"
    DEBIAN_FRONTEND=noninteractive apt-get install -y gpg
    echo 'deb http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-kernel.list
    wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/xanmod-kernel.gpg
    log_info "--- Updating sources for XanMod ---"; apt-get update
    log_info "--- Checking CPU microarchitecture level ---"
    cat > "$TEMP_AWK" <<'AWK'
#!/usr/bin/awk -f
BEGIN {
    while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
    if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
    if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
    if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
    if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
    if (level > 0) { print "CPU supports x86-64-v" level; exit level + 1 }
    exit 1
}
AWK
    chmod +x "$TEMP_AWK"; XANMOD_PKG_NAME="linux-xanmod-lts-x64v1"; CPU_LEVEL_EXIT_CODE=0
    "$TEMP_AWK" || CPU_LEVEL_EXIT_CODE=$?; rm -f "$TEMP_AWK"
    case $CPU_LEVEL_EXIT_CODE in
        3) XANMOD_PKG_NAME="linux-xanmod-x64v2" ;;
        4) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        5) XANMOD_PKG_NAME="linux-xanmod-x64v3" ;;
        *) XANMOD_PKG_NAME="linux-xanmod-lts-x64v1" ;;
    esac
    log_info "--- Installing XanMod Kernel ($XANMOD_PKG_NAME) ---"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$XANMOD_PKG_NAME"; XANMOD_PKG_NAME_INSTALLED=$XANMOD_PKG_NAME
fi

UUID_VLESS=$(uuidgen); PASSWORD_TROJAN=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
PASSWORD_HYSTERIA=$(head -c32 /dev/urandom | base64 | tr '+/' '_-'); PASSWORD_HYSTERIA_OBFS=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
echo "PASSWORD_HYSTERIA_OBFS=\"$PASSWORD_HYSTERIA_OBFS\"" >> "$INSTALL_CONF"

log_info "--- Validating DNS Records ---"
SERVER_IP=$(curl -s https://4.ipwho.de/ip); if [[ -z "$SERVER_IP" ]]; then log_error "Could not determine server's public IP address."; exit 1; fi
log_info "This server's public IP is: $SERVER_IP"; log_warn "Please ensure you have an A record for $DOMAIN pointing to this IP in your Cloudflare DNS."
log_warn "Waiting 30 seconds for DNS to propagate..."; for i in {30..1}; do printf "\rWaiting... %2d" "$i"; sleep 1; done; echo -e "\rDone waiting. Now checking DNS resolution."
RESOLVED_IP=$(dig +short "$DOMAIN" || echo ""); log_info "Resolved IP for $DOMAIN is: ${RESOLVED_IP:-Not found}"
if [[ "$RESOLVED_IP" != "$SERVER_IP" ]]; then log_error "DNS validation failed! The domain $DOMAIN does not resolve to this server's IP ($SERVER_IP)."; exit 1; fi
log_info "DNS validation successful!"

log_info "--- Storing Initial Users in PostgreSQL ---"
export PGPASSWORD=$PG_PASSWORD
psql -h localhost -U "$PG_USER" -d "$PG_DB_NAME" -c "INSERT INTO xray_users (type, user_id) VALUES ('vless', '$UUID_VLESS');"
psql -h localhost -U "$PG_USER" -d "$PG_DB_NAME" -c "INSERT INTO xray_users (type, user_id) VALUES ('trojan', '$PASSWORD_TROJAN');"
psql -h localhost -U "$PG_USER" -d "$PG_DB_NAME" -c "INSERT INTO hysteria_users (password) VALUES ('$PASSWORD_HYSTERIA');"
unset PGPASSWORD
log_info "Initial VLESS, Trojan, and Hysteria users saved to the database."

cat > "$RAYCONTROL_PATH" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DEBUG=false
VERBOSE_FLAG=""

if [[ "${1:-}" == "--debug" || "${1:-}" == "--verbose" ]]; then
  DEBUG=true
  VERBOSE_FLAG=$1
  set -x
  shift
fi

# --- Config Paths ---
RAY_AIO_DIR="/etc/ray-aio"
SECRETS_DIR="/root/.secrets"
DB_CONF="$SECRETS_DIR/db.conf"
XRAY_DIR="/etc/xray"
XCONF="${XRAY_DIR}/config.json"
XCONF_TPL="${XRAY_DIR}/config.json.tpl"
HYSTERIA_DIR="/etc/hysteria"
HYSTERIA_CONF="${HYSTERIA_DIR}/config.yaml"
BACKUP_DIR="/var/backups/ray-aio"
INSTALL_CONF="${RAY_AIO_DIR}/install.conf"
SETTINGS_FILE="${RAY_AIO_DIR}/settings.json"
LOG_FILE="/var/log/raycontrol.log"
ENABLED_FLAG="${XRAY_DIR}/enabled.flag"
NFT_TABLE="inet filter"
NFT_SET="xray_clients"

# --- Colors ---
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

# --- Logging ---
log_msg() {
  local level_color="$1"; local level_text="$2"; local message="$3"
  local timestamp; timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] [$level_text] $message" >> "$LOG_FILE"
  echo -e "${level_color}[$timestamp] [$level_text] ${message}${NC}"
}
log_info() { log_msg "$GREEN" "INFO" "$1"; }
log_warn() { log_msg "$YELLOW" "WARN" "$1"; }
log_error() { log_msg "$RED" "ERROR" "$1" >&2; }

# --- DB Connection ---
if [ ! -f "$DB_CONF" ]; then log_error "Database configuration not found at $DB_CONF"; exit 1; fi
# shellcheck source=/dev/null
source "$DB_CONF"; export PGPASSWORD=$PG_PASSWORD
PSQL_CMD="psql -h $PG_HOST -U $PG_USER -d $PG_DB_NAME -qtAX"

# --- Helper Functions ---
check_db_connection() {
  if ! $PSQL_CMD -c "SELECT 1" >/dev/null; then
    log_error "Failed to connect to PostgreSQL database '$PG_DB_NAME' as user '$PG_USER'."
    exit 1
  fi
}

reload_services(){
  if [[ -f "$ENABLED_FLAG" && "$(cat "$ENABLED_FLAG")" == "enabled" ]]; then
    case "${1:-all}" in
      xray)    systemctl restart xray; log_info "Xray service reloaded." ;;
      hysteria) systemctl restart hysteria-server; log_info "Hysteria2 service reloaded." ;;
      *)       systemctl restart xray; systemctl restart hysteria-server; log_info "All services reloaded." ;;
    esac
  else
    log_warn "Services are not enabled. Skipping reload."
  fi
}

regenerate_configs() {
  log_info "Regenerating service configurations from PostgreSQL database..."
  local vless_flow; vless_flow=$(jq -r '.vless_flow' "$SETTINGS_FILE")
  local xray_config; xray_config=$(cat "$XCONF_TPL")
  local vless_clients_json; vless_clients_json=$($PSQL_CMD -c "SELECT json_agg(json_build_object('id', user_id, 'flow', '$vless_flow')) FROM xray_users WHERE type = 'vless';")
  local trojan_clients_json; trojan_clients_json=$($PSQL_CMD -c "SELECT json_agg(json_build_object('password', user_id)) FROM xray_users WHERE type = 'trojan';")
  if [[ "$vless_clients_json" != "null" ]]; then
    xray_config=$(echo "$xray_config" | jq --argjson clients "$vless_clients_json" '.inbounds[0].settings.clients = $clients')
  else
    xray_config=$(echo "$xray_config" | jq '.inbounds[0].settings.clients = []')
  fi
  if [[ "$trojan_clients_json" != "null" ]]; then
    xray_config=$(echo "$xray_config" | jq --argjson clients "$trojan_clients_json" '.inbounds[1].settings.clients = $clients')
  else
    xray_config=$(echo "$xray_config" | jq '.inbounds[1].settings.clients = []')
  fi
  echo "$xray_config" > "$XCONF"
  log_info "Xray config.json regenerated."
}

show_qr() {
  local type="$1"
  local query="$2"
  if ! command -v qrencode >/dev/null; then log_error "Error: 'qrencode' is not installed."; return 1; fi
  # fetch list of IDs/passwords
  local -a list matches
  if [[ "$type" == "vless" ]]; then
    mapfile -t list < <($PSQL_CMD -c "SELECT user_id FROM xray_users WHERE type='vless';")
  elif [[ "$type" == "trojan" ]]; then
    mapfile -t list < <($PSQL_CMD -c "SELECT user_id FROM xray_users WHERE type='trojan';")
  elif [[ "$type" == "hysteria" ]]; then
    mapfile -t list < <($PSQL_CMD -c "SELECT password FROM hysteria_users;")
  else
    log_error "Invalid type specified for QR code generation."
    return 1
  fi
  # find matches by first letter
  for item in "${list[@]}"; do
    if [[ "${item:0:1}" == "$query" ]]; then
      matches+=("$item")
    fi
  done
  if (( ${#matches[@]} == 0 )); then
    log_error "No entries starting with '$query'."
    return 1
  elif (( ${#matches[@]} == 1 )); then
    _print_qr "$type" "${matches[0]}"
  else
    echo "Multiple matches found:"
    for i in "${!matches[@]}"; do
      printf " [%d] %s\n" $((i+1)) "${matches[i]}"
    done
    read -rp "Select number: " sel
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel<1 || sel>${#matches[@]} )); then
      log_error "Invalid selection."
      return 1
    fi
    _print_qr "$type" "${matches[sel-1]}"
  fi
}

_print_qr() {
  local type="$1"; local id="$2"
  # load environment
  source "$INSTALL_CONF"
  local vless_flow; vless_flow=$(jq -r '.vless_flow' "$SETTINGS_FILE")
  local alpn; alpn=$(jq -r '.alpn | join(",")' "$SETTINGS_FILE")
  local uri name
  case "$type" in
    vless)
      name="${DOMAIN}-VLESS-${id:0:8}"
      uri="vless://${id}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=tls&flow=${vless_flow}&alpn=${alpn}&sni=${DOMAIN}#${name}"
      ;;
    trojan)
      name="${DOMAIN}-Trojan-${id:0:8}"
      uri="trojan://${id}@${DOMAIN}:${PORT_TROJAN}?security=tls&type=tcp&alpn=${alpn}&sni=${DOMAIN}#${name}"
      ;;
    hysteria)
      local obfs_pass; obfs_pass=${PASSWORD_HYSTERIA_OBFS:-$(grep PASSWORD_HYSTERIA_OBFS "$INSTALL_CONF" | cut -d'"' -f2)}
      name="${DOMAIN}-Hysteria2-${id:0:6}"
      uri="hysteria2://${id}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${obfs_pass}#${name}"
      ;;
  esac
  log_warn "--- QR Code for: $name ---"
  qrencode -t ANSIUTF8 "$uri"
  echo -e "${YELLOW}URI: ${uri}${NC}"
}

# --- Monitor with throughput ---
monitor() {
  for cmd in tput clear; do
    command -v "$cmd" >/dev/null || { log_error "$cmd is required for monitor"; exit 1; }
  done
  trap 'tput cnorm; tput sgr0; exit 0' INT TERM
  tput civis
  source "$INSTALL_CONF" || true
  while :; do
    clear
    local c_rst c_bold c_hdr c_ok c_warn c_fail
    c_rst=$(tput sgr0)
    c_bold=$(tput bold)
    c_hdr=$(tput setaf 6)
    c_ok=$(tput setaf 2)
    c_warn=$(tput setaf 3)
    c_fail=$(tput setaf 1)
    printf '%s%s┌─ Ray-AIO Live Monitor ─────────────────────────────────────┐%s\n' "$c_hdr" "$c_bold" "$c_rst"
    printf '%s│ %s │%s\n' "$c_hdr" "$(date '+%Y-%m-%d %H:%M:%S')" "$c_rst"
    printf '%s└────────────────────────────────────────────────────────────┘%s\n\n' "$c_hdr" "$c_rst"
    # Service status
    printf '%sService Status%s\n' "$c_bold" "$c_rst"
    printf ' xray: %s%s%s\n' "$(systemctl is-active xray &>/dev/null && echo "${c_ok}UP" || echo "${c_fail}DOWN")" "$c_rst"
    printf ' hysteria: %s%s%s\n\n' "$(systemctl is-active hysteria-server &>/dev/null && echo "${c_ok}UP" || echo "${c_fail}DOWN")" "$c_rst"
    # Connections & throughput
    printf '%sConnections & Throughput%s\n' "$c_bold" "$c_rst"
    local v_port=${PORT_VLESS:-443} t_port=${PORT_TROJAN:-8443} h_port=${PORT_HYSTERIA:-3478}
    local v_conn t_conn h_conn
    v_conn=$(ss -Htn state established "( dport = :$v_port )" | wc -l)
    t_conn=$(ss -Htn state established "( dport = :$t_port )" | wc -l)
    h_conn=$(ss -Hun state established "( dport = :$h_port )" | wc -l)
    printf ' VLESS/XTLS (TCP :%s): %s connections\n' "$v_port" "$v_conn"
    printf ' Trojan (TCP :%s): %s connections\n' "$t_port" "$t_conn"
    printf ' Hysteria2 (UDP :%s): %s connections\n\n' "$h_port" "$h_conn"
    # Throughput
    printf '%sThroughput (bytes/sec)%s\n' "$c_bold" "$c_rst"
    printf ' VLESS: %s\n' "$(ss -i state established "( dport = :$v_port )" | awk '/bytes_acked/ {print $2; exit}')"
    printf ' Trojan: %s\n' "$(ss -i state established "( dport = :$t_port )" | awk '/bytes_acked/ {print $2; exit}')"
    printf ' Hysteria2: %s\n\n' "$c_bold" "$c_rst"
    sleep 5
  done
}

# --- Commands ---
help() {
  cat <<MSG
Usage: raycontrol [args] [--debug|--verbose]
Services Management:
  enable           Enable all services + firewall and persist rules
  disable          Disable all services + firewall and persist flushed rules
  status           Show service states, connections, and bandwidth usage
  monitor          Live monitor the status command (updates every 5s)
User & QR Management:
  list-users       List all users
  add-user         Add a new user. Type: [vless|trojan|hysteria]
  del-user         Delete a user by ID/Password
  show-qr TYPE Q  Show QR code by first-letter Q
Disaster Recovery:
  backup           Create a full backup of configs & database
  restore FILE     Restore from backup archive
IP Whitelist & Firewall:
  list-ips         List whitelisted IPs and timeouts
  add-ip IP        Whitelist an IP
  del-ip IP        Remove a whitelisted IP
Configuration:
  regenerate-configs  Force regeneration of service configs
MSG
}

enable_all() {
  echo "enabled" > "$ENABLED_FLAG"
  /usr/local/bin/apply_nftables_xray.sh && nft -s list ruleset > /etc/nftables.conf
  reload_services all
  log_info "All services and firewall enabled."
}

disable_all() {
  echo "disabled" > "$ENABLED_FLAG"
  systemctl stop xray hysteria-server
  nft flush ruleset && nft -s list ruleset > /etc/nftables.conf
  log_info "All services and firewall disabled."
}

show_status() {
  log_info "=== Service Status ==="
  systemctl is-active xray &>/dev/null && log_info "xray: running" || log_warn "xray: inactive/failed"
  systemctl is-active hysteria-server &>/dev/null && log_info "hysteria: running" || log_warn "hysteria: inactive/failed"
  log_info "=== Firewall Status ==="
  nft list ruleset | grep -q "table inet filter" && log_info "nftables rules loaded" || log_warn "nftables rules NOT loaded"
  [[ -f "$ENABLED_FLAG" ]] && log_info "services marked as: $(cat "$ENABLED_FLAG")" || log_warn "services marked as: disabled"
}

list_users() {
  log_warn "--- Xray Users ---"
  $PSQL_CMD -c "SELECT type, user_id FROM xray_users ORDER BY type, id;" | sed 's/|/\t/' | column -t -s $'\t'
  echo
  log_warn "--- Hysteria2 Users ---"
  $PSQL_CMD -c "SELECT password FROM hysteria_users ORDER BY id;"
}

add_user() {
  local type="$1" new_id
  case "$type" in
    vless)
      new_id=$(uuidgen)
      $PSQL_CMD -c "INSERT INTO xray_users(type,user_id) VALUES('vless','$new_id');"
      ;;
    trojan)
      new_id=$(head -c16 /dev/urandom | base64 | tr '+/' '_-' | cut -c1-16)
      $PSQL_CMD -c "INSERT INTO xray_users(type,user_id) VALUES('trojan','$new_id');"
      ;;
    hysteria)
      new_id=$(head -c32 /dev/urandom | base64 | tr '+/' '_-')
      $PSQL_CMD -c "INSERT INTO hysteria_users(password) VALUES('$new_id');"
      ;;
    *)
      log_error "Usage: raycontrol add-user [vless|trojan|hysteria]"
      exit 1
      ;;
  esac
  log_info "Added $type user: $new_id"
  regenerate_configs
  reload_services $([[ $type == hysteria ]] && echo "hysteria" || echo "xray")
  show_qr "$type" "${new_id:0:1}"
}

del_user() {
  local id="$1"
  if [[ -z "$id" ]]; then log_error "Please provide a user ID or password to delete."; exit 1; fi
  local xdel hdel
  xdel=$($PSQL_CMD -c "DELETE FROM xray_users WHERE user_id='$id';" | sed 's/DELETE //')
  hdel=$($PSQL_CMD -c "DELETE FROM hysteria_users WHERE password='$id';" | sed 's/DELETE //')
  if (( xdel>0 )); then
    log_info "Removed Xray user '$id'."
    regenerate_configs; reload_services xray
  elif (( hdel>0 )); then
    log_info "Removed Hysteria user '$id'."
  else
    log_error "User not found: $id"; exit 1
  fi
}

list_ips() {
  log_warn "--- Whitelisted IPs ---"
  if nft list set "$NFT_TABLE" "$NFT_SET" &>/dev/null; then
    nft list set "$NFT_TABLE" "$NFT_SET" | awk '/elements/ {for(i=2;i<=NF;i++) print $i}' | while read -r ip; do
      ttl=$(nft -j list set "$NFT_TABLE" "$NFT_SET" | jq -r --arg ip "$ip" '.nftables[].set.elem[]? | select(.elem.addr==$ip).elem.timeout // "static"')
      printf "%-15s %s\n" "$ip" "$ttl"
    done
  else
    echo "(no IPs whitelisted)"
  fi
}

add_ip() {
  local ip="$1"
  [[ -z "$ip" ]] && { log_error "Usage: raycontrol add-ip <IP>"; exit 1; }
  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then log_error "Invalid IPv4 address: $ip"; exit 1; fi
  nft add element "$NFT_TABLE" "$NFT_SET" "{ $ip timeout 24h }" && log_info "Added $ip to whitelist (24h)"
}

del_ip() {
  local ip="$1"
  [[ -z "$ip" ]] && { log_error "Usage: raycontrol del-ip <IP>"; exit 1; }
  nft delete element "$NFT_TABLE" "$NFT_SET" "{ $ip }" && log_info "Removed $ip from whitelist" || log_warn "$ip was not whitelisted"
}

backup_config() {
  local timestamp backup_file temp_dir
  timestamp=$(date '+%Y%m%d-%H%M%S')
  backup_file="$BACKUP_DIR/ray-aio-backup-$timestamp.tar.gz"
  temp_dir=$(mktemp -d)
  log_info "Backing up database and configs..."
  pg_dump -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB_NAME" > "$temp_dir/ray_aio_db.sql"
  cp -a /etc/letsencrypt "$temp_dir/"; cp -a "$RAY_AIO_DIR" "$temp_dir/"; cp -a "$SECRETS_DIR" "$temp_dir/"; cp -a "$HYSTERIA_DIR" "$temp_dir/"
  tar -czf "$backup_file" -C "$temp_dir" .
  rm -rf "$temp_dir"
  log_info "Backup complete: $backup_file"
}

restore_config() {
  local file temp_dir confirm
  file="$1"
  [[ -z "$file" ]] && { log_error "Usage: raycontrol restore <backup-file>"; exit 1; }
  [[ ! -f "$file" ]] && { log_error "Backup not found: $file"; exit 1; }
  temp_dir=$(mktemp -d)
  read -rp "This will overwrite current configs and database. Proceed? [y/N]: " confirm
  if [[ "${confirm,,}" != "y" ]]; then log_info "Restore cancelled."; rm -rf "$temp_dir"; exit 0; fi
  log_info "Restoring from $file..."
  systemctl stop xray hysteria-server
  tar -xzf "$file" -C "$temp_dir"
  cp -a "$temp_dir/letsencrypt/." /etc/letsencrypt/; cp -a "$temp_dir/ray-aio/." "$RAY_AIO_DIR/"; cp -a "$temp_dir/secrets/." "$SECRETS_DIR/"; cp -a "$temp_dir/hysteria/." "$HYSTERIA_DIR/"
  source "$DB_CONF"; export PGPASSWORD=$PG_PASSWORD
  sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$PG_DB_NAME\";"
  sudo -u postgres psql -c "CREATE DATABASE \"$PG_DB_NAME\";"
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$PG_DB_NAME\" TO \"$PG_USER\";"
  sudo -u postgres psql -d "$PG_DB_NAME" -c \
  "GRANT USAGE, CREATE ON SCHEMA public TO \"$PG_USER\";"
  psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB_NAME" < "$temp_dir/ray_aio_db.sql"
  regenerate_configs
  rm -rf "$temp_dir"
  log_info "Restore complete. Run 'raycontrol enable' to restart."
}

apply_nftables(){
  /usr/local/bin/apply_nftables_xray.sh && nft -s list ruleset > /etc/nftables.conf
}

check_db_connection
case "${1:-help}" in
  help)                   help ;;
  enable)                 enable_all ;;
  disable)                disable_all ;;
  status)                 show_status ;;
  monitor)                monitor ;;
  backup)                 backup_config ;;
  restore)                restore_config "${2:-}" ;;
  list-users)             list_users ;;
  add-user)               add_user "${2:-}" ;;
  del-user)               del_user "${2:-}" ;;
  show-qr)                show_qr "${2:-}" "${3:-}" ;;
  list-ips)               list_ips ;;
  add-ip)                 add_ip "${2:-}" ;;
  del-ip)                 del_ip "${2:-}" ;;
  regenerate-configs)     regenerate_configs && reload_services ;;
  *)                      help ;;
esac
EOF
chmod +x "$RAYCONTROL_PATH"

cat > "$APPLY_NFTABLES_SCRIPT" <<'SCRIPT_EOF'
#!/usr/bin/env bash
set -e
# shellcheck source=/dev/null
source /etc/ray-aio/install.conf

autodetect_inet_iface() {
    [[ -n ${INTERNET_IFACE:-} ]] && { echo "$INTERNET_IFACE"; return; }
    local d
    d=$(ip -4 route list 0/0 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1)
    [[ -n $d ]] && { echo "$d"; return; }
    d=$(ip -6 route list default 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1)
    [[ -n $d ]] && { echo "$d"; return; }
    d=$(ip -o -4 addr show scope global | awk '{print $2}' | head -1)
    [[ -n $d ]] && { echo "$d"; return; }
    echo ""
}
IFACE=$(autodetect_inet_iface)
[[ -z $IFACE ]] && echo "outgoing interface not detected; NAT disabled" || echo "outgoing interface: $IFACE"

nft -f - <<EOF
flush ruleset

table inet filter {
    set knock_stage1      { type ipv4_addr; flags dynamic; timeout 30s; size 200000; gc-interval 1m; }
    set knock_stage2      { type ipv4_addr; flags dynamic; timeout 30s; size 200000; gc-interval 1m; }
    set xray_clients      { type ipv4_addr; flags dynamic; timeout 10m; size 300000; gc-interval 5m; }
    set knock_fail        { type ipv4_addr; flags dynamic; timeout 24h; size 500000; gc-interval 5m; }
    set knock_stage1_v6   { type ipv6_addr; flags dynamic; timeout 30s; size 200000; gc-interval 1m; }
    set knock_stage2_v6   { type ipv6_addr; flags dynamic; timeout 30s; size 200000; gc-interval 1m; }
    set knock_fail_v6     { type ipv6_addr; flags dynamic; timeout 24h; size 500000; gc-interval 5m; }

    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept
        ct state { established, related } accept
        ct state invalid drop

        ip saddr @knock_fail drop
        ip6 saddr @knock_fail_v6 drop

        ip saddr @xray_clients tcp dport { $PORT_VLESS, $PORT_TROJAN, $SSH_PORT } counter update @xray_clients { ip saddr } accept
        ip saddr @xray_clients udp dport $PORT_HYSTERIA counter update @xray_clients { ip saddr } accept
        ip saddr @xray_clients icmp type { echo-request, echo-reply } accept

        tcp dport $K1 limit rate 5/minute burst 3 packets jump knock_stage1_handler
        udp dport $K1 limit rate 5/minute burst 3 packets jump knock_stage1_handler
        tcp dport $K1 add @knock_fail { ip saddr } drop
        udp dport $K1 add @knock_fail { ip saddr } drop
        tcp dport $K1 add @knock_fail_v6 { ip6 saddr } drop
        udp dport $K1 add @knock_fail_v6 { ip6 saddr } drop

        tcp dport $K2 ip saddr @knock_stage1 limit rate 5/minute burst 3 packets jump knock_stage2_handler
        udp dport $K2 ip saddr @knock_stage1 limit rate 5/minute burst 3 packets jump knock_stage2_handler
        tcp dport $K2 add @knock_fail { ip saddr } drop
        udp dport $K2 add @knock_fail { ip saddr } drop
        tcp dport $K2 add @knock_fail_v6 { ip6 saddr } drop
        udp dport $K2 add @knock_fail_v6 { ip6 saddr } drop

        tcp dport $K3 ip saddr @knock_stage2 limit rate 5/minute burst 3 packets jump knock_final_handler
        udp dport $K3 ip saddr @knock_stage2 limit rate 5/minute burst 3 packets jump knock_final_handler
        tcp dport $K3 add @knock_fail { ip saddr } drop
        udp dport $K3 add @knock_fail { ip saddr } drop
        tcp dport $K3 add @knock_fail_v6 { ip6 saddr } drop
        udp dport $K3 add @knock_fail_v6 { ip6 saddr } drop

        icmpv6 type { nd-router-advert, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
        icmpv6 type { mld-listener-query, mld-listener-report, mld-listener-reduction } accept
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept

        drop
    }

    chain forward { type filter hook forward priority 0; policy drop; }

    chain output {
        type filter hook output priority 0; policy accept;
        #DNS
        udp dport 53 accept
        tcp dport 53 accept
        #HTTPS and DoH
        tcp dport { 80, 443 } accept
        udp dport { 80, 443 } accept
        #DoT
        tcp dport 853 accept
        #DoHfallback
        tcp dport 8443 accept
        udp dport 8443 accept
        #ICMP
        icmp type { echo-request, echo-reply } accept
        meta l4proto ipv6-icmp accept
    }

    chain knock_stage1_handler {
        add @knock_stage1 { ip saddr }
        add @knock_stage1_v6 { ip6 saddr }
        drop
    }

    chain knock_stage2_handler {
        delete @knock_stage1 { ip saddr }
        delete @knock_stage1_v6 { ip6 saddr }
        add @knock_stage2 { ip saddr }
        add @knock_stage2_v6 { ip6 saddr }
        drop
    }

    chain knock_final_handler {
        delete @knock_stage2 { ip saddr }
        delete @knock_stage2_v6 { ip6 saddr }
        add @xray_clients { ip saddr }
        drop
    }
}
EOF

if [[ -n $IFACE ]]; then
    nft -f - <<NAT_EOF
    table ip nat {
        chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "$IFACE" masquerade
        }
    }
NAT_EOF
fi
SCRIPT_EOF
chmod +x "$APPLY_NFTABLES_SCRIPT"



log_info "--- Issuing Certificate with Certbot ---"
mkdir -p "$SECRETS_DIR"; cat > "$CLOUDFLARE_INI" <<< "dns_cloudflare_api_token = $CF_API_TOKEN"; chmod 600 "$CLOUDFLARE_INI"
certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_INI" --agree-tos -m "$EMAIL" -d "$DOMAIN"

log_info "--- Configuring Automatic Certificate Renewal ---"
mkdir -p "$LE_POST_HOOK_DIR"
cat > "$LE_POST_HOOK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# This script is run by certbot after a successful renewal.
/usr/local/bin/raycontrol regenerate-configs
/usr/local/bin/raycontrol reload_services
EOF
chmod +x "$LE_POST_HOOK_SCRIPT"

log_info "--- Installing Xray-core ---"
mkdir -p "$XRAY_DIR" "$XRAY_LOG_DIR"; chown -R nobody:nogroup "$XRAY_DIR" "$XRAY_LOG_DIR"
wget -qO "${TEMP_ZIP}" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip"
wget -qO "${TEMP_DGST}" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip.dgst"
XRAY_HASH=$(grep '^SHA2-256=' "${TEMP_DGST}" | cut -d'=' -f2 | tr -d '[:space:]')
CALC_HASH=$(sha256sum "${TEMP_ZIP}" | awk '{print $1}' | tr -d '[:space:]')
if [[ "$CALC_HASH" == "$XRAY_HASH" ]]; then
    log_info "Checksum OK: xray"
else
    log_error "ERROR: checksum mismatch - xray"
    echo "Expected: $XRAY_HASH"
    echo "Actual:   $CALC_HASH"
    exit 1
fi
unzip -qo "${TEMP_ZIP}" -d "$(dirname "$XRAY_BIN")"
chmod +x "$XRAY_BIN"

cat > "$XRAY_CONFIG_TPL" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": ${PORT_VLESS},
      "protocol": "vless",
      "settings": {"clients": [], "decryption": "none"},
      "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem", "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"}], "alpn": ${XRAY_ALPN}}}
    },
    {
      "port": ${PORT_TROJAN},
      "protocol": "trojan",
      "settings": {"clients": [], "fallbacks": [{"dest": "@blackhole"}]},
      "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem", "keyFile": "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"}], "alpn": ${XRAY_ALPN}}}
    }
  ],
  "outbounds": [{"protocol": "freedom"}, {"protocol": "blackhole", "tag": "@blackhole"}]
}
EOF

cat > "$XRAY_SERVICE" <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target postgresql.service
Requires=postgresql.service
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$XRAY_BIN -config $XRAY_CONFIG
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

log_info "--- Installing Hysteria2 ---"

wget -q -O hysteria-linux-amd64 "${HYSTERIA_URL_BIN}" || { log_error "Failed to download binary"; exit 1; }
wget -q -O hashes.txt           "${HYSTERIA_URL_HASHES}" || { log_error "Failed to download hashes.txt"; exit 1; }

for f in hysteria-linux-amd64 hashes.txt; do
  [[ -s "$f" ]] || { log_error "$f is empty or missing"; exit 1; }
done

grep -E 'hysteria-linux-amd64$' hashes.txt | sed 's|build/||' > chk.txt

if sha256sum -c chk.txt --status; then
    log_info "Checksum OK: hysteria2"
else
    log_error "ERROR: Checksum mismatch - hysteria2"
    sha256sum -c chk.txt
    exit 1
fi

install -m 0755 hysteria-linux-amd64 "${HYSTERIA_BIN}"
log_info "Hysteria2 installed successfully!"

cat > "$HYSTERIA_CONFIG" <<EOF
listen: :$PORT_HYSTERIA
tls:
  cert: /etc/letsencrypt/live/$DOMAIN/fullchain.pem
  key: /etc/letsencrypt/live/$DOMAIN/privkey.pem
auth:
  type: command
  command: $HYSTERIA_AUTH_SCRIPT
obfs:
  type: salamander
  salamander:
    password: $PASSWORD_HYSTERIA_OBFS
masquerade:
  type: proxy
  proxy:
    url: https://dns11.quad9.net
    rewriteHost: true
EOF

cat > "$HYSTERIA_AUTH_SCRIPT" <<'EOF'
#!/bin/bash
set -e
ADDR=$1
AUTH=$2
TX=$3
# shellcheck source=/dev/null
source "/etc/hysteria/db.conf"
export PGPASSWORD=$PG_PASSWORD
EXISTS=$(psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB_NAME" -t -c "SELECT COUNT(*) FROM hysteria_users WHERE password = '$AUTH';")
if [ "${EXISTS:-0}" -gt 0 ]; then
  ID=$(psql -h "$PG_HOST" -U "$PG_USER" -d "$PG_DB_NAME" -t -c "SELECT id FROM hysteria_users WHERE password = '$AUTH';")
  echo "$ID"
  exit 0
else
  exit 1
fi
EOF
chmod 700 "$HYSTERIA_AUTH_SCRIPT"
chown nobody:nogroup "$HYSTERIA_AUTH_SCRIPT"

cat > "$HYSTERIA_SERVICE" <<EOF
[Unit]
Description=Hysteria2 Service
After=network.target nss-lookup.target postgresql.service
Requires=postgresql.service
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$HYSTERIA_BIN server -c $HYSTERIA_CONFIG
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

log_info "--- Generating Initial Configs and Setting Permissions ---"
"$RAYCONTROL_PATH" regenerate-configs
usermod -aG ssl-cert nobody
chown -R nobody:nogroup "$XRAY_DIR" "$HYSTERIA_DIR"
chmod 600 "$HYSTERIA_CONFIG"
chgrp -R ssl-cert /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rx /etc/letsencrypt/live /etc/letsencrypt/archive

systemctl daemon-reload
systemctl enable xray
systemctl enable hysteria-server

ALPN_URI=$(jq -r '.alpn | join(",")' "$SETTINGS_FILE")
VLESS_URI="vless://${UUID_VLESS}@${DOMAIN}:${PORT_VLESS}?type=tcp&security=tls&flow=${VLESS_FLOW}&alpn=${ALPN_URI}&sni=${DOMAIN}#${DOMAIN}-VLESS"
TROJAN_URI="trojan://${PASSWORD_TROJAN}@${DOMAIN}:${PORT_TROJAN}?security=tls&type=tcp&alpn=h2,http/1.1&sni=${DOMAIN}#${DOMAIN}-Trojan"
HYSTERIA_URI="hysteria2://${PASSWORD_HYSTERIA}@${DOMAIN}:${PORT_HYSTERIA}?sni=${DOMAIN}&obfs=salamander&obfs-password=${PASSWORD_HYSTERIA_OBFS}#${DOMAIN}-Hysteria2"

trap - ERR
log_info "--- Installation successful! ---"
echo -e "\n\n${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}               ACTION REQUIRED TO ACTIVATE               ${NC}"
echo -e "${YELLOW}=====================================================${NC}\n"
if [[ "${INSTALL_XANMOD,,}" == "y" ]]; then
    echo -e "${YELLOW}IMPORTANT: A reboot is required to use the new XanMod kernel.${NC}"
    echo -e "After rebooting, run '${GREEN}$RAYCONTROL_PATH enable${NC}'.\n"
else
    echo -e "Services are installed but NOT RUNNING. The firewall is NOT ACTIVE."
    echo -e "To start all services and apply the firewall, run:\n\n  ${GREEN}$RAYCONTROL_PATH enable${NC}\n"
fi
echo -e "Your IP will not be whitelisted automatically. You must perform the port knock first."
echo -e "An IP will be removed from the whitelist after 10 minutes of inactivity."
echo -e "\n${YELLOW}--- Initial Connection Info (once enabled) ---${NC}"
echo "Knock sequence for all services: $K1 -> $K2 -> $K3"; echo "SSH Port: $SSH_PORT"; echo
echo -e "${YELLOW}VLESS (TCP, ALPN: $ALPN_URI):${NC}"; echo "  Port: $PORT_VLESS, UUID: $UUID_VLESS"; echo
echo -e "${YELLOW}Trojan (TCP, ALPN: $ALPN_URI):${NC}"; echo "  Port: $PORT_TROJAN, Password: $PASSWORD_TROJAN"; echo
echo -e "${YELLOW}Hysteria2 (UDP):${NC}"; echo "  Port: $PORT_HYSTERIA"; echo "  Initial Auth Pass: $PASSWORD_HYSTERIA"
echo "  OBFS Pass: $PASSWORD_HYSTERIA_OBFS"
if command -v qrencode &> /dev/null; then
  echo -e "\n${YELLOW}--- QR Codes for Initial Users ---${NC}"
  echo "VLESS Configuration:"; qrencode -t ANSIUTF8 "$VLESS_URI"
  echo "Trojan Configuration:"; qrencode -t ANSIUTF8 "$TROJAN_URI"
  echo "Hysteria2 Configuration:"; qrencode -t ANSIUTF8 "$HYSTERIA_URI"
else
  echo -e "\n${YELLOW}--- Configuration URIs ---${NC}"; echo "VLESS: $VLESS_URI"; echo "Trojan: $TROJAN_URI"; echo "Hysteria2: $HYSTERIA_URI"
fi
echo -e "\nUse ${GREEN}'$RAYCONTROL_PATH help'${NC} for a full list of commands."
echo -e "\n${GREEN}=========================================================================================${NC}\n"


cd "$ORIG_DIR"
rm -rf "${TMP_DIR}"
