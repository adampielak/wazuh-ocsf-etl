#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  wazuh-build-from-source.sh — Build and install/upgrade Wazuh manager from
#  source with ZeroMQ support enabled.
#
#  Required when INPUT_MODE=zeromq is used with wazuh-ocsf-etl, because
#  official Wazuh .deb/.rpm packages do NOT include ZeroMQ output support.
#
#  Usage:
#    sudo bash wazuh-build-from-source.sh [VERSION]
#
#  Examples:
#    sudo bash wazuh-build-from-source.sh            # builds WAZUH_VERSION below
#    sudo bash wazuh-build-from-source.sh 4.14.5     # override version
#
#  Tested on: Ubuntu 22.04, Ubuntu 24.04 (Debian-family only)
#
#  What this script does:
#    1. Installs build dependencies
#    2. Backs up /var/ossec/etc/ossec.conf
#    3. Downloads the Wazuh source tarball from GitHub
#    4. Builds with:  make deps TARGET=server
#                     make TARGET=server USE_ZEROMQ=yes
#    5. Writes preloaded-vars.conf for unattended install/update
#    6. Stops wazuh-manager
#    7. Runs install.sh in update mode
#    8. Restores ossec.conf from backup
#    9. Verifies version and ZeroMQ presence in the binary
#   10. Starts wazuh-manager and prints status
#
#  Log: /var/log/wazuh-build-<VERSION>.log
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# Default: latest Wazuh release verified compatible with wazuh-ocsf-etl.
# This script is updated with each new compatible Wazuh version.
# Override on the command line: sudo bash wazuh-build-from-source.sh 4.14.6
WAZUH_VERSION="${1:-4.14.5}"
BUILD_DIR="/opt/wazuh-src"
LOG="/var/log/wazuh-build-${WAZUH_VERSION}.log"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
BACKUP="${OSSEC_CONF}.bak-pre-${WAZUH_VERSION//./-}"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*" | tee -a "$LOG"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*" | tee -a "$LOG"; }
die()   { echo -e "${RED}[ERROR]${RESET} $*" | tee -a "$LOG" >&2; exit 1; }
step()  { echo -e "\n${BOLD}── Step $* ──${RESET}" | tee -a "$LOG"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root: sudo bash $0 [VERSION]"
command -v apt-get &>/dev/null || die "This script requires apt-get (Debian/Ubuntu only)"

mkdir -p "$(dirname "$LOG")"
echo "[$(date '+%F %T')] === Wazuh v${WAZUH_VERSION} build from source START ===" | tee -a "$LOG"
info "Log: $LOG"
info "Build dir: $BUILD_DIR"

# ── Step 1: Build dependencies ─────────────────────────────────────────────────
step "1: Install build dependencies"
apt-get update -qq 2>&1 | tail -1 | tee -a "$LOG"
apt-get install -y \
    gcc g++ make cmake \
    libssl-dev libpcre2-dev libevent-dev \
    libcurl4-openssl-dev libsystemd-dev \
    libzmq3-dev libczmq-dev \
    python3 python3-pip \
    2>&1 | grep -E "^(Get:|Setting up|E:|W:)" | tee -a "$LOG" || true
ok "Dependencies installed"

# ── Step 2: Backup ossec.conf ──────────────────────────────────────────────────
step "2: Backup ossec.conf"
if [[ -f "$OSSEC_CONF" ]]; then
    cp "$OSSEC_CONF" "$BACKUP"
    ok "Backed up to $BACKUP"
else
    warn "ossec.conf not found at $OSSEC_CONF — fresh install mode"
    BACKUP=""
fi

# ── Step 3: Download source ────────────────────────────────────────────────────
step "3: Download Wazuh v${WAZUH_VERSION} source"
TARBALL="/tmp/wazuh-${WAZUH_VERSION}.tar.gz"
SRC_DIR="${BUILD_DIR}/wazuh-${WAZUH_VERSION}"

mkdir -p "$BUILD_DIR"
rm -rf "$SRC_DIR"

if [[ ! -f "$TARBALL" ]]; then
    info "Downloading from GitHub..."
    wget -q --show-progress \
        "https://github.com/wazuh/wazuh/archive/refs/tags/v${WAZUH_VERSION}.tar.gz" \
        -O "$TARBALL" 2>&1 | tee -a "$LOG" \
        || die "Download failed — check version tag: v${WAZUH_VERSION}"
else
    info "Using cached tarball: $TARBALL"
fi

tar -xzf "$TARBALL" -C "$BUILD_DIR"
[[ -d "$SRC_DIR" ]] || die "Extraction failed — expected $SRC_DIR"
ok "Sources at $SRC_DIR"

# ── Step 4: Build ──────────────────────────────────────────────────────────────
step "4: Build (this takes 15–40 minutes depending on CPU)"
cd "${SRC_DIR}/src"

info "make deps TARGET=server ..."
make deps TARGET=server 2>&1 | tee -a "$LOG" | grep -E "^\[|error:|Error" || true

info "make TARGET=server USE_ZEROMQ=yes ..."
make TARGET=server USE_ZEROMQ=yes 2>&1 | tee -a "$LOG" \
    | grep -E "^\[|Linking|error:|Error 2|undefined reference" || true

# Sanity check: wazuh-analysisd must exist
[[ -x "${SRC_DIR}/src/wazuh-analysisd" ]] \
    || die "Build failed — wazuh-analysisd not produced. Check $LOG for errors."

# Verify ZeroMQ compiled in
if strings "${SRC_DIR}/src/wazuh-analysisd" | grep -q zeromq_output; then
    ok "ZeroMQ support confirmed in wazuh-analysisd"
else
    die "ZeroMQ NOT found in wazuh-analysisd — build succeeded but without ZeroMQ. Check libzmq3-dev was installed."
fi

# ── Step 5: preloaded-vars.conf ────────────────────────────────────────────────
step "5: Write preloaded-vars.conf (unattended install)"
cat > "${SRC_DIR}/etc/preloaded-vars.conf" <<'VARS'
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="server"
USER_DIR="/var/ossec"
USER_UPDATE="y"
USER_ENABLE_UPDATE_CHECK="n"
VARS
ok "preloaded-vars.conf written"

# ── Step 6: Stop Wazuh ─────────────────────────────────────────────────────────
step "6: Stop wazuh-manager"
if systemctl is-active --quiet wazuh-manager; then
    systemctl stop wazuh-manager
    ok "wazuh-manager stopped"
else
    info "wazuh-manager was not running"
fi

# ── Step 7: Install ────────────────────────────────────────────────────────────
step "7: Run install.sh"
cd "$SRC_DIR"
bash install.sh 2>&1 | tee -a "$LOG" | grep -E "^\[|Copying|Starting|Error" || true
ok "install.sh complete"

# ── Step 8: Restore ossec.conf ────────────────────────────────────────────────
step "8: Restore ossec.conf"
if [[ -n "$BACKUP" && -f "$BACKUP" ]]; then
    cp "$BACKUP" "$OSSEC_CONF"
    chown root:wazuh "$OSSEC_CONF" 2>/dev/null || chown root:root "$OSSEC_CONF"
    chmod 660 "$OSSEC_CONF"
    ok "ossec.conf restored from $BACKUP"
else
    warn "No backup to restore — review $OSSEC_CONF before starting"
fi

# ── Step 9: Verify ────────────────────────────────────────────────────────────
step "9: Verify"
INSTALLED_VERSION=$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep WAZUH_VERSION | cut -d'"' -f2)
info "Installed version: $INSTALLED_VERSION"

if strings /var/ossec/bin/wazuh-analysisd | grep -q zeromq_output; then
    ok "ZeroMQ confirmed in installed wazuh-analysisd"
else
    die "ZeroMQ NOT found in installed binary — install may have overwritten with package version"
fi

# ── Step 10: Start ────────────────────────────────────────────────────────────
step "10: Start wazuh-manager"
systemctl start wazuh-manager
sleep 5
systemctl status wazuh-manager --no-pager | head -8 | tee -a "$LOG"

# ZeroMQ in runtime logs
sleep 2
if grep -qi zeromq /var/ossec/logs/ossec.log 2>/dev/null; then
    ok "ZeroMQ output enabled in ossec.log"
else
    warn "ZeroMQ not yet visible in ossec.log — check after a few seconds:"
    warn "  grep -i zeromq /var/ossec/logs/ossec.log"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Wazuh ${INSTALLED_VERSION} installed with ZeroMQ support.${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo "  Log:     $LOG"
echo "  Backup:  ${BACKUP:-none}"
echo ""
echo "  Verify ZeroMQ is publishing:"
echo "    grep -i zeromq /var/ossec/logs/ossec.log"
echo ""
echo "  If ETL was disconnected, restart it:"
echo "    systemctl restart wazuh-ocsf-etl"
echo ""
