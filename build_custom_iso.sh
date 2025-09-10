#!/bin/bash
# build_custom_iso.sh - Build a custom Kali Linux ISO and automate ISO retrieval.

set -euo pipefail

# Set KEEP_WORKDIR=1 to retain the temporary working directory after building

usage() {
    echo "Usage: $0 [-c config] [-k] [mode [out_iso [workdir]]]" >&2
}

# Require root for package installation and ISO manipulation
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Log all actions to a timestamped file in the current directory
LOGFILE="$(pwd)/build_iso_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "Logging to $LOGFILE"

# Reinstall dpkg if the dpkg-split helper is missing to prevent
# "unable to execute split package reassembly" errors during apt.
ensure_dpkg_split() {
    if ! command -v dpkg-split >/dev/null 2>&1; then
        echo "dpkg-split missing, reinstalling dpkg..."
        apt-get update
        apt-get install -y --reinstall dpkg
    fi
}

ensure_dpkg_split

DEFAULT_MODE=installer
DEFAULT_OUT="$(pwd)/kali-custom.iso"
DEFAULT_WORKDIR=/tmp/kali-iso-build

# Allow PRESS_CONF to set the config path; flags override
CONFIG_FILE="${PRESS_CONF:-press.conf}"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"
while getopts "c:kh" opt; do
    case "$opt" in
        c) CONFIG_FILE=$OPTARG ;;
        k) KEEP_WORKDIR=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND-1))

# Stash environment values so a config file cannot overwrite them
ENV_MODE="${MODE:-}"
ENV_OUT="${OUT_ISO:-}"
ENV_WORK="${WORKDIR:-}"
ENV_KALI_USER="${KALI_USERNAME:-${KALI_USER:-}}"
ENV_KALI_PASS="${KALI_PASSWORD:-${KALI_PASS:-}}"
ENV_GUEST_USER="${GUEST_USERNAME:-${GUEST_USER:-}}"
ENV_GUEST_PASS="${GUEST_PASSWORD:-${GUEST_PASS:-}}"

# Load configuration file if present
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Apply environment overrides after sourcing config
MODE="${ENV_MODE:-${MODE:-}}"
OUT_ISO="${ENV_OUT:-${OUT_ISO:-}}"
WORKDIR="${ENV_WORK:-${WORKDIR:-}}"
KALI_USERNAME="${ENV_KALI_USER:-${KALI_USERNAME:-${KALI_USER:-}}}"
KALI_PASSWORD="${ENV_KALI_PASS:-${KALI_PASSWORD:-${KALI_PASS:-}}}"
GUEST_USERNAME="${ENV_GUEST_USER:-${GUEST_USERNAME:-${GUEST_USER:-}}}"
GUEST_PASSWORD="${ENV_GUEST_PASS:-${GUEST_PASSWORD:-${GUEST_PASS:-}}}"

# Positional arguments override everything
MODE="${1:-$MODE}"
OUT_ISO="${2:-$OUT_ISO}"
WORKDIR="${3:-$WORKDIR}"

INTERACTIVE=0

if [[ -z "$MODE" ]]; then
    read -rp "Build mode (installer/live) [$DEFAULT_MODE]: " MODE
    MODE=${MODE:-$DEFAULT_MODE}
    INTERACTIVE=1
fi
if [[ -z "$OUT_ISO" ]]; then
    read -rp "Output ISO path [$DEFAULT_OUT]: " OUT_ISO
    OUT_ISO=${OUT_ISO:-$DEFAULT_OUT}
    INTERACTIVE=1
fi
if [[ -z "$WORKDIR" ]]; then
    read -rp "Working directory [$DEFAULT_WORKDIR]: " WORKDIR
    WORKDIR=${WORKDIR:-$DEFAULT_WORKDIR}
    INTERACTIVE=1
fi

if [[ -z "$KALI_USERNAME" ]]; then
    read -rp "Enter Kali username: " KALI_USERNAME
    INTERACTIVE=1
fi
if [[ -z "$KALI_PASSWORD" ]]; then
    read -srp "Enter Kali password: " KALI_PASSWORD; echo
    INTERACTIVE=1
fi
if [[ -z "$GUEST_USERNAME" ]]; then
    read -rp "Enter guest username: " GUEST_USERNAME
    INTERACTIVE=1
fi
if [[ -z "$GUEST_PASSWORD" ]]; then
    read -srp "Enter guest password: " GUEST_PASSWORD; echo
    INTERACTIVE=1
fi

if [[ $INTERACTIVE -eq 1 ]]; then
    read -rp "Save these settings to $CONFIG_FILE for future runs? [y/N]: " save
    if [[ "$save" =~ ^[Yy]$ ]]; then
        umask 077
        cat > "$CONFIG_FILE" <<EOF
MODE="$MODE"
OUT_ISO="$OUT_ISO"
WORKDIR="$WORKDIR"
KALI_USER="$KALI_USERNAME"
KALI_PASS="$KALI_PASSWORD"
GUEST_USER="$GUEST_USERNAME"
GUEST_PASS="$GUEST_PASSWORD"
EOF
        echo "Configuration saved to $CONFIG_FILE"
    fi
fi

# Ensure we have network connectivity before attempting any downloads
check_network() {
    local url="https://kali.org/"
    for _ in {1..5}; do
        if curl -fs --head "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    echo "Unable to reach $url; network connectivity is required." >&2
    exit 1
}

# Verify sufficient disk space is available
require_space() {
    local path=$1
    local need_mb=${2:-8192}
    local avail
    avail=$(df -Pm "$path" 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -z "$avail" ]]; then
        echo "Unable to determine free space for $path" >&2
        exit 1
    fi
    if (( avail < need_mb )); then
        echo "Insufficient space on $path: need ${need_mb}MB, have ${avail}MB" >&2
        exit 1
    fi
}

# Verify sufficient available memory (in MB)
require_memory() {
    local need_mb=${1:-2048}
    local avail
    avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    if (( avail < need_mb )); then
        echo "Low available memory: need ${need_mb}MB, have ${avail}MB — throttling" >&2
        command -v renice >/dev/null && renice +10 $$ >/dev/null 2>&1 || true
        command -v ionice >/dev/null && ionice -c3 -p $$ >/dev/null 2>&1 || true
    fi
}

check_network
require_memory 2048

# Try multiple Kali mirrors so presses continue even if one blocks access
MIRRORS=(
    "https://cdimage.kali.org/current"
    "https://kali.download/kali-images/current"
)
BASE_URL=""

FIRSTBOOT="firstboot.sh"
HOST_HARDEN="host_hardening_windows.sh"
HOST_HARDEN_LINUX="host_hardening_linux.sh"
WIN_PS="windows_hardening.ps1"
VM_HARDEN="vm_windows_env_hardening.sh"
VM_LINUX_HARDEN="vm_linux_env_hardening.sh"
AI_AGENT="ai_agent_commands.sh"
SEC_SCAN="security_scan_scheduler.sh"
MAC_RANDOM="mac_randomizer.sh"
NET_MON="network_io_monitor.sh"
NET_MON_SVC="network_io_monitor.service"
DEV_SETUP="secure_dev_env.sh"
NN_SETUP="nn_ids_setup.py"
NN_RUN="setup_nn_ids.sh"
NN_RUN_SERVICE="setup_nn_ids.service"
NN_OS_TRAIN="nn_os_train.py"
NN_SERVICE="nn_ids_service.py"
NN_SVC_FILE="nn_ids.service"
NN_CAPTURE="nn_ids_capture.py"
NN_CAP_SVC="nn_ids_capture.service"
NN_CAP_TIMER="nn_ids_capture.timer"
NN_RETRAIN="nn_ids_retrain.py"
NN_RET_SVC="nn_ids_retrain.service"
NN_RET_TIMER="nn_ids_retrain.timer"
PROC_MON="process_service_monitor.py"
PROC_SVC="process_monitor.service"
PROC_TIMER="process_monitor.timer"
SANITIZER="packet_sanitizer.py"
PORT_MON="port_socket_monitor.py"
PORT_MON_SVC="port_socket_monitor.service"
PORT_MON_TIMER="port_socket_monitor.timer"
NN_HEALTH="nn_ids_healthcheck.py"
NN_HEALTH_SVC="nn_ids_healthcheck.service"
NN_HEALTH_TIMER="nn_ids_healthcheck.timer"
NN_SNAPSHOT="nn_ids_snapshot.py"
NN_SNAP_SVC="nn_ids_snapshot.service"
NN_SNAP_TIMER="nn_ids_snapshot.timer"
NN_RESTORE="nn_ids_restore.py"
NN_RES_SVC="nn_ids_restore.service"
NN_RES_TIMER="nn_ids_restore.timer"
NN_LOGROTATE="nn_ids_logrotate"
NN_BLOCK="nn_ids_autoblock.py"
NN_BLOCK_SVC="nn_ids_autoblock.service"
NN_BLOCK_TIMER="nn_ids_autoblock.timer"
NN_REPORT="nn_ids_report.py"
NN_REPORT_SVC="nn_ids_report.service"
NN_REPORT_TIMER="nn_ids_report.timer"
THREAT_FEED="threat_feed_blocklist.py"
THREAT_FEED_SVC="threat_feed_blocklist.service"
THREAT_FEED_TIMER="threat_feed_blocklist.timer"
NN_RES_MON="nn_ids_resource_monitor.py"
NN_RES_MON_SVC="nn_ids_resource_monitor.service"
NN_RES_MON_TIMER="nn_ids_resource_monitor.timer"
NN_SANITIZE="nn_ids_sanitize.py"
NN_SANITIZE_SVC="nn_ids_sanitize.service"
NN_SANITIZE_TIMER="nn_ids_sanitize.timer"
PRO_HARDEN="vm_pro_hardening.sh"
NN_CONF="nn_ids.conf"
ANTI_WIPE="anti_wipe_monitor.sh"
ANTI_WIPE_SVC="anti_wipe_monitor.service"
NET_DISCOVERY="network_discovery.sh"
NET_DISCOVERY_VIZ="network_discovery_visualize.py"
IDS_MENU="ids_menu.sh"
INET_MON="internet_access_monitor.sh"
INET_MON_SVC="internet_access_monitor.service"
INET_MON_TIMER="internet_access_monitor.timer"
SSH_ACL="ssh_access_control.sh"
SSH_WHITE="ssh_whitelist.conf"
SSH_BLACK="ssh_blacklist.conf"
IDS_DESKTOP="ids_menu.desktop"
SCAN_SUMMARY="scan_log_summary.py"

# Determine ISO type and needed scripts, cycling mirrors until an ISO name is found
ISO_PATTERN=""
if [[ "$MODE" == "installer" ]]; then
    ISO_PATTERN='kali-linux-.*-installer-amd64\.iso'
    NEED_WIN=false
    FIRSTBOOT="firstboot_single.sh"
    PRESEED_SRC="kali-preseed-single.cfg"
elif [[ "$MODE" == "live" ]]; then
    ISO_PATTERN='kali-linux-.*-live-amd64\.iso'
    NEED_WIN=true
    PRESEED_SRC="kali-preseed.cfg"
else
    echo "Mode must be 'installer' or 'live'" >&2
    exit 1
fi

ISO_NAME=""
for m in "${MIRRORS[@]}"; do
    ISO_NAME=$(curl -fsSL --retry 3 --retry-delay 5 "$m/" | grep -oP "$ISO_PATTERN" | head -n 1) || true
    if [[ -n "$ISO_NAME" ]]; then
        BASE_URL="$m"
        break
    fi
done
if [[ -z "$ISO_NAME" ]]; then
    echo "Unable to locate ISO on mirrors" >&2
    exit 1
fi

ORIG_ISO="$(pwd)/$ISO_NAME"

# Check and install dependencies
missing_pkgs=()
for cmd in curl bsdtar mkisofs isohybrid gpg dialog nmap netdiscover arp-scan nbtscan dnsrecon whatweb enum4linux nikto sslscan snmpwalk masscan traceroute git pre-commit shellcheck flake8 bandit black codespell gitleaks isort python3 pip3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        case "$cmd" in
            curl)        missing_pkgs+=(curl) ;;
            bsdtar)      missing_pkgs+=(libarchive-tools) ;;
            mkisofs)     missing_pkgs+=(genisoimage) ;;
            isohybrid)   missing_pkgs+=(syslinux-utils) ;;
            gpg)         missing_pkgs+=(gnupg) ;;
            dialog)      missing_pkgs+=(dialog) ;;
            nmap)        missing_pkgs+=(nmap) ;;
            netdiscover) missing_pkgs+=(netdiscover) ;;
            arp-scan)    missing_pkgs+=(arp-scan) ;;
            nbtscan)     missing_pkgs+=(nbtscan) ;;
            dnsrecon)    missing_pkgs+=(dnsrecon) ;;
            whatweb)     missing_pkgs+=(whatweb) ;;
            enum4linux)  missing_pkgs+=(enum4linux) ;;
            nikto)       missing_pkgs+=(nikto) ;;
            sslscan)     missing_pkgs+=(sslscan) ;;
            snmpwalk)    missing_pkgs+=(snmp) ;;
            masscan)     missing_pkgs+=(masscan) ;;
            traceroute)  missing_pkgs+=(traceroute) ;;
            git)         missing_pkgs+=(git) ;;
            pre-commit)  missing_pkgs+=(pre-commit) ;;
            shellcheck)  missing_pkgs+=(shellcheck) ;;
            flake8)      missing_pkgs+=(flake8) ;;
            bandit)      missing_pkgs+=(bandit) ;;
            black)       missing_pkgs+=(black) ;;
            codespell)   missing_pkgs+=(codespell) ;;
            gitleaks)    missing_pkgs+=(gitleaks) ;;
            isort)       missing_pkgs+=(python3-isort) ;;
            python3)     missing_pkgs+=(python3) ;;
            pip3)        missing_pkgs+=(python3-pip) ;;
        esac
    fi
done

if [ ${#missing_pkgs[@]} -gt 0 ]; then
    echo "Installing missing packages: ${missing_pkgs[*]}"
    apt-get update
    apt-get install -y "${missing_pkgs[@]}"
fi

for cmd in curl bsdtar mkisofs isohybrid gpg dialog nmap netdiscover arp-scan nbtscan dnsrecon whatweb enum4linux nikto sslscan snmpwalk masscan traceroute git pre-commit shellcheck flake8 bandit black codespell gitleaks isort; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Required command '$cmd' not found after installation" >&2
        exit 1
    fi
done

# Prepare working and output directories and verify space
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
mkdir -p "$(dirname "$OUT_ISO")"
require_space "$WORKDIR" 8192
require_space "$(dirname "$OUT_ISO")" 8192

# Remove any previous ISO or checksum so stale files cannot mask failures
rm -f "$OUT_ISO" "${OUT_ISO}.sha256" "${OUT_ISO}.sha256.asc"

# Fetch checksums and download ISO only when necessary
curl -fsSL --retry 3 --retry-delay 5 "$BASE_URL/SHA256SUMS" -o "$WORKDIR/SHA256SUMS"
curl -fsSL --retry 3 --retry-delay 5 "$BASE_URL/SHA256SUMS.gpg" -o "$WORKDIR/SHA256SUMS.gpg"
curl -fsSL --retry 3 --retry-delay 5 https://archive.kali.org/archive-key.asc | gpg --import
if ! gpg --verify "$WORKDIR/SHA256SUMS.gpg" "$WORKDIR/SHA256SUMS" >/dev/null 2>&1; then
    echo "GPG signature verification failed" >&2
    exit 1
fi
expected_hash=$(grep "$ISO_NAME" "$WORKDIR/SHA256SUMS" | awk '{print $1}')
if [[ -f "$ORIG_ISO" ]]; then
    actual_hash=$(sha256sum "$ORIG_ISO" | awk '{print $1}')
    if [[ "$actual_hash" == "$expected_hash" ]]; then
        echo "Using cached ISO $ORIG_ISO"
    else
        echo "Cached ISO hash mismatch; downloading fresh copy"
        curl -fL --retry 3 --retry-delay 5 -C - -o "$ORIG_ISO" "$BASE_URL/$ISO_NAME"
    fi
else
    curl -fL --retry 3 --retry-delay 5 -C - -o "$ORIG_ISO" "$BASE_URL/$ISO_NAME"
fi
actual_hash=$(sha256sum "$ORIG_ISO" | awk '{print $1}')
if [[ "$actual_hash" != "$expected_hash" ]]; then
    echo "Checksum verification failed for $ISO_NAME" >&2
    exit 1
fi

# Extract original ISO
bsdtar -C "$WORKDIR" -xf "$ORIG_ISO"

# Copy preseed file (always named kali-preseed.cfg inside ISO)
mkdir -p "$WORKDIR/preseed"
cp "$PRESEED_SRC" "$WORKDIR/preseed/kali-preseed.cfg"
sed -i \
    -e "s/YOUR_SECURE_ROOT_PASSWORD/$KALI_PASSWORD/g" \
    -e "s/USER_SECURE_PASSWORD/$KALI_PASSWORD/g" \
    -e "s/kaliuser/$KALI_USERNAME/g" \
    -e "s/KaliUser/$KALI_USERNAME/g" \
    "$WORKDIR/preseed/kali-preseed.cfg"

# Copy firstboot and hardening scripts
INSTALL_DIR="$WORKDIR/install"
mkdir -p "$INSTALL_DIR"
cp "$FIRSTBOOT" "$INSTALL_DIR/"
sed -i \
    -e "s/KALI_USERNAME_PLACEHOLDER/$KALI_USERNAME/g" \
    -e "s/GUEST_USERNAME_PLACEHOLDER/$GUEST_USERNAME/g" \
    -e "s/GUEST_PASSWORD_PLACEHOLDER/$GUEST_PASSWORD/g" \
    "$INSTALL_DIR/$(basename "$FIRSTBOOT")"
cp "$HOST_HARDEN_LINUX" "$INSTALL_DIR/"
cp "$VM_LINUX_HARDEN" "$INSTALL_DIR/"
cp "$AI_AGENT" "$INSTALL_DIR/"
cp "$SEC_SCAN" "$INSTALL_DIR/"
cp "$MAC_RANDOM" "$INSTALL_DIR/"
cp mac_randomizer.service "$INSTALL_DIR/"
cp "$NET_MON" "$INSTALL_DIR/"
cp "$NET_MON_SVC" "$INSTALL_DIR/"
cp "$INET_MON" "$INSTALL_DIR/"
cp "$INET_MON_SVC" "$INSTALL_DIR/"
cp "$INET_MON_TIMER" "$INSTALL_DIR/"
cp "$DEV_SETUP" "$INSTALL_DIR/"
cp "$NN_SETUP" "$INSTALL_DIR/"
cp "$NN_RUN" "$INSTALL_DIR/"
cp "$NN_RUN_SERVICE" "$INSTALL_DIR/"
cp "$NN_OS_TRAIN" "$INSTALL_DIR/"
cp "$NN_SERVICE" "$INSTALL_DIR/"
cp "$NN_SVC_FILE" "$INSTALL_DIR/"
cp "$NN_CAPTURE" "$INSTALL_DIR/"
cp "$NN_CAP_SVC" "$INSTALL_DIR/"
cp "$NN_CAP_TIMER" "$INSTALL_DIR/"
cp "$NN_RETRAIN" "$INSTALL_DIR/"
cp "$NN_RET_SVC" "$INSTALL_DIR/"
cp "$NN_RET_TIMER" "$INSTALL_DIR/"
cp "$PROC_MON" "$INSTALL_DIR/"
cp "$PROC_SVC" "$INSTALL_DIR/"
cp "$PROC_TIMER" "$INSTALL_DIR/"
cp "$SANITIZER" "$INSTALL_DIR/"
cp "$PORT_MON" "$INSTALL_DIR/"
cp "$PORT_MON_SVC" "$INSTALL_DIR/"
cp "$PORT_MON_TIMER" "$INSTALL_DIR/"
cp "$NN_HEALTH" "$INSTALL_DIR/"
cp "$NN_HEALTH_SVC" "$INSTALL_DIR/"
cp "$NN_HEALTH_TIMER" "$INSTALL_DIR/"
cp "$NN_SNAPSHOT" "$INSTALL_DIR/"
cp "$NN_SNAP_SVC" "$INSTALL_DIR/"
cp "$NN_SNAP_TIMER" "$INSTALL_DIR/"
cp "$NN_RESTORE" "$INSTALL_DIR/"
cp "$NN_RES_SVC" "$INSTALL_DIR/"
cp "$NN_RES_TIMER" "$INSTALL_DIR/"
cp "$NN_LOGROTATE" "$INSTALL_DIR/"
cp "$NN_BLOCK" "$INSTALL_DIR/"
cp "$NN_BLOCK_SVC" "$INSTALL_DIR/"
cp "$NN_BLOCK_TIMER" "$INSTALL_DIR/"
cp "$NN_REPORT" "$INSTALL_DIR/"
cp "$NN_REPORT_SVC" "$INSTALL_DIR/"
cp "$NN_REPORT_TIMER" "$INSTALL_DIR/"
cp "$THREAT_FEED" "$INSTALL_DIR/"
cp "$THREAT_FEED_SVC" "$INSTALL_DIR/"
cp "$THREAT_FEED_TIMER" "$INSTALL_DIR/"
cp "$NN_RES_MON" "$INSTALL_DIR/"
cp "$NN_RES_MON_SVC" "$INSTALL_DIR/"
cp "$NN_RES_MON_TIMER" "$INSTALL_DIR/"
cp "$NN_SANITIZE" "$INSTALL_DIR/"
cp "$NN_SANITIZE_SVC" "$INSTALL_DIR/"
cp "$NN_SANITIZE_TIMER" "$INSTALL_DIR/"
cp "$NN_CONF" "$INSTALL_DIR/"
cp "$PRO_HARDEN" "$INSTALL_DIR/"
cp "$ANTI_WIPE" "$INSTALL_DIR/"
cp "$ANTI_WIPE_SVC" "$INSTALL_DIR/"
cp "$NET_DISCOVERY" "$INSTALL_DIR/"
cp "$NET_DISCOVERY_VIZ" "$INSTALL_DIR/"
cp "$SCAN_SUMMARY" "$INSTALL_DIR/"
cp "$IDS_MENU" "$INSTALL_DIR/"
cp "$SSH_ACL" "$INSTALL_DIR/"
cp "$SSH_WHITE" "$INSTALL_DIR/"
cp "$SSH_BLACK" "$INSTALL_DIR/"
cp "$IDS_DESKTOP" "$INSTALL_DIR/"

if $NEED_WIN; then
    cp "$HOST_HARDEN" "$INSTALL_DIR/"
    cp "$WIN_PS" "$INSTALL_DIR/"
    cp "$VM_HARDEN" "$INSTALL_DIR/"
fi

cat <<SERVICE > "$INSTALL_DIR/firstboot.service"
[Unit]
Description=First boot hardening
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firstboot.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

# Repack ISO
mkdir -p "$(dirname "$OUT_ISO")"
mkisofs -D -r -V "Kali Custom" -cache-inodes -J -l -b isolinux/isolinux.bin \
 -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table \
 -o "$OUT_ISO" "$WORKDIR"

# Make hybrid for USB booting
isohybrid "$OUT_ISO"

# Ensure the ISO was actually created
if [[ ! -s "$OUT_ISO" ]]; then
    echo "ISO build failed: $OUT_ISO not created" >&2
    exit 1
fi

echo "Custom ISO created at $OUT_ISO"

# Save checksum alongside the ISO, verify it, and sign if a GPG key is available
sha256sum "$OUT_ISO" | tee "${OUT_ISO}.sha256"
echo "Checksum written to ${OUT_ISO}.sha256"
sha256sum -c "${OUT_ISO}.sha256"
if command -v gpg >/dev/null 2>&1 && gpg --list-secret-keys >/dev/null 2>&1; then
    gpg --armor --detach-sign "${OUT_ISO}.sha256"
    echo "Checksum signature written to ${OUT_ISO}.sha256.asc"
fi

if [[ $KEEP_WORKDIR -ne 1 ]]; then
    rm -rf "$WORKDIR"
fi
