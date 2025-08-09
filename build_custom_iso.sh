#!/bin/bash
# build_custom_iso.sh - Build a custom Kali Linux ISO and automate ISO retrieval.
# build_custom_iso.sh - Build a custom Kali Linux ISO using the included preseed
# and first boot hardening script.

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <installer|live> <output_iso> [working_dir]" >&2
    exit 1
fi

MODE="$1"
OUT_ISO="$2"
WORKDIR="${3:-/tmp/kali-iso-build}"
BASE_URL="https://cdimage.kali.org/current"

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
    echo "Usage: $0 <original_kali_iso> <output_iso> [working_dir]" >&2
    exit 1
fi

ORIG_ISO="$1"
OUT_ISO="$2"
WORKDIR="${3:-/tmp/kali-iso-build}"

PRESEED="kali-preseed.cfg"
FIRSTBOOT="firstboot.sh"
HOST_HARDEN="host_hardening_windows.sh"
WIN_PS="windows_hardening.ps1"
VM_HARDEN="vm_windows_env_hardening.sh"
AI_AGENT="ai_agent_commands.sh"
SEC_SCAN="security_scan_scheduler.sh"
MAC_RANDOM="mac_randomizer.sh"
NN_SETUP="nn_ids_setup.py"
NN_RUN="setup_nn_ids.sh"
NN_RUN_SERVICE="setup_nn_ids.service"
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

# Determine ISO type and needed scripts
if [[ "$MODE" == "installer" ]]; then
    ISO_NAME=$(curl -s "$BASE_URL/" | grep -oP 'kali-linux-.*-installer-amd64\.iso' | head -n 1)
    NEED_WIN=false
    FIRSTBOOT="firstboot_single.sh"
    PRESEED_SRC="kali-preseed-single.cfg"
elif [[ "$MODE" == "live" ]]; then
    ISO_NAME=$(curl -s "$BASE_URL/" | grep -oP 'kali-linux-.*-live-amd64\.iso' | head -n 1)
    NEED_WIN=true
    PRESEED_SRC="kali-preseed.cfg"
else
    echo "Mode must be 'installer' or 'live'" >&2
    exit 1
fi

ORIG_ISO="$WORKDIR/$ISO_NAME"

# Check dependencies
for cmd in curl bsdtar mkisofs isohybrid; do

# Check dependencies
for cmd in bsdtar mkisofs isohybrid; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Required command '$cmd' not found." >&2
        exit 1
    fi
done

# Prepare working directory
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

# Download original ISO
curl -L -o "$ORIG_ISO" "$BASE_URL/$ISO_NAME"
MNTDIR="$WORKDIR/mnt"
mkdir -p "$MNTDIR"

# Extract original ISO
bsdtar -C "$WORKDIR" -xf "$ORIG_ISO"

# Copy preseed file (always named kali-preseed.cfg inside ISO)
mkdir -p "$WORKDIR/preseed"
cp "$PRESEED_SRC" "$WORKDIR/preseed/kali-preseed.cfg"

# Copy firstboot and hardening scripts
INSTALL_DIR="$WORKDIR/install"
mkdir -p "$INSTALL_DIR"
cp "$FIRSTBOOT" "$INSTALL_DIR/"
cp "$HOST_HARDEN_LINUX" "$INSTALL_DIR/"
cp "$VM_LINUX_HARDEN" "$INSTALL_DIR/"
# Copy preseed file
mkdir -p "$WORKDIR/preseed"
cp "$PRESEED" "$WORKDIR/preseed/"

# Copy firstboot and host hardening scripts
INSTALL_DIR="$WORKDIR/install" # location inside ISO root for early scripts
mkdir -p "$INSTALL_DIR"
cp "$FIRSTBOOT" "$INSTALL_DIR/"
cp "$HOST_HARDEN" "$INSTALL_DIR/"
cp "$WIN_PS" "$INSTALL_DIR/"
cp "$VM_HARDEN" "$INSTALL_DIR/"
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
cp "$NN_SETUP" "$INSTALL_DIR/"
cp "$NN_RUN" "$INSTALL_DIR/"
cp "$NN_RUN_SERVICE" "$INSTALL_DIR/"
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
cp "$IDS_MENU" "$INSTALL_DIR/"

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
mkisofs -D -r -V "Kali Custom" -cache-inodes -J -l -b isolinux/isolinux.bin \
 -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table \
 -o "$OUT_ISO" "$WORKDIR"

# Make hybrid for USB booting
isohybrid "$OUT_ISO"

echo "Custom ISO created at $OUT_ISO"