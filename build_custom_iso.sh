#!/bin/bash
# build_custom_iso.sh - Build a custom Kali Linux ISO using the included preseed
# and first boot hardening script.

set -euo pipefail

if [[ $# -lt 2 ]]; then
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
NN_HEALTH="nn_ids_healthcheck.py"
NN_HEALTH_SVC="nn_ids_healthcheck.service"
NN_HEALTH_TIMER="nn_ids_healthcheck.timer"
NN_LOGROTATE="nn_ids_logrotate"

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

MNTDIR="$WORKDIR/mnt"
mkdir -p "$MNTDIR"

# Extract original ISO
bsdtar -C "$WORKDIR" -xf "$ORIG_ISO"

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
cp "$NN_HEALTH" "$INSTALL_DIR/"
cp "$NN_HEALTH_SVC" "$INSTALL_DIR/"
cp "$NN_HEALTH_TIMER" "$INSTALL_DIR/"
cp "$NN_LOGROTATE" "$INSTALL_DIR/"
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

