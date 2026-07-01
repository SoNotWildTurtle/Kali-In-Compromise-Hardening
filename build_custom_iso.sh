#!/usr/bin/env bash
# MINC - Build a custom Kali Linux ISO using included hardening modules.
# Defensive build helper only: packages local scripts into a Kali ISO tree.

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage: ./build_custom_iso.sh <installer|live> <output_iso> [working_dir]

Modes:
  installer  Build from the current Kali installer ISO and use standalone first boot flow.
  live       Build from the current Kali live ISO and include host hardening modules.

Example:
  ./build_custom_iso.sh live ./kali-hardened-live.iso /tmp/kali-iso-build
USAGE
}

if [[ $# -lt 2 ]]; then
    usage
    exit 1
fi

MODE="$1"
OUT_ISO="$2"
WORKDIR="${3:-/tmp/kali-iso-build}"
BASE_URL="${KALI_BASE_URL:-https://cdimage.kali.org/current}"

case "$MODE" in
    installer)
        ISO_PATTERN='kali-linux-.*-installer-amd64\.iso'
        PRESEED_SRC="kali-preseed-single.cfg"
        FIRSTBOOT="firstboot_single.sh"
        INCLUDE_HOST_MODULES=false
        ;;
    live)
        ISO_PATTERN='kali-linux-.*-live-amd64\.iso'
        PRESEED_SRC="kali-preseed.cfg"
        FIRSTBOOT="firstboot.sh"
        INCLUDE_HOST_MODULES=true
        ;;
    *)
        echo "Mode must be 'installer' or 'live'." >&2
        usage
        exit 2
        ;;
esac

require_cmds=(curl bsdtar mkisofs isohybrid)
for cmd in "${require_cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Required command '$cmd' not found." >&2
        exit 1
    fi
done

require_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "Required repository file missing: $file" >&2
        exit 1
    fi
}

copy_if_present() {
    local file="$1"
    local dest="$2"
    if [[ -f "$file" ]]; then
        cp "$file" "$dest/"
    else
        echo "Optional file not found, skipping: $file" >&2
    fi
}

core_modules=(
    "$FIRSTBOOT"
    "$PRESEED_SRC"
    "security_scan_scheduler.sh"
    "mac_randomizer.sh"
    "mac_randomizer.service"
    "network_io_monitor.sh"
    "network_io_monitor.service"
    "internet_access_monitor.sh"
    "internet_access_monitor.service"
    "internet_access_monitor.timer"
    "secure_dev_env.sh"
    "vm_pro_hardening.sh"
    "anti_wipe_monitor.sh"
    "anti_wipe_monitor.service"
    "network_discovery.sh"
    "network_discovery_visualize.py"
    "ids_menu.sh"
    "host_vm_comm_guard.sh"
    "host_vm_comm_guard.service"
    "host_vm_channel_policy.py"
    "host_vm_channel_policy.example.json"
    "host_vm_policy_attest.py"
    "host_vm_policy_attest.service"
    "host_vm_policy_attest.timer"
    "host_vm_policy_verify.py"
    "host_vm_policy_verify.service"
    "host_vm_policy_verify.timer"
    "host_vm_policy_restore_plan.py"
    "host_vm_policy_restore_plan.service"
    "host_vm_policy_restore_plan.timer"
    "host_vm_policy_approval_check.py"
    "host_vm_policy_approval_check.service"
    "host_vm_policy_approval_check.timer"
    "host_vm_policy_evidence_bundle.py"
    "host_vm_policy_evidence_bundle_receipt.py"
    "host_vm_policy_firstboot_handoff.py"
    "host_vm_policy_firstboot_manifest.py"
    "firstboot_release_gate.py"
    "firstboot_release_gate_status.py"
    "firstboot_release_gate_bundle_manifest.py"
    "firstboot_release_gate_operator_digest.py"
    "firstboot_release_gate_handoff_index.py"
    "firstboot_release_gate_handoff_verify.py"
    "firstboot_release_gate_handoff_freshness.py"
    "firstboot_release_gate_handoff_summary_smoke.py"
    "firstboot_release_gate_handoff_status_reader.py"
    "firstboot_release_gate_handoff_env_policy.py"
    "firstboot_release_gate_handoff_env_policy_smoke.py"
    "firstboot_final_readiness.py"
    "firstboot_final_readiness_smoke.py"
    "firstboot_final_readiness_manifest.py"
    "firstboot_final_readiness_manifest_smoke.py"
    "firstboot_final_readiness_contract_seal.py"
    "firstboot_final_readiness_contract_seal_smoke.py"
    "firstboot_final_readiness_operator_verdict.py"
    "firstboot_final_readiness_operator_bundle.py"
    "firstboot_final_readiness_operator_bundle_smoke.py"
    "firstboot_final_readiness_operator_bundle_index.py"
    "firstboot_final_readiness_release_receipt.py"
    "firstboot_final_readiness_release_receipt_smoke.py"
    "firstboot_final_readiness_release_receipt_smoke_index.py"
    "firstboot_final_readiness_release_receipt_handoff_digest.py"
    "firstboot_final_readiness_release_receipt_handoff_digest_smoke.py"
    "firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py"
    "firstboot_final_readiness_release_promotion_checkpoint.py"
    "firstboot_release_gate.service"
    "firstboot_release_gate.timer"
    "host_vm_policy_restore_execute.py"
    "host_vm_policy_restore_execute.service"
    "vm_smoke_check.sh"
)

ids_modules=(
    "nn_ids.conf"
    "nn_ids_triage_record_validate.sh"
    "nn_ids_triage_bundle_manifest.py"
    "nn_ids_setup.py"
    "setup_nn_ids.sh"
    "setup_nn_ids.service"
    "nn_ids_feature_schema.py"
    "nn_os_train.py"
    "nn_ids_service.py"
    "nn_ids.service"
    "nn_ids_capture.py"
    "nn_ids_capture.service"
    "nn_ids_capture.timer"
    "nn_ids_retrain.py"
    "nn_ids_retrain.service"
    "nn_ids_retrain.timer"
    "packet_sanitizer.py"
    "nn_ids_healthcheck.py"
    "nn_ids_healthcheck.service"
    "nn_ids_healthcheck.timer"
    "nn_ids_health_evidence.py"
    "nn_ids_health_evidence.service"
    "nn_ids_health_evidence.timer"
    "nn_ids_snapshot.py"
    "nn_ids_snapshot.service"
    "nn_ids_snapshot.timer"
    "nn_ids_restore.py"
    "nn_ids_restore.service"
    "nn_ids_restore.timer"
    "nn_ids_logrotate"
    "nn_ids_autoblock.py"
    "nn_ids_autoblock.service"
    "nn_ids_autoblock.timer"
    "nn_ids_report.py"
    "nn_ids_report.service"
    "nn_ids_report.timer"
    "threat_feed_blocklist.py"
    "threat_feed_blocklist.service"
    "threat_feed_blocklist.timer"
    "nn_ids_resource_monitor.py"
    "nn_ids_resource_monitor.service"
    "nn_ids_resource_monitor.timer"
    "nn_ids_sanitize.py"
    "nn_ids_sanitize.service"
    "nn_ids_sanitize.timer"
    "nn_ids_model_audit.py"
    "nn_ids_model_audit.service"
    "nn_ids_model_audit.timer"
    "nn_ids_audit_gate.py"
    "nn_ids_audit_gate.service"
    "nn_ids_audit_gate.timer"
    "process_service_monitor.py"
    "process_monitor.service"
    "process_monitor.timer"
    "port_socket_monitor.py"
    "port_socket_monitor.service"
    "port_socket_monitor.timer"
)

host_modules=(
    "host_hardening_windows.sh"
    "windows_hardening.ps1"
    "vm_windows_env_hardening.sh"
    "host_hardening_linux.sh"
    "vm_linux_env_hardening.sh"
    "ai_agent_commands.sh"
)

for file in "${core_modules[@]}" "${ids_modules[@]}"; do
    require_file "$file"
done
if [[ "$INCLUDE_HOST_MODULES" == true ]]; then
    for file in "${host_modules[@]}"; do
        require_file "$file"
    done
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

ISO_NAME="$(curl -fsSL "$BASE_URL/" | grep -oP "$ISO_PATTERN" | head -n 1 || true)"
if [[ -z "$ISO_NAME" ]]; then
    echo "Could not discover Kali ISO matching $ISO_PATTERN from $BASE_URL" >&2
    exit 1
fi

ORIG_ISO="$WORKDIR/$ISO_NAME"
echo "Downloading $BASE_URL/$ISO_NAME"
curl -fL -o "$ORIG_ISO" "$BASE_URL/$ISO_NAME"

EXTRACT_DIR="$WORKDIR/extracted"
mkdir -p "$EXTRACT_DIR"
bsdtar -C "$EXTRACT_DIR" -xf "$ORIG_ISO"

mkdir -p "$EXTRACT_DIR/preseed" "$EXTRACT_DIR/install"
cp "$PRESEED_SRC" "$EXTRACT_DIR/preseed/kali-preseed.cfg"

INSTALL_DIR="$EXTRACT_DIR/install"
for file in "${core_modules[@]}" "${ids_modules[@]}"; do
    # Preseed is copied to /preseed under a stable name, not /install.
    [[ "$file" == "$PRESEED_SRC" ]] && continue
    copy_if_present "$file" "$INSTALL_DIR"
done

if [[ "$INCLUDE_HOST_MODULES" == true ]]; then
    for file in "${host_modules[@]}"; do
        copy_if_present "$file" "$INSTALL_DIR"
    done
fi

cat > "$INSTALL_DIR/firstboot.service" <<SERVICE
[Unit]
Description=First boot hardening
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/${FIRSTBOOT}
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
SERVICE

mkisofs -o "$OUT_ISO" -b isolinux/isolinux.bin -c isolinux/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table "$EXTRACT_DIR"
isohybrid "$OUT_ISO"

echo "Custom Kali ISO created at $OUT_ISO"
