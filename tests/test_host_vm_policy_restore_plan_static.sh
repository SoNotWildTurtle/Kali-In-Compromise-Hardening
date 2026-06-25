#!/usr/bin/env bash
# MINC - Static tests for review-only host/VM policy restore planning.
# Defensive validation only; this test does not alter firewall, systemd, model, or host state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[restore-plan-static][FAIL] $*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "missing required file: $1"
}

require_file host_vm_policy_restore_plan.py
require_file host_vm_policy_restore_plan.service
require_file host_vm_policy_restore_plan.timer
require_file docs/host_vm_policy_restore_plan.md

python3 -m py_compile host_vm_policy_restore_plan.py

grep -q "changes_live_state.*False" host_vm_policy_restore_plan.py || fail "planner must declare no live-state changes"
grep -q "safe_default" host_vm_policy_restore_plan.py || fail "planner must write safe default language"
grep -q "manual_restore_review_required" host_vm_policy_restore_plan.py || fail "planner must require manual review"
! grep -Eq "subprocess|nft -f|systemctl (start|enable|restart)|iptables|ufw" host_vm_policy_restore_plan.py || fail "planner must remain review-only"

grep -q '^NoNewPrivileges=true' host_vm_policy_restore_plan.service || fail "service missing NoNewPrivileges"
grep -q '^ProtectSystem=strict' host_vm_policy_restore_plan.service || fail "service missing strict filesystem protection"
grep -q '^CapabilityBoundingSet=$' host_vm_policy_restore_plan.service || fail "service should not retain Linux capabilities"
grep -q '^RestrictAddressFamilies=AF_UNIX' host_vm_policy_restore_plan.service || fail "service should not need network sockets"

grep -q 'review-only' docs/host_vm_policy_restore_plan.md || fail "docs must describe review-only posture"
grep -q 'does not alter nftables' docs/host_vm_policy_restore_plan.md || fail "docs must state no nftables changes"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$TMP_DIR/etc" "$TMP_DIR/nftables.d" "$TMP_DIR/state"
printf 'HOST_VM_HOST_CIDR="192.168.56.1/32"\n' > "$TMP_DIR/etc/host_vm_comm_guard.conf"
printf 'table inet host_vm_comm_guard {}\n' > "$TMP_DIR/nftables.d/host_vm_comm_guard.nft"
printf '{"decision":"accept","created_utc":"2026-01-01T00:00:00Z"}\n' > "$TMP_DIR/state/policy_verify.json"
printf '{"schema_version":1}\n' > "$TMP_DIR/state/policy_attestation.baseline.json"

python3 host_vm_policy_restore_plan.py \
    --capture-known-good \
    --baseline "$TMP_DIR/state/policy_attestation.baseline.json" \
    --known-good-dir "$TMP_DIR/state/known_good" \
    --output "$TMP_DIR/state/capture.json" \
    --report "$TMP_DIR/state/capture.report" >/dev/null

python3 host_vm_policy_restore_plan.py \
    --verify "$TMP_DIR/state/policy_verify.json" \
    --baseline "$TMP_DIR/state/policy_attestation.baseline.json" \
    --known-good-dir "$TMP_DIR/state/known_good" \
    --output "$TMP_DIR/state/plan.json" \
    --report "$TMP_DIR/state/plan.report" >/dev/null

grep -q '"changes_live_state": false' "$TMP_DIR/state/plan.json" || fail "plan should be non-mutating"
grep -q '"decision": "no_restore_needed"' "$TMP_DIR/state/plan.json" || fail "accept verification should need no restore"

echo "[restore-plan-static] passed"
