#!/usr/bin/env bash
# MINC - Static regression test for host/VM restore planner packaging and firstboot wiring.
# Defensive validation only: does not alter firewall, systemd, model, or host state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    printf '[restore-planner-wiring][FAIL] %s\n' "$*" >&2
    exit 1
}

require_contains() {
    local file="$1"
    local token="$2"
    grep -Fq -- "$token" "$file" || fail "$file missing token: $token"
}

for file in \
    host_vm_policy_restore_plan.py \
    host_vm_policy_restore_plan.service \
    host_vm_policy_restore_plan.timer \
    docs/host_vm_policy_restore_plan.md \
    build_custom_iso.sh \
    firstboot.sh \
    vm_smoke_check.sh; do
    [[ -f "$file" ]] || fail "missing required file: $file"
done

bash -n vm_smoke_check.sh
python3 -m py_compile host_vm_policy_restore_plan.py

for token in \
    'host_vm_policy_restore_plan.py' \
    'host_vm_policy_restore_plan.service' \
    'host_vm_policy_restore_plan.timer'; do
    require_contains build_custom_iso.sh "$token"
done

require_contains firstboot.sh 'host_vm_policy_restore_plan.timer'
require_contains firstboot.sh 'host_vm_policy_restore_plan.py --capture-known-good'
require_contains firstboot.sh 'host_vm_policy_restore_plan.firstboot.log'
require_contains firstboot.sh 'host_vm_policy_restore_plan.capture.log'

require_contains vm_smoke_check.sh '/usr/local/bin/host_vm_policy_restore_plan.py'
require_contains vm_smoke_check.sh 'host_vm_policy_restore_plan.timer'
require_contains vm_smoke_check.sh '/var/log/host_vm_policy_restore_plan.firstboot.log'
require_contains vm_smoke_check.sh '/var/log/host_vm_policy_restore_plan.capture.log'
require_contains vm_smoke_check.sh '/var/log/host_vm_policy_restore_plan.report'
require_contains vm_smoke_check.sh '/var/lib/host_vm_comm_guard/policy_restore_plan.json'
require_contains vm_smoke_check.sh '/var/lib/host_vm_comm_guard/known_good/manifest.json'

require_contains host_vm_policy_restore_plan.service 'NoNewPrivileges=true'
require_contains host_vm_policy_restore_plan.service 'PrivateTmp=true'
require_contains host_vm_policy_restore_plan.service 'ProtectSystem=strict'
require_contains host_vm_policy_restore_plan.service 'CapabilityBoundingSet='

printf '[restore-planner-wiring] restore planner packaging, firstboot, smoke, and service hardening checks passed\n'
