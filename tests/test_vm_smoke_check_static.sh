#!/usr/bin/env bash
# MINC - Static tests for the read-only VM smoke validation helper.
# Defensive validation only; does not alter the local system.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    printf '[vm-smoke-static][FAIL] %s\n' "$*" >&2
    exit 1
}

[[ -f vm_smoke_check.sh ]] || fail 'vm_smoke_check.sh is missing'
[[ -f docs/vm_smoke_check.md ]] || fail 'docs/vm_smoke_check.md is missing'

bash -n vm_smoke_check.sh || fail 'vm_smoke_check.sh has invalid Bash syntax'

grep -q 'Defensive validation only' vm_smoke_check.sh || fail 'script should declare defensive-only purpose'
grep -q 'does not alter' vm_smoke_check.sh || fail 'script should state non-mutating behavior'
grep -q -- '--strict' vm_smoke_check.sh || fail 'script should support strict release validation'
grep -q 'host_vm_comm_guard.sh status' vm_smoke_check.sh || fail 'script should validate host/VM communication guard status'
grep -q 'nn_ids_model_audit.timer' vm_smoke_check.sh || fail 'script should check NN model audit timer'
grep -q 'nn_ids_audit_gate.timer' vm_smoke_check.sh || fail 'script should check NN audit gate timer'
grep -q 'nft list ruleset' vm_smoke_check.sh || fail 'script should inspect nftables read-only'
grep -q 'journalctl --no-pager' vm_smoke_check.sh || fail 'script should collect recent journal context'

for forbidden in \
    'systemctl enable' \
    'systemctl start' \
    'systemctl restart' \
    'systemctl stop' \
    'nft add' \
    'nft delete' \
    'iptables -A' \
    'iptables -D' \
    'ufw allow' \
    'ufw deny' \
    'rm -rf' \
    'chattr +i'; do
    if grep -q "$forbidden" vm_smoke_check.sh; then
        fail "script should remain read-only and must not contain: $forbidden"
    fi
done

grep -q 'vm_smoke_check.sh' build_custom_iso.sh || fail 'build_custom_iso.sh should package vm_smoke_check.sh'
grep -q 'read-only' docs/vm_smoke_check.md || fail 'docs should describe read-only safety model'
grep -qi 'post-boot' docs/vm_smoke_check.md || fail 'docs should describe post-boot validation purpose'

printf '[vm-smoke-static] all checks passed\n'
