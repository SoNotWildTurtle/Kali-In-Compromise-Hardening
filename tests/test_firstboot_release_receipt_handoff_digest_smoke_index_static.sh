#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release receipt handoff digest smoke index evidence.
# Defensive validation only: no systemd state, host settings, VM settings, firewall rules, restore state, or IDS data are changed.

set -euo pipefail

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

assert_file_contains() {
    local file="$1"
    local expected="$2"
    grep -Fq -- "$expected" "$file" || fail "Expected '$expected' in $file"
}

assert_no_command_token() {
    local file="$1"
    local token="$2"
    if grep -Eq "(^|[[:space:]/;|&])${token}([[:space:];|&]|$)" "$file"; then
        fail "$file must not contain disallowed command token: $token"
    fi
}

python3 -m py_compile firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py
bash -n build_custom_iso.sh

assert_file_contains build_custom_iso.sh '"firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py"'
assert_file_contains firstboot_release_gate.service 'firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py --input /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.summary.env --format json --output /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.json --summary /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env'
assert_file_contains firstboot_release_gate.service 'firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py --input /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke.summary.env --format markdown --output /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.md'
assert_file_contains firstboot_release_gate.service 'NoNewPrivileges=true'
assert_file_contains firstboot_release_gate.service 'ProtectSystem=full'
assert_file_contains firstboot_release_gate.service 'CapabilityBoundingSet='
assert_file_contains firstboot_release_gate.service 'ReadWritePaths=/var/log'

assert_file_contains firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py 'does not source shell content'
assert_file_contains firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py 'aggregate_metadata_only'
assert_file_contains firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py 'passive_handoff_digest_smoke_index_only_no_host_vm_firewall_service_network_restore_or_model_changes'
assert_file_contains firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py 'No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.'
assert_file_contains docs/firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.md 'does not source shell content'
assert_file_contains docs/firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.md 'Rollback'
assert_file_contains CHANGELOG.md 'firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py'

for token in iptables nft ufw curl wget ssh scp nc ncat socat systemctl; do
    assert_no_command_token firstboot_final_readiness_release_receipt_handoff_digest_smoke_index.py "$token"
done

echo '[PASS] firstboot release receipt handoff digest smoke index static coverage'
