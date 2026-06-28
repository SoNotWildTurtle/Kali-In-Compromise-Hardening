#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release-gate timer wiring.
# Defensive validation only: no systemd state, host settings, VM settings, firewall rules, or IDS data are changed.

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

assert_no_timer_command_token() {
    local file="$1"
    local token="$2"
    if grep -Eq "(^|[[:space:]/;|&])${token}([[:space:];|&]|$)" "$file"; then
        fail "$file must not contain disallowed command token: $token"
    fi
}

python3 -m py_compile firstboot_release_gate.py
python3 -m py_compile firstboot_release_gate_status.py
python3 -m py_compile firstboot_release_gate_bundle_manifest.py
python3 -m py_compile firstboot_release_gate_operator_digest.py
python3 -m py_compile firstboot_release_gate_handoff_index.py
python3 -m py_compile firstboot_release_gate_handoff_verify.py
python3 -m py_compile firstboot_release_gate_handoff_freshness.py
bash -n build_custom_iso.sh
bash -n firstboot.sh

for unit in firstboot_release_gate.service firstboot_release_gate.timer; do
    [[ -f "$unit" ]] || fail "Missing $unit"
done

assert_file_contains build_custom_iso.sh '"firstboot_release_gate.service"'
assert_file_contains build_custom_iso.sh '"firstboot_release_gate.timer"'
assert_file_contains build_custom_iso.sh '"firstboot_release_gate_handoff_index.py"'
assert_file_contains build_custom_iso.sh '"firstboot_release_gate_handoff_verify.py"'
assert_file_contains build_custom_iso.sh '"firstboot_release_gate_handoff_freshness.py"'
assert_file_contains firstboot.sh 'systemctl enable --now firstboot_release_gate.timer || true'
assert_file_contains firstboot.sh '/usr/local/bin/firstboot_release_gate.py --max-artifact-age-minutes "${FIRSTBOOT_RELEASE_GATE_MAX_AGE_MINUTES:-240}"'

assert_file_contains firstboot_release_gate.service 'NoNewPrivileges=true'
assert_file_contains firstboot_release_gate.service 'PrivateTmp=true'
assert_file_contains firstboot_release_gate.service 'ProtectSystem=full'
assert_file_contains firstboot_release_gate.service 'ProtectHome=true'
assert_file_contains firstboot_release_gate.service 'ProtectKernelTunables=true'
assert_file_contains firstboot_release_gate.service 'ProtectKernelModules=true'
assert_file_contains firstboot_release_gate.service 'ProtectControlGroups=true'
assert_file_contains firstboot_release_gate.service 'CapabilityBoundingSet='
assert_file_contains firstboot_release_gate.service 'ReadOnlyPaths=/var/log/host_vm_policy_firstboot_manifest.json /var/log/nn_ids_model_card.json'
assert_file_contains firstboot_release_gate.service 'ReadWritePaths=/var/log'
assert_file_contains firstboot_release_gate.service '--max-artifact-age-minutes 240'
assert_file_contains firstboot_release_gate.service '--output /var/log/firstboot_release_gate.json'
assert_file_contains firstboot_release_gate.service '--markdown /var/log/firstboot_release_gate.md'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_status.py --summary /var/log/firstboot_release_gate.summary.env --format json > /var/log/firstboot_release_gate.status.json || true'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_bundle_manifest.py --gate-json /var/log/firstboot_release_gate.json --gate-markdown /var/log/firstboot_release_gate.md --summary /var/log/firstboot_release_gate.summary.env --status-json /var/log/firstboot_release_gate.status.json --output /var/log/firstboot_release_gate.bundle_manifest.json'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_bundle_manifest.py --gate-json /var/log/firstboot_release_gate.json --gate-markdown /var/log/firstboot_release_gate.md --summary /var/log/firstboot_release_gate.summary.env --status-json /var/log/firstboot_release_gate.status.json --output /var/log/firstboot_release_gate.bundle_manifest.md --format markdown'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_operator_digest.py --status-json /var/log/firstboot_release_gate.status.json --bundle-json /var/log/firstboot_release_gate.bundle_manifest.json --output /var/log/firstboot_release_gate.operator_digest.json'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_index.py --output /var/log/firstboot_release_gate.handoff_index.json'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_index.py --output /var/log/firstboot_release_gate.handoff_index.md --format markdown'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_verify.py --index /var/log/firstboot_release_gate.handoff_index.json --artifact-root /var/log --output /var/log/firstboot_release_gate.handoff_verify.json'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_verify.py --index /var/log/firstboot_release_gate.handoff_index.json --artifact-root /var/log --output /var/log/firstboot_release_gate.handoff_verify.md --format markdown'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_freshness.py --input /var/log/firstboot_release_gate.handoff_verify.json --output /var/log/firstboot_release_gate.handoff_freshness.json --max-artifact-age-minutes 240'
assert_file_contains firstboot_release_gate.service 'firstboot_release_gate_handoff_freshness.py --input /var/log/firstboot_release_gate.handoff_verify.json --output /var/log/firstboot_release_gate.handoff_freshness.md --format markdown --max-artifact-age-minutes 240'

assert_file_contains firstboot_release_gate.timer 'OnBootSec=15min'
assert_file_contains firstboot_release_gate.timer 'OnUnitActiveSec=1h'
assert_file_contains firstboot_release_gate.timer 'Persistent=true'
assert_file_contains firstboot_release_gate.timer 'Unit=firstboot_release_gate.service'

# Keep this check token-aware: short command names must not match ordinary prose.
for token in iptables nft ufw curl wget ssh scp nc ncat socat; do
    assert_no_timer_command_token firstboot_release_gate.timer "$token"
done

echo '[PASS] firstboot release gate timer static coverage'
