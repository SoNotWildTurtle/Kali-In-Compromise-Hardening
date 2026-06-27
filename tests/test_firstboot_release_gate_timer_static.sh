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

python3 -m py_compile firstboot_release_gate.py
bash -n build_custom_iso.sh
bash -n firstboot.sh

for unit in firstboot_release_gate.service firstboot_release_gate.timer; do
    [[ -f "$unit" ]] || fail "Missing $unit"
done

assert_file_contains build_custom_iso.sh '"firstboot_release_gate.service"'
assert_file_contains build_custom_iso.sh '"firstboot_release_gate.timer"'
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

assert_file_contains firstboot_release_gate.timer 'OnBootSec=15min'
assert_file_contains firstboot_release_gate.timer 'OnUnitActiveSec=1h'
assert_file_contains firstboot_release_gate.timer 'Persistent=true'
assert_file_contains firstboot_release_gate.timer 'Unit=firstboot_release_gate.service'

if grep -Eq 'Exec(Start|StartPre|StartPost)=.*(iptables|nft|ufw|systemctl restart|service .* restart|rm -rf|curl|wget|ssh|scp|nc|ncat|socat)' firstboot_release_gate.service; then
    fail 'firstboot_release_gate.service must remain passive and offline'
fi

if grep -Eq '(iptables|nft|ufw|systemctl restart|service .* restart|rm -rf|curl|wget|ssh|scp|nc|ncat|socat)' firstboot_release_gate.timer; then
    fail 'firstboot_release_gate.timer must remain passive and offline'
fi

echo '[PASS] firstboot release gate timer static coverage'
