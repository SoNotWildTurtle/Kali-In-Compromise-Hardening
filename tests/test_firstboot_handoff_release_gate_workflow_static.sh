#!/usr/bin/env bash
# MINC - Static test for passive firstboot handoff release gate workflow wiring.
# Defensive validation only: checks CI wiring and aggregate evidence artifact expectations.

set -euo pipefail

WORKFLOW=".github/workflows/firstboot-handoff-release-gate.yml"

[[ -f "$WORKFLOW" ]]

grep -q '^name: Firstboot Handoff Release Gate$' "$WORKFLOW"
grep -q 'host_vm_policy_firstboot_handoff_gate.py' "$WORKFLOW"
grep -q 'host_vm_policy_firstboot_release_receipt.py' "$WORKFLOW"
grep -q 'tests/test_host_vm_policy_firstboot_handoff_gate_static.sh' "$WORKFLOW"
grep -q 'tests/test_host_vm_policy_firstboot_release_receipt_static.sh' "$WORKFLOW"
grep -q -- '--strict' "$WORKFLOW"
grep -q 'firstboot_handoff_gate.json' "$WORKFLOW"
grep -q 'firstboot_handoff_gate.report' "$WORKFLOW"
grep -q 'firstboot_release_receipt.json' "$WORKFLOW"
grep -q 'firstboot_release_receipt.report' "$WORKFLOW"
grep -q 'release_receipt_ready' "$WORKFLOW"
grep -q 'Build expected blocked receipt fixture' "$WORKFLOW"
grep -q 'firstboot_handoff_gate.blocked.json' "$WORKFLOW"
grep -q 'firstboot_handoff_gate.blocked.report' "$WORKFLOW"
grep -q 'firstboot_release_receipt.blocked.json' "$WORKFLOW"
grep -q 'firstboot_release_receipt.blocked.report' "$WORKFLOW"
grep -q 'release_receipt_blocked' "$WORKFLOW"
grep -q 'gate check not passing: validation_valid' "$WORKFLOW"
grep -q 'actions/upload-artifact@v4' "$WORKFLOW"
grep -q 'firstboot-handoff-gate-evidence' "$WORKFLOW"
grep -q 'firstboot-handoff-gate-blocked-fixture' "$WORKFLOW"
grep -q 'if-no-files-found: error' "$WORKFLOW"

if grep -Eq 'sudo|systemctl|apt-get|iptables|nft|ssh|scp|curl|wget' "$WORKFLOW"; then
    echo "workflow must remain passive and avoid live host/VM mutation or network fetch commands" >&2
    exit 1
fi

echo "firstboot handoff release gate workflow static checks passed"
