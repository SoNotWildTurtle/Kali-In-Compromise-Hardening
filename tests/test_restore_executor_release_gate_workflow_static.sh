#!/usr/bin/env bash
# MINC - Static validation for the restore executor release gate workflow.
# Defensive test only: checks repository text and never changes host, VM, firewall, IDS, or systemd state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT_DIR/.github/workflows/restore-executor-release-gate.yml"
DOC="$ROOT_DIR/docs/restore_executor_release_gate.md"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ -f "$WORKFLOW" ]] || fail "restore executor release gate workflow is missing"
[[ -f "$DOC" ]] || fail "restore executor release gate documentation is missing"

python3 -m py_compile "$ROOT_DIR/host_vm_restore_executor_wiring_check.py"

grep -q "host_vm_restore_executor_wiring_check.py" "$WORKFLOW" || fail "workflow does not run the wiring checker"
grep -q -- "--strict" "$WORKFLOW" || fail "workflow must fail closed when wiring is incomplete"
grep -q "permissions:" "$WORKFLOW" || fail "workflow permissions block missing"
grep -q "contents: read" "$WORKFLOW" || fail "workflow should use read-only content permissions"
grep -q "actions/upload-artifact@v4" "$WORKFLOW" || fail "workflow should upload review artifacts"
grep -q "workflow_dispatch" "$WORKFLOW" || fail "workflow should support manual dispatch"

grep -q "build_custom_iso.sh" "$WORKFLOW" || fail "workflow should trigger when ISO packaging changes"
grep -q "vm_smoke_check.sh" "$WORKFLOW" || fail "workflow should trigger when VM smoke checks change"
grep -q "tests/\*\*" "$WORKFLOW" || fail "workflow should trigger when tests change"

grep -q "does not run nftables" "$DOC" || fail "documentation must state workflow is non-mutating"
grep -q "host_vm_policy_restore_execute.timer" "$DOC" || fail "documentation must preserve no-timer rule"
grep -q "wiring_review_required" "$DOC" || fail "documentation must describe expected fail-closed state"

if grep -q "systemctl\|nft\|--execute" "$WORKFLOW"; then
    fail "workflow must not run live system, firewall, or restore execution commands"
fi

echo "restore executor release gate workflow static checks passed"
