#!/usr/bin/env bash
# MINC - Static and local behavior checks for host_vm_policy_approval_check.py.
# Defensive validation only; does not touch live firewall, systemd, model, host, or VM state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_approval_check.py"
SERVICE="$ROOT_DIR/host_vm_policy_approval_check.service"
TIMER="$ROOT_DIR/host_vm_policy_approval_check.timer"
DOC="$ROOT_DIR/docs/host_vm_policy_approval_check.md"
BUILD="$ROOT_DIR/build_custom_iso.sh"
FIRSTBOOT="$ROOT_DIR/firstboot.sh"
SMOKE="$ROOT_DIR/vm_smoke_check.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"

if ! grep -q 'changes_live_state.*False' "$SCRIPT"; then
    echo "approval checker must declare changes_live_state false" >&2
    exit 1
fi
if grep -Eq '\b(nft|systemctl|iptables|ufw|cp |mv |rm |shutil\.copy)' "$SCRIPT"; then
    echo "approval checker must not mutate live policy or system state" >&2
    exit 1
fi
if ! grep -q 'manual_restore_review_required' "$SCRIPT"; then
    echo "approval checker must require a restore-review plan decision" >&2
    exit 1
fi
if ! grep -q 'MAX_APPROVAL_AGE_SECONDS = 24 \* 60 \* 60' "$SCRIPT"; then
    echo "approval checker must enforce short-lived approvals" >&2
    exit 1
fi
if ! grep -q 'Ed25519' "$SCRIPT"; then
    echo "approval checker must support signed approvals" >&2
    exit 1
fi

for required in \
    'NoNewPrivileges=true' \
    'ProtectSystem=strict' \
    'ProtectHome=true' \
    'CapabilityBoundingSet=' \
    'RestrictAddressFamilies=AF_UNIX'; do
    if ! grep -q "$required" "$SERVICE"; then
        echo "service missing hardening directive: $required" >&2
        exit 1
    fi
done
if ! grep -q 'Persistent=true' "$TIMER"; then
    echo "timer must be persistent" >&2
    exit 1
fi
if ! grep -q 'approval_valid' "$DOC" || ! grep -q 'approval_rejected' "$DOC"; then
    echo "documentation must describe approval decisions" >&2
    exit 1
fi

for token in \
    'host_vm_policy_approval_check.py' \
    'host_vm_policy_approval_check.service' \
    'host_vm_policy_approval_check.timer'; do
    if ! grep -q "\"$token\"" "$BUILD"; then
        echo "build_custom_iso.sh must package $token" >&2
        exit 1
    fi
done
if ! grep -q 'host_vm_policy_approval_check.timer' "$FIRSTBOOT"; then
    echo "firstboot.sh must enable approval checker timer" >&2
    exit 1
fi
if ! grep -q 'host_vm_policy_approval_check.py --write-template' "$FIRSTBOOT"; then
    echo "firstboot.sh must write denied-by-default approval template" >&2
    exit 1
fi
if [[ -f "$SMOKE" ]] && ! grep -q 'host_vm_policy_approval_check' "$SMOKE"; then
    echo "vm_smoke_check.sh should validate approval-check artifacts" >&2
    exit 1
fi

PLAN="$TMPDIR/plan.json"
APPROVAL="$TMPDIR/approval.json"
OUT="$TMPDIR/out.json"
REPORT="$TMPDIR/report.txt"
MISSING_KEY="$TMPDIR/no-key.pub"
NOW="$(date -u +%s)"
REVIEWED="$(date -u -d "@$NOW" +%Y-%m-%dT%H:%M:%SZ)"
EXPIRES="$(date -u -d "@$((NOW + 3600))" +%Y-%m-%dT%H:%M:%SZ)"

cat > "$PLAN" <<JSON
{
  "schema_version": 1,
  "created_utc": "$REVIEWED",
  "decision": "manual_restore_review_required",
  "baseline_sha256": "abc123",
  "actions": [
    {"status": "manual_restore_candidate", "target": "/etc/host_vm_comm_guard.conf"}
  ]
}
JSON

python3 "$SCRIPT" --plan "$PLAN" --approval "$APPROVAL" --output "$OUT" --report "$REPORT" --public-key "$MISSING_KEY" --write-template >/dev/null
if ! grep -q '"approved": false' "$APPROVAL"; then
    echo "approval template must default to approved=false" >&2
    exit 1
fi

cat > "$APPROVAL" <<JSON
{
  "approved": true,
  "purpose": "host_vm_policy_restore",
  "baseline_sha256": "abc123",
  "plan_created_utc": "$REVIEWED",
  "reviewed_utc": "$REVIEWED",
  "expires_utc": "$EXPIRES",
  "reviewer": "local-console-reviewer",
  "note": "Reviewed restore plan, local console access, rollback path, and known-good policy hashes."
}
JSON
python3 "$SCRIPT" --plan "$PLAN" --approval "$APPROVAL" --output "$OUT" --report "$REPORT" --public-key "$MISSING_KEY" >/dev/null
if ! grep -q '"decision": "approval_valid"' "$OUT"; then
    echo "valid unsigned/manual approval should pass when no public key is configured" >&2
    cat "$OUT" >&2
    exit 1
fi

cat > "$APPROVAL" <<JSON
{
  "approved": true,
  "purpose": "host_vm_policy_restore",
  "baseline_sha256": "wrong",
  "plan_created_utc": "$REVIEWED",
  "reviewed_utc": "$REVIEWED",
  "expires_utc": "$EXPIRES",
  "reviewer": "local-console-reviewer",
  "note": "Reviewed restore plan but hash mismatch should reject."
}
JSON
if python3 "$SCRIPT" --plan "$PLAN" --approval "$APPROVAL" --output "$OUT" --report "$REPORT" --public-key "$MISSING_KEY" >/dev/null 2>&1; then
    echo "mismatched baseline approval should fail" >&2
    exit 1
fi
if ! grep -q 'approval_rejected' "$OUT"; then
    echo "rejected approval should write approval_rejected" >&2
    cat "$OUT" >&2
    exit 1
fi

echo "host_vm_policy_approval_check static tests passed"
