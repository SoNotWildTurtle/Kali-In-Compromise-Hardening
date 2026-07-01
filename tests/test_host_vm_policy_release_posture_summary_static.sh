#!/usr/bin/env bash
# MINC - Static and behavioral checks for passive aggregate release posture summaries.
# Defensive validation only: uses synthetic firstboot and restore summary JSON.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/host_vm_policy_release_posture_summary.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m py_compile "$SCRIPT"
grep -q "release_posture_ready" "$SCRIPT"
grep -q "release_posture_blocked" "$SCRIPT"
grep -q "aggregate_evidence_only" "$SCRIPT"
grep -q "requires_human_review_before_release_promotion" "$SCRIPT"

cat > "$TMPDIR/firstboot-summary.json" <<'JSON'
{
  "schema_version": 1,
  "summary": "host_vm_policy_firstboot_release_summary.py",
  "summary_version": "1.0.0",
  "created_utc": "2026-06-30T00:00:00Z",
  "decision": "summary_ready",
  "summary_ready": true,
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "aggregate_evidence_only": true,
  "ready_receipt": {
    "decision": "release_receipt_ready",
    "release_ready": true,
    "blocking_issue_count": 0
  },
  "expected_blocked_receipt": {
    "present": true,
    "decision": "release_receipt_blocked",
    "release_ready": false,
    "blocking_issue_count": 1
  },
  "blocking_issues": []
}
JSON

cat > "$TMPDIR/restore-summary.json" <<'JSON'
{
  "schema_version": 1,
  "created_utc": "2026-06-30T00:00:00Z",
  "decision": "restore_summary_ready",
  "summary_ready": true,
  "ready_restore_decision": "restore_ready_dry_run",
  "expected_blocked_decision": "restore_blocked",
  "blocking_issues": [],
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "aggregate_evidence_only": true,
  "requires_manual_invocation": true,
  "safe_default": "passive summary only; restore execution remains manual and dry-run by default",
  "reviewer_handoff": {
    "confirm_no_live_state_change": true,
    "confirm_manual_restore_only": true
  }
}
JSON

python3 "$SCRIPT" \
  --firstboot-summary "$TMPDIR/firstboot-summary.json" \
  --restore-summary "$TMPDIR/restore-summary.json" \
  --output "$TMPDIR/posture.json" \
  --report "$TMPDIR/posture.report" \
  --strict >/dev/null

python3 - "$TMPDIR/posture.json" <<'PY'
import json, sys
posture = json.load(open(sys.argv[1]))
assert posture['decision'] == 'release_posture_ready', posture
assert posture['posture_ready'] is True, posture
assert posture['changes_live_state'] is False, posture
assert posture['reads_raw_telemetry'] is False, posture
assert posture['aggregate_evidence_only'] is True, posture
assert posture['blocking_issues'] == [], posture
assert posture['components']['firstboot']['decision'] == 'summary_ready', posture
assert posture['components']['restore']['decision'] == 'restore_summary_ready', posture
assert posture['reviewer_handoff']['requires_human_review_before_release_promotion'] is True, posture
assert posture['rollback']['live_state_rollback_required'] is False, posture
PY

grep -q '^decision=release_posture_ready$' "$TMPDIR/posture.report"
grep -q '^posture_ready=true$' "$TMPDIR/posture.report"
grep -q '^blocking_issue_count=0$' "$TMPDIR/posture.report"

python3 - "$TMPDIR/restore-summary.json" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
data['decision'] = 'restore_summary_blocked'
data['summary_ready'] = False
data['blocking_issues'] = ['synthetic restore release blocker']
json.dump(data, open(path, 'w'))
PY

if python3 "$SCRIPT" \
  --firstboot-summary "$TMPDIR/firstboot-summary.json" \
  --restore-summary "$TMPDIR/restore-summary.json" \
  --output "$TMPDIR/posture-blocked.json" \
  --report "$TMPDIR/posture-blocked.report" \
  --strict >/dev/null 2>&1; then
    echo "strict posture summary must fail for blocked restore evidence" >&2
    exit 1
fi

python3 - "$TMPDIR/posture-blocked.json" <<'PY'
import json, sys
posture = json.load(open(sys.argv[1]))
assert posture['decision'] == 'release_posture_blocked', posture
assert posture['posture_ready'] is False, posture
assert any('restore summary decision must be restore_summary_ready' in issue for issue in posture['blocking_issues']), posture
assert any('restore summary_ready must be true' in issue for issue in posture['blocking_issues']), posture
PY

grep -q '^decision=release_posture_blocked$' "$TMPDIR/posture-blocked.report"
grep -q '^posture_ready=false$' "$TMPDIR/posture-blocked.report"
grep -Eq '^blocking_issue_count=[1-9][0-9]*$' "$TMPDIR/posture-blocked.report"

echo "host_vm_policy_release_posture_summary static tests passed"
