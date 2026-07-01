#!/usr/bin/env bash
# MINC - Dependency-free schema fixture checks for aggregate release posture summaries.
# Defensive validation only: verifies the passive JSON schema and synthetic artifacts.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT_DIR/docs/schemas/host_vm_policy_release_posture_summary.schema.json"
SCRIPT="$ROOT_DIR/host_vm_policy_release_posture_summary.py"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

python3 -m json.tool "$SCHEMA" >/dev/null
grep -q '"release_posture_ready"' "$SCHEMA"
grep -q '"release_posture_blocked"' "$SCHEMA"
grep -q '"changes_live_state": {"const": false}' "$SCHEMA"
grep -q '"reads_raw_telemetry": {"const": false}' "$SCHEMA"
grep -q '"aggregate_evidence_only": {"const": true}' "$SCHEMA"
grep -q '"requires_human_review_before_release_promotion": {"const": true}' "$SCHEMA"

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
  "blocking_issues": []
}
JSON

cat > "$TMPDIR/restore-summary.json" <<'JSON'
{
  "schema_version": 1,
  "created_utc": "2026-06-30T00:00:00Z",
  "decision": "restore_summary_ready",
  "summary_ready": true,
  "blocking_issues": [],
  "changes_live_state": false,
  "reads_raw_telemetry": false,
  "aggregate_evidence_only": true,
  "requires_manual_invocation": true
}
JSON

python3 "$SCRIPT" \
  --firstboot-summary "$TMPDIR/firstboot-summary.json" \
  --restore-summary "$TMPDIR/restore-summary.json" \
  --output "$TMPDIR/posture-ready.json" \
  --strict >/dev/null

python3 - "$SCHEMA" "$TMPDIR/posture-ready.json" <<'PY'
import json
import re
import sys
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
artifact = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))

required = schema['required']
missing = [key for key in required if key not in artifact]
assert not missing, missing
assert set(artifact) <= set(schema['properties']), sorted(set(artifact) - set(schema['properties']))
assert artifact['schema_version'] == schema['properties']['schema_version']['const']
assert artifact['summary'] == schema['properties']['summary']['const']
assert artifact['decision'] in schema['properties']['decision']['enum']
assert artifact['decision'] == 'release_posture_ready'
assert artifact['posture_ready'] is True
assert artifact['blocking_issues'] == []
assert artifact['changes_live_state'] is False
assert artifact['reads_raw_telemetry'] is False
assert artifact['aggregate_evidence_only'] is True
assert re.match(schema['properties']['created_utc']['pattern'], artifact['created_utc'])

components = artifact['components']
assert set(components) == {'firstboot', 'restore'}
component_required = schema['$defs']['component']['required']
for component in components.values():
    missing_component = [key for key in component_required if key not in component]
    assert not missing_component, missing_component
    assert component['changes_live_state'] is False
    assert component['reads_raw_telemetry'] is False
    assert component['aggregate_evidence_only'] is True
    assert component['blocking_issue_count'] == 0

handoff = artifact['reviewer_handoff']
assert handoff['confirm_firstboot_summary_ready'] == 'summary_ready'
assert handoff['confirm_restore_summary_ready'] == 'restore_summary_ready'
assert handoff['confirm_no_live_state_change'] is True
assert handoff['confirm_no_raw_telemetry'] is True
assert handoff['requires_human_review_before_release_promotion'] is True
assert artifact['rollback']['live_state_rollback_required'] is False
PY

python3 - "$TMPDIR/restore-summary.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding='utf-8'))
data['requires_manual_invocation'] = False
data['blocking_issues'] = ['manual restore boundary not confirmed']
path.write_text(json.dumps(data), encoding='utf-8')
PY

if python3 "$SCRIPT" \
  --firstboot-summary "$TMPDIR/firstboot-summary.json" \
  --restore-summary "$TMPDIR/restore-summary.json" \
  --output "$TMPDIR/posture-blocked.json" \
  --strict >/dev/null 2>&1; then
    echo "strict posture summary must fail when restore manual boundary is absent" >&2
    exit 1
fi

python3 - "$SCHEMA" "$TMPDIR/posture-blocked.json" <<'PY'
import json
import sys
from pathlib import Path
schema = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
artifact = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
assert artifact['decision'] == 'release_posture_blocked', artifact
assert artifact['decision'] in schema['properties']['decision']['enum']
assert artifact['posture_ready'] is False, artifact
assert len(artifact['blocking_issues']) >= 1, artifact
assert artifact['changes_live_state'] is False, artifact
assert artifact['reads_raw_telemetry'] is False, artifact
assert artifact['aggregate_evidence_only'] is True, artifact
assert any('requires_manual_invocation=true' in issue for issue in artifact['blocking_issues']), artifact
PY

echo "host_vm_policy_release_posture_summary schema tests passed"
