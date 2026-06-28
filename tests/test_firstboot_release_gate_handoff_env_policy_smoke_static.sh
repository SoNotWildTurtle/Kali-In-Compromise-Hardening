#!/usr/bin/env bash
# MINC - Static behavior coverage for defensive firstboot handoff env-policy smoke evidence.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

summary="$TMPDIR/handoff_env_policy.summary.env"
json_out="$TMPDIR/smoke.json"
markdown_out="$TMPDIR/smoke.md"

cat > "$summary" <<'ENV'
FIRSTBOOT_HANDOFF_ENV_POLICY_OK='1'
FIRSTBOOT_HANDOFF_ENV_POLICY_DECISION='approved'
FIRSTBOOT_HANDOFF_ENV_POLICY_RELEASE_GATE='pass'
FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_COMPONENT='firstboot_release_gate_handoff_env_policy'
FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_CREATED_UTC='2026-06-28T00:00:00Z'
FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_DECISION='approved'
FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_PRIVACY_SCOPE='aggregate_release_gate_handoff_status_reader_only'
FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKER_COUNT='0'
FIRSTBOOT_HANDOFF_ENV_POLICY_BLOCKERS='none'
FIRSTBOOT_HANDOFF_ENV_POLICY_TOTAL_ARTIFACTS='7'
FIRSTBOOT_HANDOFF_ENV_POLICY_PRIVACY_SCOPE='aggregate_release_gate_handoff_env_policy_only'
FIRSTBOOT_HANDOFF_ENV_POLICY_SAFE_DEFAULT='read-only summary evidence validator; no live system state was changed'
ENV

python3 -m py_compile firstboot_release_gate_handoff_env_policy_smoke.py
python3 firstboot_release_gate_handoff_env_policy_smoke.py --input "$summary" --format json --output "$json_out" --require-pass
python3 - <<'PY' "$json_out"
import json
import sys
report = json.load(open(sys.argv[1], encoding='utf-8'))
assert report['ok'] is True
assert report['decision'] == 'approved'
assert report['release_gate'] == 'pass'
assert report['blockers'] == []
assert report['source_values']['total_artifacts'] == 7
assert report['privacy_scope'] == 'aggregate_release_gate_handoff_env_policy_smoke_only'
assert 'read-only' in report['safe_default']
assert 'authoritative' in report['rollback_note']
PY

python3 firstboot_release_gate_handoff_env_policy_smoke.py --input "$summary" --format markdown --output "$markdown_out"
grep -q 'Env-policy summary evidence is smoke-approved' "$markdown_out"
grep -q 'Rollback' "$markdown_out"

bad_summary="$TMPDIR/bad.summary.env"
cp "$summary" "$bad_summary"
sed -i "s/FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_PRIVACY_SCOPE='aggregate_release_gate_handoff_status_reader_only'/FIRSTBOOT_HANDOFF_ENV_POLICY_SOURCE_PRIVACY_SCOPE='raw_logs'/" "$bad_summary"
if python3 firstboot_release_gate_handoff_env_policy_smoke.py --input "$bad_summary" --require-pass > "$TMPDIR/bad.out" 2>&1; then
    echo 'expected --require-pass to fail for mismatched privacy scope' >&2
    exit 1
fi
python3 firstboot_release_gate_handoff_env_policy_smoke.py --input "$bad_summary" --format json --output "$TMPDIR/bad.json"
grep -q 'source_privacy_scope_mismatch' "$TMPDIR/bad.json"

missing_key_summary="$TMPDIR/missing.summary.env"
grep -v 'FIRSTBOOT_HANDOFF_ENV_POLICY_TOTAL_ARTIFACTS' "$summary" > "$missing_key_summary"
python3 firstboot_release_gate_handoff_env_policy_smoke.py --input "$missing_key_summary" --format json --output "$TMPDIR/missing.json"
grep -q 'missing_required_key:FIRSTBOOT_HANDOFF_ENV_POLICY_TOTAL_ARTIFACTS' "$TMPDIR/missing.json"

grep -q 'firstboot_release_gate_handoff_env_policy_smoke.py' build_custom_iso.sh
grep -q 'firstboot_release_gate.handoff_env_policy_smoke.json' firstboot_release_gate.service
grep -q 'firstboot_release_gate.handoff_env_policy_smoke.md' firstboot_release_gate.service
grep -q 'env-policy smoke' docs/firstboot_release_gate_handoff_env_policy_smoke.md
grep -q 'read-only' docs/firstboot_release_gate_handoff_env_policy_smoke.md
grep -q 'rollback' docs/changelog/firstboot_release_gate_handoff_env_policy_smoke.md

echo '[test] firstboot handoff env-policy smoke static checks passed'
