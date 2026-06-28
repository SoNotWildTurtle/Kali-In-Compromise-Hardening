#!/usr/bin/env bash
# MINC - Static behavior coverage for defensive firstboot final readiness evidence.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

summary="$TMPDIR/handoff_env_policy_smoke.summary.env"
json_out="$TMPDIR/final_readiness.json"
markdown_out="$TMPDIR/final_readiness.md"
summary_out="$TMPDIR/final_readiness.summary.env"

cat > "$summary" <<'ENV'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK='1'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION='approved'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE='pass'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_COMPONENT='firstboot_release_gate_handoff_env_policy_smoke'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_DECISION='approved'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SOURCE_PRIVACY_SCOPE='aggregate_release_gate_handoff_env_policy_smoke_only'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKER_COUNT='0'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_BLOCKERS='none'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_TOTAL_ARTIFACTS='7'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_PRIVACY_SCOPE='aggregate_release_gate_handoff_env_policy_smoke_only'
FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_SAFE_DEFAULT='read-only summary smoke validator; no live system state was changed'
ENV

python3 -m py_compile firstboot_final_readiness.py
python3 firstboot_final_readiness.py --input "$summary" --format json --output "$json_out" --summary "$summary_out" --require-pass
python3 - <<'PY' "$json_out"
import json
import sys
report = json.load(open(sys.argv[1], encoding='utf-8'))
assert report['ok'] is True
assert report['decision'] == 'approved'
assert report['release_gate'] == 'pass'
assert report['blockers'] == []
assert report['source_values']['total_artifacts'] == 7
assert report['privacy_scope'] == 'aggregate_firstboot_final_readiness_only'
assert 'read-only' in report['safe_default']
assert 'authoritative' in report['rollback_note']
PY

grep -q "FIRSTBOOT_FINAL_READINESS_OK='1'" "$summary_out"
grep -q "FIRSTBOOT_FINAL_READINESS_RELEASE_GATE='pass'" "$summary_out"
grep -q "FIRSTBOOT_FINAL_READINESS_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_only'" "$summary_out"

python3 firstboot_final_readiness.py --input "$summary" --format markdown --output "$markdown_out"
grep -q 'Final readiness is approved' "$markdown_out"
grep -q 'Rollback' "$markdown_out"

bad_summary="$TMPDIR/bad.summary.env"
cp "$summary" "$bad_summary"
sed -i "s/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_PRIVACY_SCOPE='aggregate_release_gate_handoff_env_policy_smoke_only'/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_PRIVACY_SCOPE='raw_logs'/" "$bad_summary"
if python3 firstboot_final_readiness.py --input "$bad_summary" --require-pass > "$TMPDIR/bad.out" 2>&1; then
    echo 'expected --require-pass to fail for mismatched privacy scope' >&2
    exit 1
fi
python3 firstboot_final_readiness.py --input "$bad_summary" --format json --output "$TMPDIR/bad.json"
grep -q 'privacy_scope_mismatch' "$TMPDIR/bad.json"

deferred_summary="$TMPDIR/deferred.summary.env"
cp "$summary" "$deferred_summary"
sed -i "s/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK='1'/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK='0'/" "$deferred_summary"
sed -i "s/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION='approved'/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION='deferred'/" "$deferred_summary"
sed -i "s/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE='pass'/FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE='stop'/" "$deferred_summary"
python3 firstboot_final_readiness.py --input "$deferred_summary" --format json --output "$TMPDIR/deferred.json"
grep -q 'deferred' "$TMPDIR/deferred.json"
grep -q 'stop' "$TMPDIR/deferred.json"

missing_key_summary="$TMPDIR/missing.summary.env"
grep -v 'FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_TOTAL_ARTIFACTS' "$summary" > "$missing_key_summary"
python3 firstboot_final_readiness.py --input "$missing_key_summary" --format json --output "$TMPDIR/missing.json"
grep -q 'missing_required_key:FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_TOTAL_ARTIFACTS' "$TMPDIR/missing.json"

grep -q 'firstboot_final_readiness.py' build_custom_iso.sh
grep -q 'firstboot_release_gate.final_readiness.json' firstboot_release_gate.service
grep -q 'firstboot_release_gate.final_readiness.md' firstboot_release_gate.service
grep -q 'firstboot_release_gate.final_readiness.summary.env' firstboot_release_gate.service
grep -q 'firstboot final readiness helper' docs/firstboot_final_readiness.md
grep -q 'read-only' docs/firstboot_final_readiness.md
grep -q 'Rollback' docs/firstboot_final_readiness.md
grep -q 'rollback' docs/changelog/firstboot_final_readiness.md

echo '[test] firstboot final readiness static checks passed'
