#!/usr/bin/env bash
# MINC - Static checks for passive firstboot final-readiness smoke evidence.
# Defensive validation only: creates synthetic aggregate summaries in a temp directory.

set -euo pipefail

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

SUMMARY="$TMPDIR/final_readiness.summary.env"
JSON_OUT="$TMPDIR/final_readiness_smoke.json"
MD_OUT="$TMPDIR/final_readiness_smoke.md"
SIDE_OUT="$TMPDIR/final_readiness_smoke.summary.env"

cat > "$SUMMARY" <<'SUMMARY'
FIRSTBOOT_FINAL_READINESS_OK='1'
FIRSTBOOT_FINAL_READINESS_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SOURCE_COMPONENT='firstboot_final_readiness'
FIRSTBOOT_FINAL_READINESS_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_only'
FIRSTBOOT_FINAL_READINESS_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_TOTAL_ARTIFACTS='7'
FIRSTBOOT_FINAL_READINESS_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_only'
FIRSTBOOT_FINAL_READINESS_SAFE_DEFAULT='read-only final readiness helper; no live system state was changed'
SUMMARY

python3 -m py_compile firstboot_final_readiness_smoke.py
python3 firstboot_final_readiness_smoke.py \
    --input "$SUMMARY" \
    --format json \
    --output "$JSON_OUT" \
    --summary "$SIDE_OUT" \
    --require-pass
python3 firstboot_final_readiness_smoke.py \
    --input "$SUMMARY" \
    --format markdown \
    --output "$MD_OUT" \
    --require-pass

python3 - "$JSON_OUT" "$SIDE_OUT" "$MD_OUT" <<'PY'
import json
import pathlib
import sys

json_path, summary_path, markdown_path = map(pathlib.Path, sys.argv[1:])
report = json.loads(json_path.read_text(encoding='utf-8'))
summary = summary_path.read_text(encoding='utf-8')
markdown = markdown_path.read_text(encoding='utf-8')
assert report['ok'] is True
assert report['decision'] == 'approved'
assert report['release_gate'] == 'pass'
assert report['privacy_scope'] == 'aggregate_firstboot_final_readiness_smoke_only'
assert report['safe_default'].startswith('read-only')
assert 'FIRSTBOOT_FINAL_READINESS_SMOKE_OK=' in summary
assert 'FIRSTBOOT_FINAL_READINESS_SMOKE_RELEASE_GATE=' in summary
assert 'FIRSTBOOT_FINAL_READINESS_SMOKE_SAFE_DEFAULT=' in summary
assert 'raw packets' not in markdown.lower()
assert 'Rollback' in markdown
PY

BAD_SUMMARY="$TMPDIR/final_readiness_bad.summary.env"
cp "$SUMMARY" "$BAD_SUMMARY"
python3 - <<'PY' "$BAD_SUMMARY"
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
text = text.replace("FIRSTBOOT_FINAL_READINESS_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_only'", "FIRSTBOOT_FINAL_READINESS_PRIVACY_SCOPE='raw_environment'", 1)
path.write_text(text, encoding='utf-8')
PY

if python3 firstboot_final_readiness_smoke.py --input "$BAD_SUMMARY" --require-pass >/tmp/final_readiness_bad.out 2>&1; then
    echo 'expected malformed privacy scope to fail require-pass' >&2
    exit 1
fi

grep -q 'firstboot_final_readiness_smoke.py' build_custom_iso.sh
grep -q 'firstboot_final_readiness_smoke.py' firstboot_release_gate.service
grep -q 'final_readiness_smoke.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_smoke.py' docs/firstboot_final_readiness.md
grep -qi 'rollback' docs/firstboot_final_readiness.md
grep -q 'firstboot_final_readiness_smoke.py' CHANGELOG.md
grep -qi 'rollback' CHANGELOG.md

echo '[static-check] firstboot final readiness smoke gate passed'
