#!/usr/bin/env bash
# MINC - Static coverage for passive firstboot operator bundle smoke helper.
# Defensive validation only: verifies aggregate-only smoke evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_operator_bundle_smoke.py

grep -q '"firstboot_final_readiness_operator_bundle_smoke.py"' build_custom_iso.sh
grep -q 'firstboot_final_readiness_operator_bundle_smoke.py --input /var/log/firstboot_release_gate.final_readiness_operator_bundle.summary.env' firstboot_release_gate.service

grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_' firstboot_final_readiness_operator_bundle_smoke.py
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE' firstboot_final_readiness_operator_bundle_smoke.py
grep -q 'aggregate_firstboot_final_readiness_operator_bundle_only' firstboot_final_readiness_operator_bundle_smoke.py
grep -q 'aggregate_firstboot_final_readiness_operator_bundle_smoke_only' firstboot_final_readiness_operator_bundle_smoke.py
grep -q 'read-only final readiness operator bundle smoke helper' firstboot_final_readiness_operator_bundle_smoke.py
grep -q 'return 10' firstboot_final_readiness_operator_bundle_smoke.py

grep -q 'operator bundle smoke' docs/firstboot_final_readiness_operator_bundle_smoke.md
grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_operator_bundle_smoke.md
grep -q 'does not source shell content' docs/firstboot_final_readiness_operator_bundle_smoke.md
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_' docs/firstboot_final_readiness_operator_bundle_smoke.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_operator_bundle_smoke.md

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/operator_bundle.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_OK='1'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT='ready'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_COMPONENT='firstboot_final_readiness_operator_verdict'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_operator_verdict_only'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_EXPECTED_ARTIFACTS='3'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_operator_bundle_only'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SAFE_DEFAULT='read-only final readiness operator bundle helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_operator_bundle_smoke.py \
    --input "$tmpdir/operator_bundle.summary.env" \
    --format json \
    --output "$tmpdir/operator_bundle_smoke.json" \
    --summary "$tmpdir/operator_bundle_smoke.summary.env" \
    --require-pass

python3 firstboot_final_readiness_operator_bundle_smoke.py \
    --input "$tmpdir/operator_bundle.summary.env" \
    --format markdown \
    --output "$tmpdir/operator_bundle_smoke.md" \
    --require-pass

grep -q '"smoke_verdict": "pass"' "$tmpdir/operator_bundle_smoke.json"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_OK='1'" "$tmpdir/operator_bundle_smoke.summary.env"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_VERDICT='pass'" "$tmpdir/operator_bundle_smoke.summary.env"
grep -q 'Smoke verdict: `pass`' "$tmpdir/operator_bundle_smoke.md"
grep -q 'Privacy scope: `aggregate_firstboot_final_readiness_operator_bundle_smoke_only`' "$tmpdir/operator_bundle_smoke.md"
grep -q 'firstboot_final_readiness_operator_bundle' "$tmpdir/operator_bundle_smoke.md"

sed "s/FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT='ready'/FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT='hold'/" "$tmpdir/operator_bundle.summary.env" > "$tmpdir/bad_bundle.summary.env"
if python3 firstboot_final_readiness_operator_bundle_smoke.py --input "$tmpdir/bad_bundle.summary.env" --require-pass; then
    echo 'operator bundle smoke should fail closed when upstream bundle is not ready' >&2
    exit 1
fi
