#!/usr/bin/env bash
# MINC - Static coverage for passive firstboot operator bundle helper.
# Defensive validation only: verifies aggregate-only handoff bundle evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_operator_bundle.py

grep -q '"firstboot_final_readiness_operator_bundle.py"' build_custom_iso.sh
grep -q 'firstboot_final_readiness_operator_bundle.py --input /var/log/firstboot_release_gate.final_readiness_operator_verdict.summary.env' firstboot_release_gate.service

grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_' firstboot_final_readiness_operator_bundle.py
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE' firstboot_final_readiness_operator_bundle.py
grep -q 'aggregate_firstboot_final_readiness_operator_verdict_only' firstboot_final_readiness_operator_bundle.py
grep -q 'aggregate_firstboot_final_readiness_operator_bundle_only' firstboot_final_readiness_operator_bundle.py
grep -q 'read-only final readiness operator bundle helper' firstboot_final_readiness_operator_bundle.py
grep -q 'return 10' firstboot_final_readiness_operator_bundle.py

grep -q 'operator bundle' docs/firstboot_final_readiness_operator_bundle.md
grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_operator_bundle.md
grep -q 'does not source shell content' docs/firstboot_final_readiness_operator_bundle.md
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_' docs/firstboot_final_readiness_operator_bundle.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_operator_bundle.md
grep -q 'NIST Cybersecurity Framework 2.0' docs/firstboot_final_readiness_operator_bundle.md

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/operator_verdict.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_OK='1'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT='promote'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_COMPONENT='firstboot_final_readiness_operator_verdict'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_contract_seal_smoke_only'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_EXPECTED_ARTIFACTS='3'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_operator_verdict_only'
FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_SAFE_DEFAULT='read-only final readiness operator verdict helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_operator_bundle.py \
    --input "$tmpdir/operator_verdict.summary.env" \
    --format json \
    --output "$tmpdir/operator_bundle.json" \
    --summary "$tmpdir/operator_bundle.summary.env" \
    --require-pass

python3 firstboot_final_readiness_operator_bundle.py \
    --input "$tmpdir/operator_verdict.summary.env" \
    --format markdown \
    --output "$tmpdir/operator_bundle.md" \
    --require-pass

grep -q '"bundle_verdict": "ready"' "$tmpdir/operator_bundle.json"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_OK='1'" "$tmpdir/operator_bundle.summary.env"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_VERDICT='ready'" "$tmpdir/operator_bundle.summary.env"
grep -q 'Bundle verdict: `ready`' "$tmpdir/operator_bundle.md"
grep -q 'Privacy scope: `aggregate_firstboot_final_readiness_operator_bundle_only`' "$tmpdir/operator_bundle.md"
grep -q 'firstboot_final_readiness_operator_verdict' "$tmpdir/operator_bundle.md"

sed "s/FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT='promote'/FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT='hold'/" "$tmpdir/operator_verdict.summary.env" > "$tmpdir/bad_verdict.summary.env"
if python3 firstboot_final_readiness_operator_bundle.py --input "$tmpdir/bad_verdict.summary.env" --require-pass; then
    echo 'operator bundle should fail closed when upstream verdict is not promote' >&2
    exit 1
fi
