#!/usr/bin/env bash
# MINC - Static coverage for passive firstboot operator verdict helper.
# Defensive validation only: verifies aggregate-only release-gate evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_operator_verdict.py

grep -q '"firstboot_final_readiness_operator_verdict.py"' build_custom_iso.sh
grep -q 'firstboot_final_readiness_operator_verdict.py --input /var/log/firstboot_release_gate.final_readiness_contract_seal_smoke.summary.env' firstboot_release_gate.service

grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_' firstboot_final_readiness_operator_verdict.py
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT' firstboot_final_readiness_operator_verdict.py
grep -q 'aggregate_firstboot_final_readiness_contract_seal_smoke_only' firstboot_final_readiness_operator_verdict.py
grep -q 'aggregate_firstboot_final_readiness_operator_verdict_only' firstboot_final_readiness_operator_verdict.py
grep -q 'read-only final readiness operator verdict helper' firstboot_final_readiness_operator_verdict.py
grep -q 'return 10' firstboot_final_readiness_operator_verdict.py

grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_contract_seal.md
grep -q 'does not source shell content' docs/firstboot_final_readiness_contract_seal.md
grep -q 'FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_' docs/firstboot_final_readiness_contract_seal.md
grep -q 'operator verdict' docs/firstboot_final_readiness_contract_seal.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_contract_seal.md
grep -q 'NIST SP 800-53 Rev. 5' docs/firstboot_final_readiness_contract_seal.md

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/contract_seal_smoke.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_OK='1'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_SOURCE_COMPONENT='firstboot_final_readiness_contract_seal_smoke'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_contract_seal_smoke_only'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_EXPECTED_ARTIFACTS='3'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_contract_seal_smoke_only'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_SAFE_DEFAULT='read-only final readiness contract seal smoke helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_operator_verdict.py \
    --input "$tmpdir/contract_seal_smoke.summary.env" \
    --format json \
    --output "$tmpdir/operator_verdict.json" \
    --summary "$tmpdir/operator_verdict.summary.env" \
    --require-pass

python3 firstboot_final_readiness_operator_verdict.py \
    --input "$tmpdir/contract_seal_smoke.summary.env" \
    --format markdown \
    --output "$tmpdir/operator_verdict.md" \
    --require-pass

grep -q '"operator_verdict": "promote"' "$tmpdir/operator_verdict.json"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_OK='1'" "$tmpdir/operator_verdict.summary.env"
grep -q "FIRSTBOOT_FINAL_READINESS_OPERATOR_VERDICT_VERDICT='promote'" "$tmpdir/operator_verdict.summary.env"
grep -q 'Operator verdict: `promote`' "$tmpdir/operator_verdict.md"
grep -q 'Privacy scope: `aggregate_firstboot_final_readiness_operator_verdict_only`' "$tmpdir/operator_verdict.md"

sed "s/aggregate_firstboot_final_readiness_contract_seal_smoke_only/raw_packet_scope/" "$tmpdir/contract_seal_smoke.summary.env" > "$tmpdir/bad_scope.summary.env"
if python3 firstboot_final_readiness_operator_verdict.py --input "$tmpdir/bad_scope.summary.env" --require-pass; then
    echo 'operator verdict should fail closed on privacy-scope mismatch' >&2
    exit 1
fi
