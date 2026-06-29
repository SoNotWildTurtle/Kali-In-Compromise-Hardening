#!/usr/bin/env bash
# MINC - Static coverage for passive firstboot contract seal smoke helper.
# Defensive validation only: verifies aggregate-only release-gate evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_contract_seal.py
python3 -m py_compile firstboot_final_readiness_contract_seal_smoke.py

grep -q '"firstboot_final_readiness_contract_seal.py"' build_custom_iso.sh
grep -q '"firstboot_final_readiness_contract_seal_smoke.py"' build_custom_iso.sh
grep -q 'firstboot_final_readiness_contract_seal.py --input /var/log/firstboot_release_gate.final_readiness_manifest_smoke.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_contract_seal_smoke.py --input /var/log/firstboot_release_gate.final_readiness_contract_seal.summary.env' firstboot_release_gate.service

grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_' firstboot_final_readiness_contract_seal_smoke.py
grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE' firstboot_final_readiness_contract_seal_smoke.py
grep -q 'aggregate_firstboot_final_readiness_contract_seal_only' firstboot_final_readiness_contract_seal_smoke.py
grep -q 'aggregate_firstboot_final_readiness_contract_seal_smoke_only' firstboot_final_readiness_contract_seal_smoke.py
grep -q 'read-only final readiness contract seal smoke helper' firstboot_final_readiness_contract_seal_smoke.py
grep -q 'return 10' firstboot_final_readiness_contract_seal_smoke.py

grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_contract_seal.md
grep -q 'does not source shell content' docs/firstboot_final_readiness_contract_seal.md
grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_' docs/firstboot_final_readiness_contract_seal.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_contract_seal.md
grep -q 'NIST SP 800-53 Rev. 5' docs/firstboot_final_readiness_contract_seal.md

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/contract_seal.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_OK='1'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SOURCE_COMPONENT='firstboot_final_readiness_contract_seal'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_contract_seal_only'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_EXPECTED_ARTIFACTS='3'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_contract_seal_only'
FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SAFE_DEFAULT='read-only final readiness contract seal helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_contract_seal_smoke.py \
    --input "$tmpdir/contract_seal.summary.env" \
    --format json \
    --output "$tmpdir/contract_seal_smoke.json" \
    --summary "$tmpdir/contract_seal_smoke.summary.env" \
    --require-pass

grep -q '"decision": "approved"' "$tmpdir/contract_seal_smoke.json"
grep -q "FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_SMOKE_OK='1'" "$tmpdir/contract_seal_smoke.summary.env"

sed "s/aggregate_firstboot_final_readiness_contract_seal_only/raw_packet_scope/" "$tmpdir/contract_seal.summary.env" > "$tmpdir/bad_scope.summary.env"
if python3 firstboot_final_readiness_contract_seal_smoke.py --input "$tmpdir/bad_scope.summary.env" --require-pass; then
    echo 'contract seal smoke should fail closed on privacy-scope mismatch' >&2
    exit 1
fi
