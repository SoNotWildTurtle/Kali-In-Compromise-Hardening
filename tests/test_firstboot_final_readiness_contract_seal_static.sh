#!/usr/bin/env bash
# MINC - Static and behavior coverage for passive firstboot contract seal helper.
# Defensive validation only: verifies aggregate-only release-gate evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_contract_seal.py

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cat >"$TMPDIR/pass.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_OK='1'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_SOURCE_COMPONENT='firstboot_final_readiness_manifest_smoke'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_manifest_smoke_only'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_EXPECTED_ARTIFACTS='3'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_PRIVACY_SCOPE='aggregate_firstboot_contract_seal_only'
FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_SAFE_DEFAULT='read-only final readiness manifest smoke helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_contract_seal.py \
  --input "$TMPDIR/pass.summary.env" \
  --format json \
  --output "$TMPDIR/contract_seal.json" \
  --summary "$TMPDIR/contract_seal.summary.env" \
  --require-pass

grep -q '"component": "firstboot_final_readiness_contract_seal"' "$TMPDIR/contract_seal.json"
grep -q '"decision": "approved"' "$TMPDIR/contract_seal.json"
grep -q '"release_gate": "pass"' "$TMPDIR/contract_seal.json"
grep -q "FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_OK='1'" "$TMPDIR/contract_seal.summary.env"
grep -q "FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_RELEASE_GATE='pass'" "$TMPDIR/contract_seal.summary.env"

sed "s/aggregate_firstboot_contract_seal_only/raw_telemetry/" "$TMPDIR/pass.summary.env" >"$TMPDIR/fail.summary.env"
if python3 firstboot_final_readiness_contract_seal.py --input "$TMPDIR/fail.summary.env" --require-pass >"$TMPDIR/fail.out" 2>&1; then
    echo 'privacy-scope mismatch unexpectedly passed' >&2
    exit 1
fi
grep -q 'release_gate=stop' "$TMPDIR/fail.out"

python3 firstboot_final_readiness_contract_seal.py --input "$TMPDIR/pass.summary.env" --format markdown --output "$TMPDIR/contract_seal.md"
grep -q 'Firstboot final readiness contract seal' "$TMPDIR/contract_seal.md"
grep -q 'Rollback' "$TMPDIR/contract_seal.md"

grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_contract_seal.md
grep -q 'must not source shell content' docs/firstboot_final_readiness_contract_seal.md
grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_' docs/firstboot_final_readiness_contract_seal.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_contract_seal.md
grep -q 'NIST SP 800-53 Rev. 5' docs/firstboot_final_readiness_contract_seal.md
