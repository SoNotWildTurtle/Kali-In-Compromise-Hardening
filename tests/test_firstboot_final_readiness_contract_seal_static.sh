#!/usr/bin/env bash
# MINC - Static coverage for passive firstboot contract seal helper.
# Defensive validation only: verifies aggregate-only release-gate evidence without changing system state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile firstboot_final_readiness_contract_seal.py

grep -q 'FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_' firstboot_final_readiness_contract_seal.py
grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL' firstboot_final_readiness_contract_seal.py
grep -q 'aggregate_firstboot_final_readiness_manifest_smoke_only' firstboot_final_readiness_contract_seal.py
grep -q 'aggregate_firstboot_final_readiness_contract_seal_only' firstboot_final_readiness_contract_seal.py
grep -q 'read-only final readiness contract seal helper' firstboot_final_readiness_contract_seal.py
grep -q 'return 10' firstboot_final_readiness_contract_seal.py

grep -q 'read-only and aggregate-only' docs/firstboot_final_readiness_contract_seal.md
grep -q 'must not source shell content' docs/firstboot_final_readiness_contract_seal.md
grep -q 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_' docs/firstboot_final_readiness_contract_seal.md
grep -q 'Rollback is removal' docs/firstboot_final_readiness_contract_seal.md
grep -q 'NIST SP 800-53 Rev. 5' docs/firstboot_final_readiness_contract_seal.md
