#!/usr/bin/env bash
# MINC - Static packaging check for policy evidence receipt gate.
# Defensive validation only: verifies the ISO build includes the read-only receipt tool.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from pathlib import Path

build = Path('build_custom_iso.sh').read_text(encoding='utf-8')
required = [
    '"host_vm_policy_evidence_bundle.py"',
    '"host_vm_policy_evidence_bundle_receipt.py"',
]
missing = [token for token in required if token not in build]
if missing:
    raise SystemExit('missing receipt packaging token(s): ' + ', '.join(missing))

if not Path('host_vm_policy_evidence_bundle_receipt.py').is_file():
    raise SystemExit('receipt utility is missing')
if not Path('tests/test_host_vm_policy_evidence_bundle_receipt_static.sh').is_file():
    raise SystemExit('receipt behavior test is missing')
print('policy evidence receipt packaging check passed')
PY
