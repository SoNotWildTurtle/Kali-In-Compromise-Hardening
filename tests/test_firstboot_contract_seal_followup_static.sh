#!/usr/bin/env bash
# MINC - Static coverage for the firstboot contract seal follow-up note.
# Defensive validation only: verifies the proposal stays passive, reversible, and aggregate-only.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_text() {
    local token="$1"
    local file="$2"
    grep -q "$token" "$file" || {
        echo "missing expected token '$token' in $file" >&2
        exit 1
    }
}

require_text 'FIRSTBOOT_FINAL_READINESS_MANIFEST_SMOKE_' docs/firstboot_contract_seal_followup.md
require_text 'FIRSTBOOT_FINAL_READINESS_CONTRACT_SEAL_' docs/firstboot_contract_seal_followup.md
require_text 'read-only and aggregate-only' docs/firstboot_contract_seal_followup.md
require_text 'must not source shell content' docs/firstboot_contract_seal_followup.md
require_text 'Rollback is removal' docs/firstboot_contract_seal_followup.md
require_text 'deferred/stop' docs/firstboot_contract_seal_followup.md
