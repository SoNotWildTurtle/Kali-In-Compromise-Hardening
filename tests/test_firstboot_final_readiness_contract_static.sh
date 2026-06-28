#!/usr/bin/env bash
# MINC - Static coverage for the passive firstboot final readiness contract.
# Defensive validation only: checks documentation and handoff contract text.

set -euo pipefail

DOC="docs/firstboot_final_readiness_contract.md"

require_text() {
    local needle="$1"
    if ! grep -Fq -- "$needle" "$DOC"; then
        echo "Missing expected contract text: $needle" >&2
        exit 1
    fi
}

[[ -f "$DOC" ]] || { echo "Missing $DOC" >&2; exit 1; }

require_text "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_OK"
require_text "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_DECISION"
require_text "FIRSTBOOT_HANDOFF_ENV_POLICY_SMOKE_RELEASE_GATE"
require_text "aggregate_release_gate_handoff_env_policy_smoke_only"
require_text "read-only contract"
require_text "fail closed"
require_text "must not read raw packets"
require_text "Rollback"
require_text "--require-pass"

if grep -Eiq -- 'force-merge|bypass protections|emit.*raw packets|emit.*credentials' "$DOC"; then
    echo "Unsafe release or privacy wording found in $DOC" >&2
    exit 1
fi

echo "firstboot final readiness contract static coverage passed"
