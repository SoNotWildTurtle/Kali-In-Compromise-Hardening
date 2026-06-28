#!/usr/bin/env bash
# MINC - Static checks for passive firstboot final-readiness manifest helper.
# Defensive validation only; does not touch live host or VM state.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m py_compile firstboot_final_readiness_manifest.py

sample_dir="$(mktemp -d)"
trap 'rm -rf "$sample_dir"' EXIT

cat > "$sample_dir/final_readiness_smoke.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_SMOKE_OK='1'
FIRSTBOOT_FINAL_READINESS_SMOKE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_SMOKE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_COMPONENT='firstboot_final_readiness_smoke'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_smoke_only'
FIRSTBOOT_FINAL_READINESS_SMOKE_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_SMOKE_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_SMOKE_TOTAL_ARTIFACTS='9'
FIRSTBOOT_FINAL_READINESS_SMOKE_PRIVACY_SCOPE='aggregate_firstboot_final_readiness_smoke_only'
FIRSTBOOT_FINAL_READINESS_SMOKE_SAFE_DEFAULT='read-only final readiness smoke helper; no live system state was changed'
ENV

python3 firstboot_final_readiness_manifest.py \
    --input "$sample_dir/final_readiness_smoke.summary.env" \
    --format json \
    --output "$sample_dir/manifest.json" \
    --summary "$sample_dir/manifest.summary.env" \
    --require-pass

python3 firstboot_final_readiness_manifest.py \
    --input "$sample_dir/final_readiness_smoke.summary.env" \
    --format markdown \
    --output "$sample_dir/manifest.md" \
    --require-pass

grep -q '"component": "firstboot_final_readiness_manifest"' "$sample_dir/manifest.json"
grep -q '"decision": "approved"' "$sample_dir/manifest.json"
grep -q '"release_gate": "pass"' "$sample_dir/manifest.json"
grep -q 'aggregate_firstboot_final_readiness_manifest_only' "$sample_dir/manifest.json"
grep -q 'read-only final readiness manifest helper' "$sample_dir/manifest.json"
grep -q '/var/log/firstboot_release_gate.final_readiness_smoke.summary.env' "$sample_dir/manifest.json"
grep -q '^FIRSTBOOT_FINAL_READINESS_MANIFEST_OK=' "$sample_dir/manifest.summary.env"
grep -q '^FIRSTBOOT_FINAL_READINESS_MANIFEST_RELEASE_GATE=' "$sample_dir/manifest.summary.env"
grep -q '# Firstboot final readiness manifest' "$sample_dir/manifest.md"
grep -q '## Rollback' "$sample_dir/manifest.md"

grep -q 'firstboot_final_readiness_manifest.py' build_custom_iso.sh
grep -q 'firstboot_release_gate.final_readiness_manifest.json' firstboot_release_gate.service
grep -q 'firstboot_release_gate.final_readiness_manifest.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_manifest.py' docs/firstboot_final_readiness.md
grep -q 'rollback for the manifest helper' docs/firstboot_final_readiness.md
grep -q 'firstboot_final_readiness_manifest.py' CHANGELOG.md

cat > "$sample_dir/bad_privacy.summary.env" <<'ENV'
FIRSTBOOT_FINAL_READINESS_SMOKE_OK='1'
FIRSTBOOT_FINAL_READINESS_SMOKE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_SMOKE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_COMPONENT='firstboot_final_readiness_smoke'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_DECISION='approved'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_RELEASE_GATE='pass'
FIRSTBOOT_FINAL_READINESS_SMOKE_SOURCE_PRIVACY_SCOPE='raw_telemetry'
FIRSTBOOT_FINAL_READINESS_SMOKE_BLOCKER_COUNT='0'
FIRSTBOOT_FINAL_READINESS_SMOKE_BLOCKERS='none'
FIRSTBOOT_FINAL_READINESS_SMOKE_TOTAL_ARTIFACTS='9'
FIRSTBOOT_FINAL_READINESS_SMOKE_PRIVACY_SCOPE='raw_telemetry'
FIRSTBOOT_FINAL_READINESS_SMOKE_SAFE_DEFAULT='read-only final readiness smoke helper; no live system state was changed'
ENV

if python3 firstboot_final_readiness_manifest.py \
    --input "$sample_dir/bad_privacy.summary.env" \
    --format json \
    --output "$sample_dir/bad_privacy.json" \
    --require-pass; then
    echo "privacy-mismatched summary unexpectedly passed" >&2
    exit 1
fi

grep -q 'source_privacy_scope_mismatch:raw_telemetry' "$sample_dir/bad_privacy.json"
grep -q 'privacy_scope_mismatch:raw_telemetry' "$sample_dir/bad_privacy.json"
