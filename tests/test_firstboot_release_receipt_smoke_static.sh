#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release receipt smoke evidence.
# Defensive validation only; this test executes local helper logic with temp files.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/release_receipt_pass.summary.env"
DEFER_SUMMARY="$TMP_DIR/release_receipt_defer.summary.env"
JSON_OUT="$TMP_DIR/release_receipt_smoke.json"
MD_OUT="$TMP_DIR/release_receipt_smoke.md"
SUMMARY_OUT="$TMP_DIR/release_receipt_smoke.summary.env"

cat > "$PASS_SUMMARY" <<'EOF_SUMMARY'
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS="approved"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS="2"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE="aggregate_metadata_only"
EOF_SUMMARY

cat > "$DEFER_SUMMARY" <<'EOF_SUMMARY'
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS="deferred"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS="1"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE="aggregate_metadata_only"
EOF_SUMMARY

python3 firstboot_final_readiness_release_receipt_smoke.py \
    --input "$PASS_SUMMARY" \
    --output "$JSON_OUT" \
    --summary "$SUMMARY_OUT" \
    --require-pass

python3 firstboot_final_readiness_release_receipt_smoke.py \
    --input "$PASS_SUMMARY" \
    --output "$MD_OUT" \
    --format markdown

if python3 firstboot_final_readiness_release_receipt_smoke.py \
    --input "$DEFER_SUMMARY" \
    --output "$TMP_DIR/deferred.json" \
    --summary "$TMP_DIR/deferred.summary.env" \
    --require-pass; then
    echo "deferred release receipt smoke unexpectedly passed --require-pass" >&2
    exit 1
fi

python3 - "$JSON_OUT" "$SUMMARY_OUT" "$MD_OUT" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
markdown = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

assert payload["schema_version"] == "1.0"
assert payload["status"] == "pass"
assert payload["release_receipt_status"] == "approved"
assert payload["release_receipt_blockers"] == 0
assert payload["release_receipt_artifacts"] == 2
assert payload["privacy_scope"] == "aggregate_metadata_only"
assert payload["safe_automation_boundary"].startswith("passive_summary_validation_only")
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS="pass"' in summary
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE="aggregate_metadata_only"' in summary
assert "Firstboot Final Readiness Release Receipt Smoke" in markdown
assert "performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes" in markdown
assert "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback" in markdown
PY

grep -q 'firstboot_final_readiness_release_receipt_smoke.py' build_custom_iso.sh
grep -q 'final_readiness_release_receipt_smoke.json' firstboot_release_gate.service
grep -q 'final_readiness_release_receipt_smoke.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_release_receipt_smoke.py' docs/firstboot_final_readiness_release_receipt_smoke.md
grep -q 'It is intentionally passive and aggregate-only' docs/firstboot_final_readiness_release_receipt_smoke.md
grep -q 'release receipt smoke' changelog.d/firstboot_release_receipt_smoke.md

echo "firstboot release receipt smoke static checks passed"
