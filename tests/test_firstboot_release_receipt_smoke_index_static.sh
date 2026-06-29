#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release receipt smoke index evidence.
# Defensive validation only; this test executes local helper logic with temp files.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/release_receipt_smoke_pass.summary.env"
DEFER_SUMMARY="$TMP_DIR/release_receipt_smoke_defer.summary.env"
JSON_OUT="$TMP_DIR/release_receipt_smoke_index.json"
MD_OUT="$TMP_DIR/release_receipt_smoke_index.md"
SUMMARY_OUT="$TMP_DIR/release_receipt_smoke_index.summary.env"

cat > "$PASS_SUMMARY" <<'EOF_SUMMARY'
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS="pass"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE="aggregate_metadata_only"
EOF_SUMMARY

cat > "$DEFER_SUMMARY" <<'EOF_SUMMARY'
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS="review"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS="1"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS="0"
FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE="aggregate_metadata_only"
EOF_SUMMARY

python3 firstboot_final_readiness_release_receipt_smoke_index.py \
    --input "$PASS_SUMMARY" \
    --output "$JSON_OUT" \
    --summary "$SUMMARY_OUT" \
    --require-pass

python3 firstboot_final_readiness_release_receipt_smoke_index.py \
    --input "$PASS_SUMMARY" \
    --output "$MD_OUT" \
    --format markdown

if python3 firstboot_final_readiness_release_receipt_smoke_index.py \
    --input "$DEFER_SUMMARY" \
    --output "$TMP_DIR/deferred.json" \
    --summary "$TMP_DIR/deferred.summary.env" \
    --require-pass; then
    echo "deferred release receipt smoke index unexpectedly passed --require-pass" >&2
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
assert payload["release_receipt_smoke_status"] == "pass"
assert payload["release_receipt_smoke_blockers"] == 0
assert payload["privacy_scope"] == "aggregate_metadata_only"
assert len(payload["indexed_artifacts"]) == 3
assert payload["safe_automation_boundary"].startswith("passive_smoke_index_only")
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_STATUS="pass"' in summary
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_ARTIFACTS="3"' in summary
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_PRIVACY_SCOPE="aggregate_metadata_only"' in summary
assert "Firstboot Final Readiness Release Receipt Smoke Index" in markdown
assert "performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes" in markdown
assert "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback" in markdown
PY

grep -q 'firstboot_final_readiness_release_receipt_smoke_index.py' build_custom_iso.sh
grep -q 'final_readiness_release_receipt_smoke_index.json' firstboot_release_gate.service
grep -q 'final_readiness_release_receipt_smoke_index.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_release_receipt_smoke_index.py' docs/firstboot_final_readiness_release_receipt_smoke_index.md
grep -q 'It is intentionally passive and aggregate-only' docs/firstboot_final_readiness_release_receipt_smoke_index.md
grep -q 'release receipt smoke index' changelog.d/firstboot_release_receipt_smoke_index.md

echo "firstboot release receipt smoke index static checks passed"
