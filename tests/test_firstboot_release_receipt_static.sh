#!/usr/bin/env bash
# MINC - Static tests for passive firstboot release receipt evidence.
# Defensive validation only; this test executes local helper logic with temp files.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

INDEX_PASS="$TMP_DIR/operator_bundle_index_pass.json"
INDEX_DEFER="$TMP_DIR/operator_bundle_index_defer.json"
JSON_OUT="$TMP_DIR/release_receipt.json"
MD_OUT="$TMP_DIR/release_receipt.md"
SUMMARY_OUT="$TMP_DIR/release_receipt.summary.env"

cat > "$INDEX_PASS" <<'JSON'
{
  "schema_version": "1.0",
  "status": "pass",
  "upstream_smoke_status": "pass",
  "missing_artifacts": [],
  "zero_byte_artifacts": [],
  "artifacts": [
    {"path": "/var/log/firstboot_release_gate.json", "present": true, "size_bytes": 42, "modified_utc": "2026-06-29T00:00:00Z"},
    {"path": "/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.json", "present": true, "size_bytes": 99, "modified_utc": "2026-06-29T00:00:00Z"}
  ]
}
JSON

cat > "$INDEX_DEFER" <<'JSON'
{
  "schema_version": "1.0",
  "status": "review",
  "upstream_smoke_status": "pass",
  "missing_artifacts": ["/var/log/missing.json"],
  "zero_byte_artifacts": [],
  "artifacts": [
    {"path": "/var/log/missing.json", "present": false, "size_bytes": 0, "modified_utc": null}
  ]
}
JSON

python3 firstboot_final_readiness_release_receipt.py \
    --input "$INDEX_PASS" \
    --output "$JSON_OUT" \
    --summary "$SUMMARY_OUT"

python3 firstboot_final_readiness_release_receipt.py \
    --input "$INDEX_PASS" \
    --output "$MD_OUT" \
    --format markdown \
    --require-approved

if python3 firstboot_final_readiness_release_receipt.py \
    --input "$INDEX_DEFER" \
    --output "$TMP_DIR/deferred.json" \
    --summary "$TMP_DIR/deferred.summary.env" \
    --require-approved; then
    echo "deferred receipt unexpectedly passed --require-approved" >&2
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
assert payload["status"] == "approved"
assert payload["operator_bundle_index_status"] == "pass"
assert payload["operator_bundle_smoke_status"] == "pass"
assert payload["artifact_counts"]["missing"] == 0
assert payload["privacy_scope"] == "aggregate_metadata_only"
assert payload["safe_automation_boundary"].startswith("passive_review_only")
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS="approved"' in summary
assert 'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE="aggregate_metadata_only"' in summary
assert "Firstboot Final Readiness Release Receipt" in markdown
assert "performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes" in markdown
assert "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback" in markdown
PY

grep -q 'firstboot_final_readiness_release_receipt.py' build_custom_iso.sh
grep -q 'final_readiness_release_receipt.json' firstboot_release_gate.service
grep -q 'final_readiness_release_receipt.summary.env' firstboot_release_gate.service
grep -q 'firstboot_final_readiness_release_receipt.md' docs/firstboot_final_readiness_release_receipt.md
grep -q 'release receipt helper is additive and passive' CHANGELOG.md

echo "firstboot release receipt static checks passed"
