#!/usr/bin/env bash
# MINC - Static tests for passive firstboot operator bundle index evidence.
# Defensive validation only; this test executes local helper logic with temp files.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SUMMARY_FILE="$TMP_DIR/operator_bundle_smoke.summary.env"
JSON_OUT="$TMP_DIR/operator_bundle_index.json"
MD_OUT="$TMP_DIR/operator_bundle_index.md"
SUMMARY_OUT="$TMP_DIR/operator_bundle_index.summary.env"
ARTIFACT_ONE="$TMP_DIR/firstboot_release_gate.json"
ARTIFACT_TWO="$TMP_DIR/firstboot_release_gate.final_readiness_operator_bundle_smoke.json"

cat > "$SUMMARY_FILE" <<'ENV'
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_STATUS="pass"
FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_REASON="static test input"
ENV

printf '{"ok": true}\n' > "$ARTIFACT_ONE"
printf '{"smoke": "pass"}\n' > "$ARTIFACT_TWO"

python3 firstboot_final_readiness_operator_bundle_index.py \
    --input "$SUMMARY_FILE" \
    --output "$JSON_OUT" \
    --summary "$SUMMARY_OUT" \
    --artifact "$ARTIFACT_ONE" \
    --artifact "$ARTIFACT_TWO"

python3 firstboot_final_readiness_operator_bundle_index.py \
    --input "$SUMMARY_FILE" \
    --output "$MD_OUT" \
    --format markdown \
    --artifact "$ARTIFACT_ONE" \
    --artifact "$ARTIFACT_TWO"

python3 - "$JSON_OUT" "$SUMMARY_OUT" "$MD_OUT" "$ARTIFACT_ONE" "$ARTIFACT_TWO" <<'PY'
import json
import pathlib
import sys

json_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
markdown_path = pathlib.Path(sys.argv[3])
artifact_one = sys.argv[4]
artifact_two = sys.argv[5]

payload = json.loads(json_path.read_text(encoding="utf-8"))
summary = summary_path.read_text(encoding="utf-8")
markdown = markdown_path.read_text(encoding="utf-8")

assert payload["schema_version"] == "1.0"
assert payload["upstream_smoke_status"] == "pass"
assert payload["status"] == "review"  # default /var/log artifacts are absent during static tests
assert artifact_one in [item["path"] for item in payload["artifacts"]]
assert artifact_two in [item["path"] for item in payload["artifacts"]]
assert 'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_INDEX_STATUS="review"' in summary
assert "Firstboot Final Readiness Operator Bundle Index" in markdown
assert "performs no policy, firewall, service, or network changes" in markdown
PY

grep -q 'firstboot_final_readiness_operator_bundle_index.py' build_custom_iso.sh
grep -q 'final_readiness_operator_bundle_index.json' firstboot_release_gate.service
grep -q 'final_readiness_operator_bundle_index.summary.env' firstboot_release_gate.service

echo "firstboot operator bundle index static checks passed"
