#!/usr/bin/env bash
# MINC - Static tests for passive firstboot handoff release gate.
# Defensive validation only: builds synthetic aggregate evidence and never changes live host or VM state.

set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

VALIDATOR_EVIDENCE="$TMP_DIR/host_vm_policy_validator_evidence.json"
MANIFEST="$TMP_DIR/host_vm_policy_firstboot_manifest.json"
HANDOFF="$TMP_DIR/host_vm_policy_firstboot_handoff.json"
OUTPUT="$TMP_DIR/gate-output.json"
REPORT="$TMP_DIR/gate.report"

printf '{"valid": true, "policy_id": "default_firstboot_review"}\n' > "$VALIDATOR_EVIDENCE"
printf '{"firstboot_dry_run": {"passive_only": true}}\n' > "$MANIFEST"

cat > "$HANDOFF" <<JSON
{
  "handoff_schema_version": 1,
  "wrapper": "host_vm_policy_firstboot_dry_run.py",
  "wrapper_version": "1.0.0",
  "validation": {
    "valid": true,
    "error_count": 0,
    "errors": []
  },
  "generated_artifacts": {
    "validator_evidence_json": "$VALIDATOR_EVIDENCE",
    "firstboot_manifest_json": "$MANIFEST"
  },
  "safety": {
    "passive_only": true,
    "mutates_host_or_vm_state": false,
    "collects_credentials_or_secrets": false,
    "enables_persistence_or_remote_access": false
  },
  "privacy_boundaries": {
    "contains_raw_telemetry": false,
    "contains_secret_material": false,
    "forbidden_handoff_keys": [
      "raw_logs",
      "packets",
      "captures",
      "credentials",
      "hostnames",
      "usernames",
      "secrets",
      "model_binaries",
      "datasets",
      "private_keys",
      "tokens"
    ]
  },
  "rollback": {
    "live_state_rollback_required": false
  }
}
JSON

python3 host_vm_policy_firstboot_handoff_gate.py "$HANDOFF" --strict --output "$OUTPUT" --report "$REPORT"
python3 - <<PY
import json
from pathlib import Path
result = json.loads(Path("$OUTPUT").read_text(encoding="utf-8"))
assert result["decision"] == "release_ready"
assert result["changes_live_state"] is False
assert result["reads_raw_telemetry"] is False
assert result["checks_failed"] == 0
PY

grep -q '^decision=release_ready$' "$REPORT"

BROKEN="$TMP_DIR/broken_handoff.json"
python3 - <<PY
import json
from pathlib import Path
handoff = json.loads(Path("$HANDOFF").read_text(encoding="utf-8"))
handoff["safety"]["mutates_host_or_vm_state"] = True
Path("$BROKEN").write_text(json.dumps(handoff), encoding="utf-8")
PY

if python3 host_vm_policy_firstboot_handoff_gate.py "$BROKEN" --strict --output "$TMP_DIR/broken-output.json"; then
    echo "expected strict gate to reject mutating handoff" >&2
    exit 1
fi

grep -q 'release_blocked' "$TMP_DIR/broken-output.json"

echo "firstboot handoff gate static checks passed"
