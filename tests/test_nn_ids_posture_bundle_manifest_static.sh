#!/usr/bin/env bash
set -euo pipefail

SCRIPT="nn_ids_posture_bundle_manifest.py"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"

cat >"${TMP_DIR}/health.json" <<'JSON'
{
  "component": "nn_ids",
  "generated_at": "2026-06-26T00:00:00+00:00",
  "status": "pass",
  "ok": true,
  "failing_controls": [],
  "warning_controls": []
}
JSON

cat >"${TMP_DIR}/drift.json" <<'JSON'
{
  "component": "nn_ids_drift",
  "generated_at": "2026-06-26T00:00:01+00:00",
  "status": "warn",
  "ok": false,
  "failing_controls": [],
  "warning_controls": ["nn_ids.drift.ttl"]
}
JSON

cat >"${TMP_DIR}/triage.json" <<'JSON'
{
  "component": "nn_ids_drift_triage",
  "generated_at": "2026-06-26T00:00:02+00:00",
  "status": "warn",
  "ok": false,
  "recommended_actions": ["Track ttl in the next health window."]
}
JSON

python3 "${SCRIPT}" \
  --health-evidence "${TMP_DIR}/health.json" \
  --drift-evidence "${TMP_DIR}/drift.json" \
  --drift-triage "${TMP_DIR}/triage.json" \
  --output "${TMP_DIR}/manifest.json"

python3 - "${TMP_DIR}/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert manifest["component"] == "nn_ids_posture_bundle_manifest"
assert manifest["schema_version"] == 1
assert manifest["status"] == "warn"
assert manifest["summary"]["present_artifacts"] == 3
assert manifest["summary"]["missing_artifacts"] == []
assert manifest["summary"]["stale_artifacts"] == []
assert manifest["summary"]["warning_controls"] == ["nn_ids.drift.ttl"]
assert manifest["release_gate"]["promotion_warnings"] == ["nn_ids.drift.ttl"]
assert manifest["release_gate"]["freshness_policy"]["enforced"] is False
assert "packets" in manifest["privacy_note"]
assert "Delete the generated manifest" in manifest["rollback"]
assert all(entry["sha256"] for entry in manifest["artifacts"])
PY

python3 "${SCRIPT}" \
  --health-evidence "${TMP_DIR}/health.json" \
  --drift-evidence "${TMP_DIR}/drift.json" \
  --drift-triage "${TMP_DIR}/triage.json" \
  --format markdown \
  --output "${TMP_DIR}/handoff.md"

grep -q '^# NN IDS posture bundle handoff' "${TMP_DIR}/handoff.md"
grep -q 'Freshness window: `not enforced`' "${TMP_DIR}/handoff.md"
grep -q '| health_evidence | `pass` | `not_enforced` |' "${TMP_DIR}/handoff.md"
grep -q '`nn_ids.drift.ttl`' "${TMP_DIR}/handoff.md"
grep -q 'Privacy: The manifest does not embed packets' "${TMP_DIR}/handoff.md"
grep -q 'Rollback: Delete the generated manifest' "${TMP_DIR}/handoff.md"

if python3 "${SCRIPT}" \
  --health-evidence "${TMP_DIR}/health.json" \
  --drift-evidence "${TMP_DIR}/missing.json" \
  --drift-triage "${TMP_DIR}/triage.json" \
  --output - \
  --require-pass >"${TMP_DIR}/nn_ids_posture_missing.json"; then
  echo "expected --require-pass to fail when an artifact is missing" >&2
  exit 1
fi

python3 - "${TMP_DIR}/nn_ids_posture_missing.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert manifest["status"] == "fail"
assert "drift_evidence" in manifest["summary"]["missing_artifacts"]
assert "nn_ids.posture_bundle.drift_evidence.present" in manifest["release_gate"]["promotion_blockers"]
PY
