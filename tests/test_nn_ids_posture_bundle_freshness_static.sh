#!/usr/bin/env bash
set -euo pipefail

SCRIPT="nn_ids_posture_bundle_manifest.py"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"

cat >"${TMP_DIR}/health.json" <<'JSON'
{
  "component": "nn_ids",
  "generated_at": "1970-01-01T00:00:00Z",
  "status": "pass",
  "ok": true,
  "failing_controls": [],
  "warning_controls": []
}
JSON

cat >"${TMP_DIR}/drift.json" <<'JSON'
{
  "component": "nn_ids_drift",
  "generated_at": "1970-01-01T00:00:01Z",
  "status": "pass",
  "ok": true,
  "failing_controls": [],
  "warning_controls": []
}
JSON

cat >"${TMP_DIR}/triage.json" <<'JSON'
{
  "component": "nn_ids_drift_triage",
  "generated_at": "1970-01-01T00:00:02Z",
  "status": "pass",
  "ok": true
}
JSON

if python3 "${SCRIPT}" \
  --health-evidence "${TMP_DIR}/health.json" \
  --drift-evidence "${TMP_DIR}/drift.json" \
  --drift-triage "${TMP_DIR}/triage.json" \
  --max-artifact-age-minutes 60 \
  --require-pass \
  --output "${TMP_DIR}/manifest.json"; then
  echo "expected stale posture evidence to fail the freshness gate" >&2
  exit 1
fi

python3 - "${TMP_DIR}/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert manifest["status"] == "fail"
assert manifest["release_gate"]["freshness_policy"] == {
    "enforced": True,
    "max_artifact_age_minutes": 60.0,
}
assert sorted(manifest["summary"]["stale_artifacts"]) == [
    "drift_evidence",
    "drift_triage",
    "health_evidence",
]
assert "nn_ids.posture_bundle.health_evidence.fresh" in manifest["release_gate"]["promotion_blockers"]
assert all(entry["freshness_status"] == "fail" for entry in manifest["artifacts"])
assert all(entry["artifact_age_minutes"] > 60 for entry in manifest["artifacts"])
PY

python3 "${SCRIPT}" \
  --health-evidence "${TMP_DIR}/health.json" \
  --drift-evidence "${TMP_DIR}/drift.json" \
  --drift-triage "${TMP_DIR}/triage.json" \
  --max-artifact-age-minutes 60 \
  --format markdown \
  --output "${TMP_DIR}/manifest.md" || true

grep -q 'Freshness window: `60.0` minutes' "${TMP_DIR}/manifest.md"
grep -q '| health_evidence | `fail` | `fail` |' "${TMP_DIR}/manifest.md"
grep -q '`nn_ids.posture_bundle.health_evidence.fresh`' "${TMP_DIR}/manifest.md"
