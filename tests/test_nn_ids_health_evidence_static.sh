#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/nn_ids_health_evidence.py"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"
python3 "${SCRIPT}" --help >/dev/null

# Normalize source whitespace before checking the documented passive-safety
# contract. This avoids brittle failures when Python formatters wrap a
# docstring across lines without changing its meaning.
python3 - "${SCRIPT}" <<'PY'
from pathlib import Path
import sys

source = " ".join(Path(sys.argv[1]).read_text(encoding="utf-8").split())
required_phrases = (
    "never opens network sockets",
    "never executes system commands",
    "hardening_posture_summary.py",
    "--require-pass",
)
missing = [phrase for phrase in required_phrases if phrase not in source]
if missing:
    raise SystemExit(f"missing passive-safety contract phrase(s): {', '.join(missing)}")
PY

MODEL="${TMP_DIR}/ids_model.pkl"
TRAIN_LOG="${TMP_DIR}/nn_ids_train.log"
HEALTH_LOG="${TMP_DIR}/nn_ids_health.log"
OUTPUT_JSON="${TMP_DIR}/nn_ids_health.json"

printf 'model-bytes\n' > "${MODEL}"
printf 'Retrain accuracy: 0.93 f1: 0.90\n' > "${TRAIN_LOG}"
printf '2026-01-01T00:00:00 healthy\n' > "${HEALTH_LOG}"

python3 "${SCRIPT}" \
  --model "${MODEL}" \
  --train-log "${TRAIN_LOG}" \
  --health-log "${HEALTH_LOG}" \
  --max-model-age-hours 999999 \
  --min-accuracy 0.7 \
  --min-f1 0.7 \
  --output "${OUTPUT_JSON}" \
  --require-pass

python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["component"] == "nn_ids"
assert payload["status"] == "pass"
assert payload["ok"] is True
assert payload["metrics"]["accuracy"] == 0.93
assert payload["metrics"]["f1"] == 0.90
controls = {finding["control"] for finding in payload["findings"]}
assert "nn_ids.model.present" in controls
assert "nn_ids.metrics.thresholds" in controls
PY

echo "nn_ids_health_evidence static smoke checks passed"
