#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT_DIR}/nn_ids_dataset_quality_evidence.py"
BUILD_SCRIPT="${ROOT_DIR}/build_custom_iso.sh"
DOC="${ROOT_DIR}/docs/nn_ids_dataset_quality_evidence.md"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

python3 -m py_compile "${SCRIPT}"
python3 "${SCRIPT}" --help >/dev/null

grep -q -- '"nn_ids_dataset_quality_evidence.py"' "${BUILD_SCRIPT}"
grep -q -- 'never opens network sockets' "${SCRIPT}"
grep -q -- 'never executes system commands' "${SCRIPT}"
grep -q -- 'packet payloads' "${SCRIPT}"
grep -q -- '--require-pass' "${SCRIPT}"
grep -q -- 'Rollback' "${DOC}"
grep -q -- 'privacy' "${DOC}"

DATASET="${TMP_DIR}/dataset.csv"
OUTPUT_JSON="${TMP_DIR}/dataset_quality.json"
OUTPUT_MD="${TMP_DIR}/dataset_quality.md"

cat > "${DATASET}" <<'CSV'
flow_duration,total_packets,bytes,label
1.0,10,500,benign
2.0,12,700,benign
3.0,40,2000,malicious
4.0,45,2400,malicious
CSV

python3 "${SCRIPT}" \
  --dataset "${DATASET}" \
  --min-rows 4 \
  --min-classes 2 \
  --max-missing-rate 0.01 \
  --max-class-imbalance 0.75 \
  --max-duplicate-rate 0.01 \
  --output "${OUTPUT_JSON}" \
  --require-pass

python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["component"] == "nn_ids_dataset_quality"
assert payload["status"] == "pass"
assert payload["ok"] is True
assert payload["summary"]["rows"] == 4
assert payload["summary"]["columns"] == 4
assert payload["summary"]["label_counts"]["benign"] == 2
assert payload["privacy"]["raw_rows_included"] is False
assert payload["privacy"]["packet_payloads_included"] is False
controls = {finding["control"] for finding in payload["findings"]}
assert "nn_ids.dataset.rows" in controls
assert "nn_ids.dataset.label_classes" in controls
assert "nn_ids.dataset.class_imbalance" in controls
PY

python3 "${SCRIPT}" \
  --dataset "${DATASET}" \
  --min-rows 4 \
  --format markdown \
  --output "${OUTPUT_MD}"
grep -q '# NN IDS Dataset Quality Evidence' "${OUTPUT_MD}"
grep -q 'Raw dataset rows and packet payloads are not embedded' "${OUTPUT_MD}"
grep -q 'Rollback' "${OUTPUT_MD}"

cat > "${DATASET}" <<'CSV'
flow_duration,total_packets,bytes,label
1.0,10,500,benign
2.0,,700,benign
3.0,,900,benign
4.0,,1100,benign
CSV

if python3 "${SCRIPT}" \
  --dataset "${DATASET}" \
  --min-rows 4 \
  --min-classes 2 \
  --max-missing-rate 0.01 \
  --max-class-imbalance 0.75 \
  --require-pass >/dev/null; then
  echo "expected single-class missing-heavy dataset to fail with --require-pass" >&2
  exit 1
fi

python3 "${SCRIPT}" \
  --dataset "${DATASET}" \
  --min-rows 4 \
  --min-classes 2 \
  --max-missing-rate 0.01 \
  --max-class-imbalance 0.75 \
  --output "${OUTPUT_JSON}" >/dev/null
python3 - "${OUTPUT_JSON}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    payload = json.load(handle)

assert payload["status"] == "fail"
assert "nn_ids.dataset.label_classes" in payload["failing_controls"]
assert "nn_ids.dataset.missing_rate" in payload["failing_controls"]
assert "nn_ids.dataset.class_imbalance" in payload["failing_controls"]
PY

cat > "${DATASET}" <<'CSV'
flow_duration,total_packets,bytes
1.0,10,500
CSV
if python3 "${SCRIPT}" --dataset "${DATASET}" --min-rows 1 --require-pass >/dev/null; then
  echo "expected missing label column to fail with --require-pass" >&2
  exit 1
fi

cat > "${DATASET}" <<'CSV'
flow_duration,total_packets,bytes,label
1.0,10,500,benign
1.0,10,500,benign
2.0,20,1000,malicious
2.0,20,1000,malicious
CSV
if python3 "${SCRIPT}" \
  --dataset "${DATASET}" \
  --min-rows 4 \
  --min-classes 2 \
  --max-duplicate-rate 0.01 \
  --require-pass >/dev/null; then
  echo "expected duplicate-heavy dataset sample to fail with --require-pass" >&2
  exit 1
fi

echo "nn_ids_dataset_quality_evidence static smoke checks passed"
