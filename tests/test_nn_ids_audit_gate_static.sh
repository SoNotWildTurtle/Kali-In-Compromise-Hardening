#!/usr/bin/env bash
# MINC - Static checks for the defensive NN IDS audit gate.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 -m py_compile nn_ids_audit_gate.py

python3 - <<'PY'
import importlib.util
import json
import os
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    tmp_path = Path(tmp)
    audit_path = tmp_path / "audit.json"
    gate_report = tmp_path / "gate.json"
    gate_state = tmp_path / "state.json"
    os.environ["NN_IDS_AUDIT_REPORT"] = str(audit_path)
    os.environ["NN_IDS_AUDIT_GATE_REPORT"] = str(gate_report)
    os.environ["NN_IDS_AUDIT_GATE_STATE"] = str(gate_state)
    os.environ["NN_IDS_GATE_AUTO_ACTIONS"] = "0"

    spec = importlib.util.spec_from_file_location("gate", "nn_ids_audit_gate.py")
    gate = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(gate)

    audit_path.write_text(json.dumps({
        "message": "nn_ids_model_audit_complete",
        "metrics": {"f1": 0.95, "balanced_accuracy": 0.94},
        "robustness": {"robustness_index": 0.91},
        "drift": {"max_mean_z": 0.2, "shifted_features": []}
    }), encoding="utf-8")
    report = gate.evaluate_gate()
    assert report["decision"] == "accept", report
    assert gate_report.exists()

    audit_path.write_text(json.dumps({
        "message": "nn_ids_model_audit_complete",
        "metrics": {"f1": 0.20, "balanced_accuracy": 0.50},
        "robustness": {"robustness_index": 0.91},
        "drift": {"max_mean_z": 0.2, "shifted_features": []}
    }), encoding="utf-8")
    report = gate.evaluate_gate()
    assert report["decision"] == "retrain", report
    assert report["actions"][0]["started"] is False
    assert report["actions"][0]["reason"] == "auto_actions_disabled"

    audit_path.write_text(json.dumps({"message": "nn_ids_model_audit_failed", "error": "missing model"}), encoding="utf-8")
    report = gate.evaluate_gate()
    assert report["decision"] == "restore", report
PY

grep -q '^NoNewPrivileges=true' nn_ids_audit_gate.service
grep -q '^ProtectSystem=strict' nn_ids_audit_gate.service
grep -q '^RestrictAddressFamilies=AF_UNIX' nn_ids_audit_gate.service
grep -q '^OnUnitActiveSec=1h' nn_ids_audit_gate.timer
grep -q 'NN_IDS_GATE_AUTO_ACTIONS=0' docs/nn_ids_audit_gate.md

echo "nn_ids_audit_gate static checks passed"
