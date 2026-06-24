#!/usr/bin/env python3
"""nn_ids_audit_gate.py - policy gate for NN IDS audit results.

MINC - Defensive automation only. This script reads the local NN IDS model audit
report and produces a conservative decision about whether the model remains
acceptable, should be retrained, or should be restored from the latest known-good
snapshot. It does not scan, attack, evade, persist, or contact remote systems.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

AUDIT_REPORT = Path(os.getenv("NN_IDS_AUDIT_REPORT", "/var/log/nn_ids_model_audit.json"))
GATE_REPORT = Path(os.getenv("NN_IDS_AUDIT_GATE_REPORT", "/var/log/nn_ids_audit_gate.json"))
GATE_STATE = Path(os.getenv("NN_IDS_AUDIT_GATE_STATE", "/opt/nnids/audit/audit_gate_state.json"))
RETRAIN_SERVICE = os.getenv("NN_IDS_RETRAIN_SERVICE", "nn_ids_retrain.service")
RESTORE_SERVICE = os.getenv("NN_IDS_RESTORE_SERVICE", "nn_ids_restore.service")

MIN_F1 = float(os.getenv("NN_IDS_GATE_MIN_F1", "0.70"))
MIN_BALANCED_ACCURACY = float(os.getenv("NN_IDS_GATE_MIN_BALANCED_ACCURACY", "0.70"))
MIN_ROBUSTNESS_INDEX = float(os.getenv("NN_IDS_GATE_MIN_ROBUSTNESS_INDEX", "0.65"))
MAX_MEAN_Z = float(os.getenv("NN_IDS_GATE_MAX_MEAN_Z", "3.0"))
MAX_SHIFTED_FEATURES = int(os.getenv("NN_IDS_GATE_MAX_SHIFTED_FEATURES", "10"))
MAX_CONSECUTIVE_RETRAIN = int(os.getenv("NN_IDS_GATE_MAX_CONSECUTIVE_RETRAIN", "2"))
AUTO_ACTIONS = os.getenv("NN_IDS_GATE_AUTO_ACTIONS", "0") == "1"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o640)


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _float_at(data: Dict[str, Any], keys: Iterable[str], default: float = 0.0) -> float:
    node: Any = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    try:
        return float(node)
    except (TypeError, ValueError):
        return default


def _int_at(data: Dict[str, Any], keys: Iterable[str], default: int = 0) -> int:
    node: Any = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    try:
        return int(node)
    except (TypeError, ValueError):
        return default


def _shifted_feature_count(audit: Dict[str, Any]) -> int:
    shifted = audit.get("drift", {}).get("shifted_features", [])
    return len(shifted) if isinstance(shifted, list) else 0


def _build_findings(audit: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
    findings: List[Dict[str, Any]] = []
    message = str(audit.get("message", ""))
    if message.endswith("failed") or "error" in audit:
        findings.append({"severity": "critical", "reason": "audit_failed", "details": audit.get("error", message)})
        return findings, "restore"

    f1 = _float_at(audit, ["metrics", "f1"])
    balanced_accuracy = _float_at(audit, ["metrics", "balanced_accuracy"])
    robustness = _float_at(audit, ["robustness", "robustness_index"])
    max_mean_z = _float_at(audit, ["drift", "max_mean_z"])
    shifted_count = _shifted_feature_count(audit)

    if f1 < MIN_F1:
        findings.append({"severity": "high", "reason": "f1_below_threshold", "value": f1, "threshold": MIN_F1})
    if balanced_accuracy < MIN_BALANCED_ACCURACY:
        findings.append({
            "severity": "high",
            "reason": "balanced_accuracy_below_threshold",
            "value": balanced_accuracy,
            "threshold": MIN_BALANCED_ACCURACY,
        })
    if robustness < MIN_ROBUSTNESS_INDEX:
        findings.append({
            "severity": "medium",
            "reason": "robustness_index_below_threshold",
            "value": robustness,
            "threshold": MIN_ROBUSTNESS_INDEX,
        })
    if max_mean_z >= MAX_MEAN_Z:
        findings.append({"severity": "medium", "reason": "feature_mean_drift", "value": max_mean_z, "threshold": MAX_MEAN_Z})
    if shifted_count > MAX_SHIFTED_FEATURES:
        findings.append({
            "severity": "medium",
            "reason": "too_many_shifted_features",
            "value": shifted_count,
            "threshold": MAX_SHIFTED_FEATURES,
        })

    if any(item["severity"] == "high" for item in findings):
        decision = "retrain"
    elif findings:
        decision = "watch"
    else:
        decision = "accept"
    return findings, decision


def _update_state(decision: str) -> Dict[str, Any]:
    state = _load_json(GATE_STATE)
    previous = str(state.get("last_decision", "unknown"))
    consecutive_retrain = _int_at(state, ["consecutive_retrain"], 0)

    if decision == "retrain":
        consecutive_retrain += 1
    elif decision == "accept":
        consecutive_retrain = 0

    escalated = False
    if consecutive_retrain > MAX_CONSECUTIVE_RETRAIN:
        decision = "restore"
        escalated = True
        consecutive_retrain = 0

    new_state = {
        "timestamp": _now(),
        "last_decision": decision,
        "previous_decision": previous,
        "consecutive_retrain": consecutive_retrain,
        "escalated_to_restore": escalated,
    }
    _write_json(GATE_STATE, new_state)
    return new_state


def _systemctl_start(service: str) -> Dict[str, Any]:
    if not AUTO_ACTIONS:
        return {"service": service, "started": False, "reason": "auto_actions_disabled"}
    result = subprocess.run(["systemctl", "start", service], check=False, text=True, capture_output=True)
    return {
        "service": service,
        "started": result.returncode == 0,
        "returncode": result.returncode,
        "stderr": result.stderr.strip()[-500:],
    }


def evaluate_gate() -> Dict[str, Any]:
    audit = _load_json(AUDIT_REPORT)
    if not audit:
        findings = [{"severity": "critical", "reason": "audit_report_missing", "path": str(AUDIT_REPORT)}]
        decision = "restore"
    else:
        findings, decision = _build_findings(audit)

    state = _update_state(decision)
    decision = str(state["last_decision"])

    actions: List[Dict[str, Any]] = []
    if decision == "retrain":
        actions.append(_systemctl_start(RETRAIN_SERVICE))
    elif decision == "restore":
        actions.append(_systemctl_start(RESTORE_SERVICE))
    elif decision == "watch":
        actions.append({"service": RETRAIN_SERVICE, "started": False, "reason": "watch_only_collect_more_audits"})

    report = {
        "timestamp": _now(),
        "message": "nn_ids_audit_gate_complete",
        "decision": decision,
        "findings": findings,
        "state": state,
        "thresholds": {
            "min_f1": MIN_F1,
            "min_balanced_accuracy": MIN_BALANCED_ACCURACY,
            "min_robustness_index": MIN_ROBUSTNESS_INDEX,
            "max_mean_z": MAX_MEAN_Z,
            "max_shifted_features": MAX_SHIFTED_FEATURES,
            "max_consecutive_retrain": MAX_CONSECUTIVE_RETRAIN,
            "auto_actions": AUTO_ACTIONS,
        },
        "actions": actions,
    }
    _write_json(GATE_REPORT, report)
    return report


def main() -> int:
    report = evaluate_gate()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["decision"] == "restore" else 1 if report["decision"] in {"retrain", "watch"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
