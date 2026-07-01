#!/usr/bin/env python3
# MINC - Passive NN IDS release readiness summary for defensive handoff evidence.
# Defensive purpose: compose existing IDS audit artifacts without reading packets, models, datasets, or mutating services.
"""Create a passive release-readiness summary from NN IDS audit artifacts."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

SUMMARY_VERSION = "1.0.0"
DECISION_READY = "ids_release_ready"
DECISION_BLOCKED = "ids_release_blocked"
SCHEMA_PATH = "docs/schemas/nn_ids_release_readiness_summary.schema.json"
STATIC_VALIDATION_COMMANDS = [
    "bash tests/test_nn_ids_release_readiness_summary_static.sh",
    "bash tests/test_nn_ids_release_schema_contract_static.sh",
    "bash tests/run_static_security_checks.sh",
]
HOSTED_REQUIRED_CHECKS = [
    "Static Security Checks",
]
ACCEPTABLE_GATE_DECISIONS = {"accept", "watch"}
BLOCKING_GATE_DECISIONS = {"retrain", "restore"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path, label: str) -> tuple[dict[str, Any], list[str]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, [f"{label} artifact is missing: {path}"]
    except json.JSONDecodeError as exc:
        return {}, [f"{label} artifact JSON is invalid: {exc}"]
    if not isinstance(loaded, dict):
        return {}, [f"{label} artifact JSON root must be an object"]
    return loaded, []


def number_at(data: dict[str, Any], keys: list[str]) -> Optional[float]:
    node: Any = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    try:
        return float(node)
    except (TypeError, ValueError):
        return None


def validate_model_audit(audit: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if audit.get("message") != "nn_ids_model_audit_complete":
        issues.append("model audit message must be nn_ids_model_audit_complete")
    for metric in ["accuracy", "balanced_accuracy", "precision", "recall", "f1"]:
        value = number_at(audit, ["metrics", metric])
        if value is None:
            issues.append(f"model audit metric is missing or non-numeric: {metric}")
        elif not 0.0 <= value <= 1.0:
            issues.append(f"model audit metric {metric} must be between 0 and 1")
    robustness = number_at(audit, ["robustness", "robustness_index"])
    if robustness is None:
        issues.append("model audit robustness_index is missing or non-numeric")
    elif not 0.0 <= robustness <= 1.0:
        issues.append("model audit robustness_index must be between 0 and 1")
    features = audit.get("features")
    if not isinstance(features, list) or not features:
        issues.append("model audit features must be a non-empty list")
    rows = audit.get("rows")
    if not isinstance(rows, int) or rows <= 0:
        issues.append("model audit rows must be a positive integer")
    return issues


def validate_gate(gate: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if gate.get("message") != "nn_ids_audit_gate_complete":
        issues.append("audit gate message must be nn_ids_audit_gate_complete")
    decision = gate.get("decision")
    if decision not in ACCEPTABLE_GATE_DECISIONS | BLOCKING_GATE_DECISIONS:
        issues.append("audit gate decision must be accept, watch, retrain, or restore")
    findings = gate.get("findings")
    if not isinstance(findings, list):
        issues.append("audit gate findings must be a list")
    actions = gate.get("actions")
    if not isinstance(actions, list):
        issues.append("audit gate actions must be a list")
    thresholds = gate.get("thresholds")
    if not isinstance(thresholds, dict):
        issues.append("audit gate thresholds must be an object")
    elif thresholds.get("auto_actions") is not False:
        issues.append("audit gate release summary requires thresholds.auto_actions=false")
    if decision in BLOCKING_GATE_DECISIONS:
        issues.append(f"audit gate decision requires remediation before release: {decision}")
    return issues


def evidence_manifest() -> dict[str, Any]:
    return {
        "schema_path": SCHEMA_PATH,
        "static_validation_commands": STATIC_VALIDATION_COMMANDS,
        "hosted_required_checks": HOSTED_REQUIRED_CHECKS,
        "safe_to_publish": True,
        "contains_raw_telemetry": False,
        "contains_secrets": False,
        "live_state_validation_required": False,
        "human_review_required": True,
    }


def build_summary(model_audit_path: Path, audit_gate_path: Path) -> dict[str, Any]:
    audit, audit_load_issues = load_json(model_audit_path, "model_audit")
    gate, gate_load_issues = load_json(audit_gate_path, "audit_gate")

    issues = [f"model_audit: {issue}" for issue in audit_load_issues]
    issues.extend(f"audit_gate: {issue}" for issue in gate_load_issues)
    if not audit_load_issues:
        issues.extend(validate_model_audit(audit))
    if not gate_load_issues:
        issues.extend(validate_gate(gate))

    ready = not issues
    metrics = audit.get("metrics", {}) if isinstance(audit.get("metrics"), dict) else {}
    drift = audit.get("drift", {}) if isinstance(audit.get("drift"), dict) else {}
    robustness = audit.get("robustness", {}) if isinstance(audit.get("robustness"), dict) else {}
    shifted_features = drift.get("shifted_features", []) if isinstance(drift.get("shifted_features"), list) else []

    return {
        "schema_version": 1,
        "summary": "nn_ids_release_readiness_summary.py",
        "summary_version": SUMMARY_VERSION,
        "created_utc": utc_now(),
        "decision": DECISION_READY if ready else DECISION_BLOCKED,
        "ids_release_ready": ready,
        "changes_live_state": False,
        "reads_raw_telemetry": False,
        "aggregate_evidence_only": True,
        "model_audit": {
            "path": str(model_audit_path),
            "message": audit.get("message"),
            "rows": audit.get("rows"),
            "feature_count": len(audit.get("features", [])) if isinstance(audit.get("features"), list) else None,
            "metric_average": audit.get("metric_average"),
            "accuracy": metrics.get("accuracy"),
            "balanced_accuracy": metrics.get("balanced_accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1": metrics.get("f1"),
            "robustness_index": robustness.get("robustness_index"),
            "max_mean_z": drift.get("max_mean_z"),
            "shifted_feature_count": len(shifted_features),
            "probability_available": audit.get("probability_available"),
        },
        "audit_gate": {
            "path": str(audit_gate_path),
            "message": gate.get("message"),
            "decision": gate.get("decision"),
            "finding_count": len(gate.get("findings", [])) if isinstance(gate.get("findings"), list) else None,
            "auto_actions": (gate.get("thresholds") or {}).get("auto_actions") if isinstance(gate.get("thresholds"), dict) else None,
        },
        "blocking_issues": issues,
        "reviewer_handoff": {
            "purpose": "Summarize NN IDS model audit and audit-gate evidence for release review without reading raw telemetry or mutating IDS services.",
            "confirm_model_audit_complete": "nn_ids_model_audit_complete",
            "confirm_gate_complete": "nn_ids_audit_gate_complete",
            "acceptable_gate_decisions": sorted(ACCEPTABLE_GATE_DECISIONS),
            "remediation_gate_decisions": sorted(BLOCKING_GATE_DECISIONS),
            "confirm_no_live_state_change": True,
            "confirm_no_raw_telemetry": True,
            "requires_human_review_before_release_promotion": True,
        },
        "evidence_manifest": evidence_manifest(),
        "rollback": {
            "live_state_rollback_required": False,
            "action": "revert IDS release summary CLI, schema, docs, changelog, and tests only",
        },
        "follow_up": [
            "Wire IDS readiness into the aggregate host/VM release posture once firstboot and restore artifacts share a hosted workspace.",
            "Add hosted JSON Schema validation once the repository adopts a reusable validator.",
            "Extend IDS audit evidence with calibrated confidence intervals and dataset provenance hashes.",
        ],
    }


def write_outputs(summary: dict[str, Any], output: Optional[Path], report: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"created_utc={summary['created_utc']}",
            f"decision={summary['decision']}",
            f"ids_release_ready={str(summary['ids_release_ready']).lower()}",
            f"gate_decision={summary['audit_gate']['decision']}",
            f"blocking_issue_count={len(summary['blocking_issues'])}",
            f"changes_live_state={str(summary['changes_live_state']).lower()}",
            f"reads_raw_telemetry={str(summary['reads_raw_telemetry']).lower()}",
            f"aggregate_evidence_only={str(summary['aggregate_evidence_only']).lower()}",
            f"schema_path={summary['evidence_manifest']['schema_path']}",
            f"safe_to_publish={str(summary['evidence_manifest']['safe_to_publish']).lower()}",
            f"contains_raw_telemetry={str(summary['evidence_manifest']['contains_raw_telemetry']).lower()}",
            f"contains_secrets={str(summary['evidence_manifest']['contains_secrets']).lower()}",
            f"human_review_required={str(summary['evidence_manifest']['human_review_required']).lower()}",
        ]
        for issue in summary["blocking_issues"][:50]:
            lines.append(f"blocking_issue={issue}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a passive NN IDS release-readiness summary from audit artifacts.")
    parser.add_argument("--model-audit", type=Path, required=True, help="Path to nn_ids_model_audit.py JSON output")
    parser.add_argument("--audit-gate", type=Path, required=True, help="Path to nn_ids_audit_gate.py JSON output")
    parser.add_argument("--output", type=Path, help="optional JSON release-readiness summary output path")
    parser.add_argument("--report", type=Path, help="optional compact key=value report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless IDS release readiness is satisfied")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    summary = build_summary(args.model_audit, args.audit_gate)
    write_outputs(summary, args.output, args.report)
    print(json.dumps({"decision": summary["decision"], "ids_release_ready": summary["ids_release_ready"], "blocking_issues": len(summary["blocking_issues"])}, sort_keys=True))
    if args.strict and not summary["ids_release_ready"]:
        return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
