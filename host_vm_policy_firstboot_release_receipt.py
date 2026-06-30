#!/usr/bin/env python3
# MINC - Passive firstboot handoff release receipt generator; aggregate evidence only.
"""Build a compact release-readiness receipt from firstboot handoff gate evidence."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

RECEIPT_NAME = "host_vm_policy_firstboot_release_receipt.py"
RECEIPT_VERSION = "1.0.0"
SAFE_GATE_NAME = "host_vm_policy_firstboot_handoff_gate.py"
REQUIRED_GATE_FIELDS = {
    "schema_version",
    "gate",
    "gate_version",
    "created_utc",
    "decision",
    "changes_live_state",
    "reads_raw_telemetry",
    "checks_passed",
    "checks_failed",
    "checks",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, [f"gate evidence file is missing: {path}"]
    except json.JSONDecodeError as exc:
        return {}, [f"gate evidence JSON is invalid: {exc}"]
    if not isinstance(loaded, dict):
        return {}, ["gate evidence JSON root must be an object"]
    return loaded, []


def failed_check_names(gate: dict[str, Any]) -> list[str]:
    checks = gate.get("checks")
    if not isinstance(checks, list):
        return ["checks_not_list"]
    names: list[str] = []
    for item in checks:
        if not isinstance(item, dict):
            names.append("malformed_check")
        elif item.get("status") != "pass":
            names.append(str(item.get("name", "unnamed_check")))
    return names


def evaluate(gate_path: Path) -> dict[str, Any]:
    gate, issues = load_json(gate_path)
    if not issues:
        for field in sorted(REQUIRED_GATE_FIELDS.difference(gate)):
            issues.append(f"gate evidence missing required field: {field}")
        if gate.get("schema_version") != 1:
            issues.append("gate schema_version must be 1")
        if gate.get("gate") != SAFE_GATE_NAME:
            issues.append(f"gate must be {SAFE_GATE_NAME}")
        if gate.get("decision") != "release_ready":
            issues.append("gate decision must be release_ready")
        if gate.get("changes_live_state") is not False:
            issues.append("gate evidence must declare changes_live_state=false")
        if gate.get("reads_raw_telemetry") is not False:
            issues.append("gate evidence must declare reads_raw_telemetry=false")
        if gate.get("checks_failed") != 0:
            issues.append("gate evidence must report checks_failed=0")
        if not isinstance(gate.get("checks_passed"), int) or int(gate.get("checks_passed", 0)) <= 0:
            issues.append("gate evidence must report at least one passed check")
        for name in failed_check_names(gate):
            issues.append(f"gate check not passing: {name}")

    release_ready = not issues
    return {
        "schema_version": 1,
        "receipt": RECEIPT_NAME,
        "receipt_version": RECEIPT_VERSION,
        "created_utc": utc_now(),
        "source_gate_path": str(gate_path),
        "source_gate": gate.get("gate") if isinstance(gate, dict) else None,
        "source_gate_version": gate.get("gate_version") if isinstance(gate, dict) else None,
        "source_gate_decision": gate.get("decision") if isinstance(gate, dict) else None,
        "release_ready": release_ready,
        "decision": "release_receipt_ready" if release_ready else "release_receipt_blocked",
        "changes_live_state": False,
        "reads_raw_telemetry": False,
        "checks_passed": gate.get("checks_passed") if isinstance(gate.get("checks_passed"), int) else 0,
        "checks_failed": gate.get("checks_failed") if isinstance(gate.get("checks_failed"), int) else len(issues),
        "blocking_issues": issues,
        "handoff_scope": {
            "aggregate_evidence_only": True,
            "mutates_host_or_vm_state": False,
        },
        "rollback": {
            "live_state_rollback_required": False,
            "action": "revert receipt artifact generation and workflow receipt step only",
        },
        "follow_up": [
            "Feed this receipt into a broader release-readiness gate with restore executor and IDS audit evidence.",
            "Add expected-blocked receipt examples once release aggregation can distinguish intentional blocked cases.",
        ],
    }


def write_outputs(receipt: dict[str, Any], output: Optional[Path], report: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"created_utc={receipt['created_utc']}",
            f"decision={receipt['decision']}",
            f"release_ready={str(receipt['release_ready']).lower()}",
            f"source_gate_decision={receipt['source_gate_decision']}",
            f"changes_live_state={receipt['changes_live_state']}",
            f"reads_raw_telemetry={receipt['reads_raw_telemetry']}",
            f"blocking_issue_count={len(receipt['blocking_issues'])}",
        ]
        for issue in receipt["blocking_issues"]:
            lines.append(f"issue={issue}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a passive release-readiness receipt from firstboot handoff gate evidence.")
    parser.add_argument("gate_evidence", type=Path, help="Path to firstboot_handoff_gate.json")
    parser.add_argument("--output", type=Path, help="optional JSON receipt path")
    parser.add_argument("--report", type=Path, help="optional compact receipt report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless the release receipt is ready")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    receipt = evaluate(args.gate_evidence)
    write_outputs(receipt, args.output, args.report)
    print(json.dumps({"decision": receipt["decision"], "blocking_issues": len(receipt["blocking_issues"])}, sort_keys=True))
    if args.strict and not receipt["release_ready"]:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
