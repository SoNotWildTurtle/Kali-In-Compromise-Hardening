#!/usr/bin/env python3
# MINC - Passive firstboot release-readiness summary; aggregate receipt evidence only.
"""Summarize firstboot release and expected-blocked receipt evidence for handoff review."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

SUMMARY_NAME = "host_vm_policy_firstboot_release_summary.py"
SUMMARY_VERSION = "1.0.0"
RECEIPT_NAME = "host_vm_policy_firstboot_release_receipt.py"
REQUIRED_RECEIPT_FIELDS = {
    "schema_version",
    "receipt",
    "receipt_version",
    "created_utc",
    "decision",
    "release_ready",
    "changes_live_state",
    "reads_raw_telemetry",
    "blocking_issues",
    "handoff_scope",
    "rollback",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, [f"receipt file is missing: {path}"]
    except json.JSONDecodeError as exc:
        return {}, [f"receipt JSON is invalid: {exc}"]
    if not isinstance(loaded, dict):
        return {}, ["receipt JSON root must be an object"]
    return loaded, []


def validate_receipt(receipt: dict[str, Any], *, expected_decision: str, expected_ready: bool, label: str) -> list[str]:
    issues: list[str] = []
    for field in sorted(REQUIRED_RECEIPT_FIELDS.difference(receipt)):
        issues.append(f"{label} receipt missing required field: {field}")
    if receipt.get("schema_version") != 1:
        issues.append(f"{label} receipt schema_version must be 1")
    if receipt.get("receipt") != RECEIPT_NAME:
        issues.append(f"{label} receipt must come from {RECEIPT_NAME}")
    if receipt.get("decision") != expected_decision:
        issues.append(f"{label} receipt decision must be {expected_decision}")
    if receipt.get("release_ready") is not expected_ready:
        issues.append(f"{label} receipt release_ready must be {str(expected_ready).lower()}")
    if receipt.get("changes_live_state") is not False:
        issues.append(f"{label} receipt must declare changes_live_state=false")
    if receipt.get("reads_raw_telemetry") is not False:
        issues.append(f"{label} receipt must declare reads_raw_telemetry=false")
    blocking_issues = receipt.get("blocking_issues")
    if not isinstance(blocking_issues, list):
        issues.append(f"{label} receipt blocking_issues must be a list")
    elif expected_ready and blocking_issues:
        issues.append(f"{label} receipt must not carry blocking issues when release_ready=true")
    elif not expected_ready and not blocking_issues:
        issues.append(f"{label} receipt must explain why release is blocked")
    handoff_scope = receipt.get("handoff_scope")
    if not isinstance(handoff_scope, dict) or handoff_scope.get("aggregate_evidence_only") is not True:
        issues.append(f"{label} receipt must declare aggregate_evidence_only=true")
    rollback = receipt.get("rollback")
    if not isinstance(rollback, dict) or rollback.get("live_state_rollback_required") is not False:
        issues.append(f"{label} receipt rollback must not require live-state changes")
    return issues


def evaluate(ready_receipt_path: Path, blocked_receipt_path: Optional[Path] = None) -> dict[str, Any]:
    ready_receipt, ready_load_issues = load_json(ready_receipt_path)
    issues = [f"ready: {issue}" for issue in ready_load_issues]
    if not ready_load_issues:
        issues.extend(validate_receipt(ready_receipt, expected_decision="release_receipt_ready", expected_ready=True, label="ready"))

    blocked_receipt: dict[str, Any] = {}
    blocked_fixture_present = blocked_receipt_path is not None
    if blocked_receipt_path is not None:
        blocked_receipt, blocked_load_issues = load_json(blocked_receipt_path)
        issues.extend(f"expected_blocked: {issue}" for issue in blocked_load_issues)
        if not blocked_load_issues:
            issues.extend(
                validate_receipt(
                    blocked_receipt,
                    expected_decision="release_receipt_blocked",
                    expected_ready=False,
                    label="expected_blocked",
                )
            )

    summary_ready = not issues
    return {
        "schema_version": 1,
        "summary": SUMMARY_NAME,
        "summary_version": SUMMARY_VERSION,
        "created_utc": utc_now(),
        "decision": "summary_ready" if summary_ready else "summary_blocked",
        "summary_ready": summary_ready,
        "changes_live_state": False,
        "reads_raw_telemetry": False,
        "aggregate_evidence_only": True,
        "ready_receipt": {
            "path": str(ready_receipt_path),
            "decision": ready_receipt.get("decision") if isinstance(ready_receipt, dict) else None,
            "release_ready": ready_receipt.get("release_ready") if isinstance(ready_receipt, dict) else None,
            "blocking_issue_count": len(ready_receipt.get("blocking_issues", [])) if isinstance(ready_receipt.get("blocking_issues"), list) else None,
        },
        "expected_blocked_receipt": {
            "present": blocked_fixture_present,
            "path": str(blocked_receipt_path) if blocked_receipt_path else None,
            "decision": blocked_receipt.get("decision") if isinstance(blocked_receipt, dict) else None,
            "release_ready": blocked_receipt.get("release_ready") if isinstance(blocked_receipt, dict) else None,
            "blocking_issue_count": len(blocked_receipt.get("blocking_issues", [])) if isinstance(blocked_receipt.get("blocking_issues"), list) else None,
        },
        "blocking_issues": issues,
        "reviewer_handoff": {
            "purpose": "Compare release-ready and expected-blocked firstboot receipt evidence without exposing raw telemetry or mutating host/VM state.",
            "safe_to_publish": True,
            "requires_human_review_before_live_firstboot_wiring": True,
        },
        "rollback": {
            "live_state_rollback_required": False,
            "action": "revert summary generation, workflow wiring, docs, and static tests only",
        },
        "follow_up": [
            "Feed restore executor and IDS aggregate release evidence into this summary once those receipts use matching ready/expected-blocked semantics.",
            "Keep expected-blocked fixture changes documented so reviewers can distinguish intentional negative evidence from workflow failure.",
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
            f"summary_ready={str(summary['summary_ready']).lower()}",
            f"ready_receipt_decision={summary['ready_receipt']['decision']}",
            f"expected_blocked_present={str(summary['expected_blocked_receipt']['present']).lower()}",
            f"expected_blocked_decision={summary['expected_blocked_receipt']['decision']}",
            f"changes_live_state={summary['changes_live_state']}",
            f"reads_raw_telemetry={summary['reads_raw_telemetry']}",
            f"blocking_issue_count={len(summary['blocking_issues'])}",
        ]
        for issue in summary["blocking_issues"]:
            lines.append(f"issue={issue}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a passive firstboot release-readiness summary from aggregate receipt evidence.")
    parser.add_argument("ready_receipt", type=Path, help="Path to firstboot_release_receipt.json")
    parser.add_argument("--expected-blocked-receipt", type=Path, help="optional expected-blocked receipt JSON path")
    parser.add_argument("--output", type=Path, help="optional JSON summary path")
    parser.add_argument("--report", type=Path, help="optional compact summary report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless the summary is ready")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    summary = evaluate(args.ready_receipt, args.expected_blocked_receipt)
    write_outputs(summary, args.output, args.report)
    print(json.dumps({"decision": summary["decision"], "blocking_issues": len(summary["blocking_issues"])}, sort_keys=True))
    if args.strict and not summary["summary_ready"]:
        return 5
    return 0


if __name__ == "__main__":
    sys.exit(main())
