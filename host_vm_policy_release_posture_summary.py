#!/usr/bin/env python3
# MINC - Passive aggregate posture summary for firstboot and restore release evidence.
# Defensive purpose: combine already-summarized release artifacts without reading raw telemetry or mutating state.
"""Create a passive release posture summary from firstboot and restore readiness summaries."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

POSTURE_VERSION = "1.0.0"
POSTURE_READY = "release_posture_ready"
POSTURE_BLOCKED = "release_posture_blocked"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path, label: str) -> tuple[dict[str, Any], list[str]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, [f"{label} summary file is missing: {path}"]
    except json.JSONDecodeError as exc:
        return {}, [f"{label} summary JSON is invalid: {exc}"]
    if not isinstance(loaded, dict):
        return {}, [f"{label} summary JSON root must be an object"]
    return loaded, []


def validate_common(summary: dict[str, Any], label: str) -> list[str]:
    issues: list[str] = []
    if summary.get("changes_live_state") is not False:
        issues.append(f"{label} summary must declare changes_live_state=false")
    if summary.get("reads_raw_telemetry") is not False:
        issues.append(f"{label} summary must declare reads_raw_telemetry=false")
    if summary.get("aggregate_evidence_only") is not True:
        issues.append(f"{label} summary must declare aggregate_evidence_only=true")
    if not isinstance(summary.get("blocking_issues"), list):
        issues.append(f"{label} summary blocking_issues must be a list")
    return issues


def validate_firstboot(summary: dict[str, Any]) -> list[str]:
    issues = validate_common(summary, "firstboot")
    if summary.get("decision") != "summary_ready":
        issues.append("firstboot summary decision must be summary_ready")
    if summary.get("summary_ready") is not True:
        issues.append("firstboot summary_ready must be true")
    return issues


def validate_restore(summary: dict[str, Any]) -> list[str]:
    issues = validate_common(summary, "restore")
    if summary.get("decision") != "restore_summary_ready":
        issues.append("restore summary decision must be restore_summary_ready")
    if summary.get("summary_ready") is not True:
        issues.append("restore summary_ready must be true")
    if summary.get("requires_manual_invocation") is not True:
        issues.append("restore summary must declare requires_manual_invocation=true")
    return issues


def component_record(path: Path, summary: dict[str, Any], label: str) -> dict[str, Any]:
    blocking_issues = summary.get("blocking_issues")
    return {
        "path": str(path),
        "decision": summary.get("decision"),
        "ready": summary.get("summary_ready"),
        "blocking_issue_count": len(blocking_issues) if isinstance(blocking_issues, list) else None,
        "changes_live_state": summary.get("changes_live_state"),
        "reads_raw_telemetry": summary.get("reads_raw_telemetry"),
        "aggregate_evidence_only": summary.get("aggregate_evidence_only"),
        "label": label,
    }


def build_posture(firstboot_path: Path, restore_path: Path) -> dict[str, Any]:
    firstboot, firstboot_load_issues = load_json(firstboot_path, "firstboot")
    restore, restore_load_issues = load_json(restore_path, "restore")

    issues = [f"firstboot: {issue}" for issue in firstboot_load_issues]
    issues.extend(f"restore: {issue}" for issue in restore_load_issues)
    if not firstboot_load_issues:
        issues.extend(validate_firstboot(firstboot))
    if not restore_load_issues:
        issues.extend(validate_restore(restore))

    posture_ready = not issues
    return {
        "schema_version": 1,
        "summary": "host_vm_policy_release_posture_summary.py",
        "summary_version": POSTURE_VERSION,
        "created_utc": utc_now(),
        "decision": POSTURE_READY if posture_ready else POSTURE_BLOCKED,
        "posture_ready": posture_ready,
        "changes_live_state": False,
        "reads_raw_telemetry": False,
        "aggregate_evidence_only": True,
        "components": {
            "firstboot": component_record(firstboot_path, firstboot, "firstboot handoff release summary"),
            "restore": component_record(restore_path, restore, "manual restore release summary"),
        },
        "blocking_issues": issues,
        "reviewer_handoff": {
            "purpose": "Combine firstboot and restore aggregate summaries so reviewers can promote release evidence from one posture artifact.",
            "confirm_firstboot_summary_ready": "summary_ready",
            "confirm_restore_summary_ready": "restore_summary_ready",
            "confirm_no_live_state_change": True,
            "confirm_no_raw_telemetry": True,
            "requires_human_review_before_release_promotion": True,
        },
        "rollback": {
            "live_state_rollback_required": False,
            "action": "revert posture summary CLI, docs, changelog, and tests only",
        },
        "follow_up": [
            "Add IDS aggregate release summary once IDS evidence exposes matching ready/blocked semantics.",
            "Publish a JSON Schema contract for this aggregate posture artifact after the field set stabilizes.",
            "Wire this posture summary into hosted release gates after firstboot and restore artifacts are both generated in a shared workflow context.",
        ],
    }


def write_outputs(posture: dict[str, Any], output: Optional[Path], report: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(posture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"created_utc={posture['created_utc']}",
            f"decision={posture['decision']}",
            f"posture_ready={str(posture['posture_ready']).lower()}",
            f"firstboot_decision={posture['components']['firstboot']['decision']}",
            f"restore_decision={posture['components']['restore']['decision']}",
            f"blocking_issue_count={len(posture['blocking_issues'])}",
            f"changes_live_state={str(posture['changes_live_state']).lower()}",
            f"reads_raw_telemetry={str(posture['reads_raw_telemetry']).lower()}",
            f"aggregate_evidence_only={str(posture['aggregate_evidence_only']).lower()}",
        ]
        for issue in posture["blocking_issues"][:50]:
            lines.append(f"blocking_issue={issue}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a passive aggregate release posture summary from firstboot and restore summaries.")
    parser.add_argument("--firstboot-summary", type=Path, required=True, help="Path to firstboot release summary JSON")
    parser.add_argument("--restore-summary", type=Path, required=True, help="Path to restore release summary JSON")
    parser.add_argument("--output", type=Path, help="optional JSON posture summary output path")
    parser.add_argument("--report", type=Path, help="optional compact key=value report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless aggregate posture is ready")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    posture = build_posture(args.firstboot_summary, args.restore_summary)
    write_outputs(posture, args.output, args.report)
    print(json.dumps({"decision": posture["decision"], "posture_ready": posture["posture_ready"], "blocking_issues": len(posture["blocking_issues"])}, sort_keys=True))
    if args.strict and not posture["posture_ready"]:
        return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
