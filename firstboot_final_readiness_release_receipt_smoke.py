#!/usr/bin/env python3
"""Validate passive firstboot release receipt summary evidence.

MINC - Defensive firstboot release receipt smoke helper only. This script reads
aggregate `.summary.env` evidence produced by the release receipt helper and
writes JSON or Markdown smoke evidence. It does not source shell content and does
not change firewall, policy, service, account, approval, restore, model,
dataset, host, VM, or network state.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List

REQUIRED_KEYS = {
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE",
}
PASS_STATUSES = {"approved", "pass", "ready"}
SUMMARY_RE = re.compile(r'^(FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_[A-Z0-9_]+)="([^"\\]*)"$')


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_summary(path: pathlib.Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"_load_error": str(exc), "_source_path": str(path)}
    for line in lines:
        if not line.strip():
            continue
        match = SUMMARY_RE.match(line.strip())
        if match:
            values[match.group(1)] = match.group(2)
        else:
            values.setdefault("_parse_warnings", "malformed summary line ignored")
    values["_source_path"] = str(path)
    return values


def parse_non_negative_int(values: Dict[str, str], key: str, blockers: List[str]) -> int:
    raw = values.get(key, "")
    try:
        parsed = int(raw)
    except ValueError:
        blockers.append(f"{key} is not an integer")
        return 0
    if parsed < 0:
        blockers.append(f"{key} is negative")
        return 0
    return parsed


def build_smoke(values: Dict[str, str]) -> Dict[str, object]:
    blockers: List[str] = []
    warnings: List[str] = []

    if values.get("_load_error"):
        blockers.append(f"release receipt summary could not be loaded: {values['_load_error']}")

    missing = sorted(REQUIRED_KEYS.difference(values))
    if missing:
        blockers.append("missing required release receipt summary keys: " + ", ".join(missing))

    if values.get("_parse_warnings"):
        warnings.append(values["_parse_warnings"])

    receipt_status = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS", "unknown").lower()
    privacy_scope = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE", "unknown")
    blocker_count = parse_non_negative_int(values, "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS", blockers)
    warning_count = parse_non_negative_int(values, "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS", blockers)
    artifact_count = parse_non_negative_int(values, "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS", blockers)

    if receipt_status not in PASS_STATUSES:
        blockers.append(f"release receipt status is {receipt_status}")
    if blocker_count:
        blockers.append(f"release receipt reports {blocker_count} blocker(s)")
    if artifact_count <= 0:
        blockers.append("release receipt reports no firstboot artifacts")
    if privacy_scope != "aggregate_metadata_only":
        blockers.append(f"privacy scope is {privacy_scope}")
    if warning_count:
        warnings.append(f"release receipt reports {warning_count} warning(s)")

    status = "pass" if not blockers else "review"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "source_path": values.get("_source_path"),
        "release_receipt_status": receipt_status,
        "release_receipt_blockers": blocker_count,
        "release_receipt_warnings": warning_count,
        "release_receipt_artifacts": artifact_count,
        "privacy_scope": privacy_scope,
        "blockers": blockers,
        "warnings": warnings,
        "safe_automation_boundary": "passive_summary_validation_only_no_host_vm_firewall_service_network_restore_or_model_changes",
        "operator_guidance": [
            "Treat review status as a release blocker until upstream receipt evidence is corrected.",
            "Use this smoke artifact as a quick contract check, not as a substitute for reviewing upstream evidence.",
            "Approve promotion only when required repository checks are green and stacked dependencies are satisfied.",
        ],
        "rollback_guidance": [
            "Remove the release receipt smoke helper from build_custom_iso.sh.",
            "Remove the release receipt smoke ExecStartPost lines from firstboot_release_gate.service.",
            "Delete generated /var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.* artifacts.",
            "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.",
        ],
    }


def write_summary(path: pathlib.Path, smoke: Dict[str, object]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS="{smoke["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS="{len(smoke["blockers"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS="{len(smoke["warnings"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE="{smoke["privacy_scope"]}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(smoke: Dict[str, object]) -> str:
    lines = [
        "# Firstboot Final Readiness Release Receipt Smoke",
        "",
        f"- Generated UTC: `{smoke['generated_utc']}`",
        f"- Status: `{smoke['status']}`",
        f"- Release receipt status: `{smoke['release_receipt_status']}`",
        f"- Release receipt blockers: `{smoke['release_receipt_blockers']}`",
        f"- Release receipt warnings: `{smoke['release_receipt_warnings']}`",
        f"- Release receipt artifacts: `{smoke['release_receipt_artifacts']}`",
        f"- Privacy scope: `{smoke['privacy_scope']}`",
        "",
        "## Blockers",
        "",
    ]
    blockers = smoke["blockers"]
    if blockers:
        lines.extend(f"- {item}" for item in blockers)
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings", ""])
    warnings = smoke["warnings"]
    if warnings:
        lines.extend(f"- {item}" for item in warnings)
    else:
        lines.append("- None.")
    lines.extend(["", "## Operator guidance", ""])
    lines.extend(f"- {item}" for item in smoke["operator_guidance"])
    lines.extend(
        [
            "",
            "## Safe automation boundary",
            "",
            "This helper is passive summary validation only and performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes.",
            "",
            "## Rollback",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in smoke["rollback_guidance"])
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot release receipt smoke evidence.")
    parser.add_argument("--input", default="/var/log/firstboot_release_gate.final_readiness_release_receipt.summary.env")
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero when smoke status is review.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    smoke = build_smoke(parse_summary(pathlib.Path(args.input)))
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(smoke), encoding="utf-8")
    else:
        output.write_text(json.dumps(smoke, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), smoke)
    if args.require_pass and smoke["status"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
