#!/usr/bin/env python3
"""Index passive firstboot release receipt smoke evidence for operators.

MINC - Defensive firstboot release receipt smoke index helper only. This script
reads aggregate `.summary.env` smoke evidence and writes JSON or Markdown index
evidence. It does not source shell content and does not change firewall, policy,
service, account, approval, restore, model, dataset, host, VM, or network state.
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
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE",
}
SUMMARY_RE = re.compile(r'^(FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_[A-Z0-9_]+)="([^"\\]*)"$')


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
            values.setdefault("_parse_warnings", "malformed smoke summary line ignored")
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


def build_index(values: Dict[str, str]) -> Dict[str, object]:
    blockers: List[str] = []
    warnings: List[str] = []

    if values.get("_load_error"):
        blockers.append(f"release receipt smoke summary could not be loaded: {values['_load_error']}")

    missing = sorted(REQUIRED_KEYS.difference(values))
    if missing:
        blockers.append("missing required release receipt smoke summary keys: " + ", ".join(missing))

    if values.get("_parse_warnings"):
        warnings.append(values["_parse_warnings"])

    smoke_status = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_STATUS", "unknown").lower()
    smoke_blockers = parse_non_negative_int(values, "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_BLOCKERS", blockers)
    smoke_warnings = parse_non_negative_int(values, "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_WARNINGS", blockers)
    privacy_scope = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_PRIVACY_SCOPE", "unknown")

    if smoke_status != "pass":
        blockers.append(f"release receipt smoke status is {smoke_status}")
    if smoke_blockers:
        blockers.append(f"release receipt smoke reports {smoke_blockers} blocker(s)")
    if privacy_scope != "aggregate_metadata_only":
        blockers.append(f"privacy scope is {privacy_scope}")
    if smoke_warnings:
        warnings.append(f"release receipt smoke reports {smoke_warnings} warning(s)")

    status = "pass" if not blockers else "review"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "source_path": values.get("_source_path"),
        "release_receipt_smoke_status": smoke_status,
        "release_receipt_smoke_blockers": smoke_blockers,
        "release_receipt_smoke_warnings": smoke_warnings,
        "privacy_scope": privacy_scope,
        "indexed_artifacts": [
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.json",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.md",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.summary.env",
        ],
        "blockers": blockers,
        "warnings": warnings,
        "safe_automation_boundary": "passive_smoke_index_only_no_host_vm_firewall_service_network_restore_or_model_changes",
        "operator_guidance": [
            "Treat review status as a release blocker until the release receipt smoke evidence is corrected.",
            "Use this index to locate aggregate smoke artifacts quickly during firstboot handoff.",
            "Approve promotion only after repository checks, review threads, branch protection, and stacked dependency order are satisfied.",
        ],
        "rollback_guidance": [
            "Remove the release receipt smoke index helper from build_custom_iso.sh.",
            "Remove the release receipt smoke index ExecStartPost lines from firstboot_release_gate.service.",
            "Delete generated /var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.* artifacts.",
            "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.",
        ],
    }


def write_summary(path: pathlib.Path, index: Dict[str, object]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_STATUS="{index["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_BLOCKERS="{len(index["blockers"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_WARNINGS="{len(index["warnings"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_ARTIFACTS="{len(index["indexed_artifacts"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_PRIVACY_SCOPE="{index["privacy_scope"]}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(index: Dict[str, object]) -> str:
    lines = [
        "# Firstboot Final Readiness Release Receipt Smoke Index",
        "",
        f"- Generated UTC: `{index['generated_utc']}`",
        f"- Status: `{index['status']}`",
        f"- Release receipt smoke status: `{index['release_receipt_smoke_status']}`",
        f"- Release receipt smoke blockers: `{index['release_receipt_smoke_blockers']}`",
        f"- Release receipt smoke warnings: `{index['release_receipt_smoke_warnings']}`",
        f"- Privacy scope: `{index['privacy_scope']}`",
        "",
        "## Indexed artifacts",
        "",
    ]
    lines.extend(f"- `{item}`" for item in index["indexed_artifacts"])
    lines.extend(["", "## Blockers", ""])
    blockers = index["blockers"]
    if blockers:
        lines.extend(f"- {item}" for item in blockers)
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings", ""])
    warnings = index["warnings"]
    if warnings:
        lines.extend(f"- {item}" for item in warnings)
    else:
        lines.append("- None.")
    lines.extend(["", "## Operator guidance", ""])
    lines.extend(f"- {item}" for item in index["operator_guidance"])
    lines.extend(
        [
            "",
            "## Safe automation boundary",
            "",
            "This helper is passive smoke indexing only and performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes.",
            "",
            "## Rollback",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in index["rollback_guidance"])
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot release receipt smoke index evidence.")
    parser.add_argument("--input", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.summary.env")
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero when index status is review.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    index = build_index(parse_summary(pathlib.Path(args.input)))
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(index), encoding="utf-8")
    else:
        output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), index)
    if args.require_pass and index["status"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
