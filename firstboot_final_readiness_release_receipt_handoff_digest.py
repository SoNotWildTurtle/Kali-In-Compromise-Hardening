#!/usr/bin/env python3
"""Write a passive operator handoff digest for firstboot release receipt evidence.

MINC - Defensive firstboot release receipt handoff digest helper only. This script
reads aggregate `.summary.env` smoke-index evidence and writes JSON or Markdown
operator digest evidence. It does not source shell content and does not change
firewall, service, policy, approval, restore, host, VM, model, dataset, account,
or network state.
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
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_STATUS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_BLOCKERS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_WARNINGS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_ARTIFACTS",
    "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_PRIVACY_SCOPE",
}
SUMMARY_RE = re.compile(r'^(FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_[A-Z0-9_]+)="([^"\\]*)"$')
EXPECTED_PRIVACY_SCOPE = "aggregate_metadata_only"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_summary(path: pathlib.Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"_load_error": str(exc), "_source_path": str(path)}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = SUMMARY_RE.match(stripped)
        if match:
            values[match.group(1)] = match.group(2)
        else:
            values.setdefault("_parse_warnings", "malformed smoke-index summary line ignored")
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


def build_digest(values: Dict[str, str]) -> Dict[str, object]:
    blockers: List[str] = []
    warnings: List[str] = []

    if values.get("_load_error"):
        blockers.append(f"release receipt smoke-index summary could not be loaded: {values['_load_error']}")

    missing = sorted(REQUIRED_KEYS.difference(values))
    if missing:
        blockers.append("missing required release receipt smoke-index summary keys: " + ", ".join(missing))

    if values.get("_parse_warnings"):
        warnings.append(values["_parse_warnings"])

    index_status = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_STATUS", "unknown").lower()
    index_blockers = parse_non_negative_int(
        values,
        "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_BLOCKERS",
        blockers,
    )
    index_warnings = parse_non_negative_int(
        values,
        "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_WARNINGS",
        blockers,
    )
    artifact_count = parse_non_negative_int(
        values,
        "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_ARTIFACTS",
        blockers,
    )
    privacy_scope = values.get("FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_SMOKE_INDEX_PRIVACY_SCOPE", "unknown")

    if index_status != "pass":
        blockers.append(f"release receipt smoke-index status is {index_status}")
    if index_blockers:
        blockers.append(f"release receipt smoke-index reports {index_blockers} blocker(s)")
    if privacy_scope != EXPECTED_PRIVACY_SCOPE:
        blockers.append(f"privacy scope is {privacy_scope}")
    if artifact_count < 3:
        blockers.append(f"release receipt smoke-index reports only {artifact_count} indexed artifact(s)")
    if index_warnings:
        warnings.append(f"release receipt smoke-index reports {index_warnings} warning(s)")

    status = "pass" if not blockers else "review"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "source_path": values.get("_source_path"),
        "release_receipt_smoke_index_status": index_status,
        "release_receipt_smoke_index_blockers": index_blockers,
        "release_receipt_smoke_index_warnings": index_warnings,
        "release_receipt_smoke_index_artifacts": artifact_count,
        "privacy_scope": privacy_scope,
        "handoff_artifacts": [
            "/var/log/firstboot_release_gate.final_readiness_release_receipt.json",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt.md",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.json",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke.md",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.json",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.md",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.json",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.md",
            "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.summary.env",
        ],
        "promotion_checklist": [
            "Confirm repository checks are green for the final PR head SHA.",
            "Confirm no unresolved review threads or branch-protection blockers remain.",
            "Confirm stacked PR dependencies are merged or promoted in the documented order.",
            "Confirm firstboot release receipt, smoke, index, and digest artifacts are present for handoff.",
            "Confirm generated evidence remains aggregate-only before publishing or retaining it.",
        ],
        "blockers": blockers,
        "warnings": warnings,
        "safe_automation_boundary": "passive_handoff_digest_only_no_firewall_service_network_restore_or_model_changes",
        "rollback_guidance": [
            "Remove the handoff digest helper from build_custom_iso.sh.",
            "Remove the handoff digest ExecStartPost lines from firstboot_release_gate.service.",
            "Delete generated /var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.* artifacts.",
            "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.",
        ],
    }


def write_summary(path: pathlib.Path, digest: Dict[str, object]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_STATUS="{digest["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_BLOCKERS="{len(digest["blockers"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_WARNINGS="{len(digest["warnings"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_ARTIFACTS="{len(digest["handoff_artifacts"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_PRIVACY_SCOPE="{digest["privacy_scope"]}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(digest: Dict[str, object]) -> str:
    lines = [
        "# Firstboot Final Readiness Release Receipt Handoff Digest",
        "",
        f"- Generated UTC: `{digest['generated_utc']}`",
        f"- Status: `{digest['status']}`",
        f"- Smoke-index status: `{digest['release_receipt_smoke_index_status']}`",
        f"- Smoke-index blockers: `{digest['release_receipt_smoke_index_blockers']}`",
        f"- Smoke-index warnings: `{digest['release_receipt_smoke_index_warnings']}`",
        f"- Smoke-index artifacts: `{digest['release_receipt_smoke_index_artifacts']}`",
        f"- Privacy scope: `{digest['privacy_scope']}`",
        "",
        "## Handoff artifacts",
        "",
    ]
    lines.extend(f"- `{item}`" for item in digest["handoff_artifacts"])
    lines.extend(["", "## Promotion checklist", ""])
    lines.extend(f"- {item}" for item in digest["promotion_checklist"])
    lines.extend(["", "## Blockers", ""])
    blockers = digest["blockers"]
    if blockers:
        lines.extend(f"- {item}" for item in blockers)
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings", ""])
    warnings = digest["warnings"]
    if warnings:
        lines.extend(f"- {item}" for item in warnings)
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Safe automation boundary",
            "",
            "This helper is a passive handoff digest only and performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes.",
            "",
            "## Rollback",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in digest["rollback_guidance"])
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot release receipt handoff digest evidence.")
    parser.add_argument("--input", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_smoke_index.summary.env")
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero when digest status is review.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    digest = build_digest(parse_summary(pathlib.Path(args.input)))
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(digest), encoding="utf-8")
    else:
        output.write_text(json.dumps(digest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), digest)
    if args.require_pass and digest["status"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
