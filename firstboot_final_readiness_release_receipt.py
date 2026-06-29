#!/usr/bin/env python3
"""Build a passive firstboot release receipt from operator bundle index evidence.

MINC - Defensive release-gate evidence helper only. This script reads the
aggregate firstboot operator-bundle index JSON and writes review-only JSON or
Markdown. It does not change firewall, policy, service, account, approval,
restore, model, dataset, host, VM, or network state.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List


PASS_STATUSES = {"pass", "approved", "ready"}
REVIEW_STATUSES = {"review", "deferred", "fail", "failed", "error", "unknown", ""}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: pathlib.Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"_load_error": str(exc), "_source_path": str(path)}
    if not isinstance(payload, dict):
        return {"_load_error": "top-level JSON value is not an object", "_source_path": str(path)}
    payload.setdefault("_source_path", str(path))
    return payload


def summarize_artifacts(index: Dict[str, Any]) -> Dict[str, int]:
    artifacts = index.get("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []
    present = 0
    missing = 0
    zero_byte = 0
    for item in artifacts:
        if not isinstance(item, dict):
            continue
        if item.get("present") is True:
            present += 1
            try:
                if int(item.get("size_bytes", 0)) == 0:
                    zero_byte += 1
            except (TypeError, ValueError):
                zero_byte += 1
        else:
            missing += 1
    return {"total": len(artifacts), "present": present, "missing": missing, "zero_byte": zero_byte}


def build_receipt(index: Dict[str, Any]) -> Dict[str, Any]:
    blockers: List[str] = []
    warnings: List[str] = []

    if index.get("_load_error"):
        blockers.append(f"operator bundle index could not be loaded: {index['_load_error']}")

    index_status = str(index.get("status", "unknown")).lower()
    upstream_status = str(index.get("upstream_smoke_status", "unknown")).lower()
    if index_status not in PASS_STATUSES:
        blockers.append(f"operator bundle index status is {index_status}")
    if upstream_status and upstream_status not in PASS_STATUSES:
        blockers.append(f"operator bundle smoke status is {upstream_status}")

    missing = index.get("missing_artifacts", [])
    if isinstance(missing, list) and missing:
        blockers.append(f"{len(missing)} expected firstboot artifact(s) are missing")
    zero_byte = index.get("zero_byte_artifacts", [])
    if isinstance(zero_byte, list) and zero_byte:
        blockers.append(f"{len(zero_byte)} expected firstboot artifact(s) are zero-byte")

    counts = summarize_artifacts(index)
    if counts["total"] == 0:
        blockers.append("operator bundle index did not include an artifact inventory")
    if counts["present"] and counts["missing"]:
        warnings.append("partial evidence bundle is present but incomplete")

    status = "approved" if not blockers else "deferred"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "source_path": index.get("_source_path"),
        "operator_bundle_index_status": index_status,
        "operator_bundle_smoke_status": upstream_status,
        "artifact_counts": counts,
        "blockers": blockers,
        "warnings": warnings,
        "approval_scope": "firstboot_release_evidence_only",
        "privacy_scope": "aggregate_metadata_only",
        "operator_guidance": [
            "Approve promotion only when this receipt is approved and required repository checks are green.",
            "Treat deferred receipts as review blockers, not auto-repair triggers.",
            "Review upstream JSON/Markdown evidence before merging, publishing, or promoting an image.",
        ],
        "safe_automation_boundary": "passive_review_only_no_host_vm_firewall_service_network_restore_or_model_changes",
        "rollback_guidance": [
            "Remove the release receipt helper from build_custom_iso.sh.",
            "Remove the release receipt ExecStartPost lines from firstboot_release_gate.service.",
            "Delete generated /var/log/firstboot_release_gate.final_readiness_release_receipt.* artifacts.",
            "No live firewall, service, host, VM, IDS, approval, restore, model, or dataset state requires rollback.",
        ],
    }


def write_summary(path: pathlib.Path, receipt: Dict[str, Any]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_STATUS="{receipt["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_BLOCKERS="{len(receipt["blockers"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_WARNINGS="{len(receipt["warnings"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_ARTIFACTS="{receipt["artifact_counts"]["total"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_PRIVACY_SCOPE="{receipt["privacy_scope"]}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(receipt: Dict[str, Any]) -> str:
    counts = receipt["artifact_counts"]
    lines = [
        "# Firstboot Final Readiness Release Receipt",
        "",
        f"- Generated UTC: `{receipt['generated_utc']}`",
        f"- Status: `{receipt['status']}`",
        f"- Operator bundle index status: `{receipt['operator_bundle_index_status']}`",
        f"- Operator bundle smoke status: `{receipt['operator_bundle_smoke_status']}`",
        f"- Artifact inventory: `{counts['present']}` present / `{counts['missing']}` missing / `{counts['zero_byte']}` zero-byte / `{counts['total']}` total",
        f"- Privacy scope: `{receipt['privacy_scope']}`",
        f"- Approval scope: `{receipt['approval_scope']}`",
        "",
        "## Blockers",
        "",
    ]
    if receipt["blockers"]:
        lines.extend(f"- {item}" for item in receipt["blockers"])
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings", ""])
    if receipt["warnings"]:
        lines.extend(f"- {item}" for item in receipt["warnings"])
    else:
        lines.append("- None.")
    lines.extend(["", "## Operator guidance", ""])
    lines.extend(f"- {item}" for item in receipt["operator_guidance"])
    lines.extend(["", "## Safe automation boundary", "", "This helper is passive and performs no policy, firewall, service, restore, model, dataset, host, VM, or network changes.", "", "## Rollback", ""])
    lines.extend(f"- {item}" for item in receipt["rollback_guidance"])
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot final-readiness release receipt evidence.")
    parser.add_argument("--input", default="/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.json")
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_release_receipt.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_release_receipt.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-approved", action="store_true", help="Exit non-zero when the receipt is deferred.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = build_receipt(load_json(pathlib.Path(args.input)))
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(receipt), encoding="utf-8")
    else:
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), receipt)
    if args.require_approved and receipt["status"] != "approved":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
