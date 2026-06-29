#!/usr/bin/env python3
"""Build a passive firstboot release promotion checkpoint.

MINC - Defensive firstboot release promotion checkpoint helper only.
This script reads aggregate `.summary.env` index evidence and writes JSON or
Markdown checkpoint evidence. It does not source shell content and does not
change firewall, service, policy, approval, restore, host, VM, model, dataset,
account, credential, or network state.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List

PREFIX = "FIRSTBOOT_FINAL_READINESS_RELEASE_RECEIPT_HANDOFF_DIGEST_SMOKE_INDEX"
REQUIRED_KEYS = {
    f"{PREFIX}_STATUS",
    f"{PREFIX}_BLOCKERS",
    f"{PREFIX}_WARNINGS",
    f"{PREFIX}_ARTIFACTS",
    f"{PREFIX}_PRIVACY_SCOPE",
}
SUMMARY_RE = re.compile(rf'^({PREFIX}_[A-Z0-9_]+)="([^"\\]*)"$')
EXPECTED_PRIVACY_SCOPE = "aggregate_metadata_only"
MIN_INDEX_ARTIFACTS = 3
DEFAULT_INPUT = "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_summary(path: pathlib.Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"_load_error": str(exc), "_source_path": str(path)}

    malformed = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        match = SUMMARY_RE.match(stripped)
        if match:
            values[match.group(1)] = match.group(2)
        else:
            malformed += 1
    if malformed:
        values["_parse_warnings"] = f"{malformed} malformed promotion checkpoint summary line(s) ignored"
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


def build_checkpoint(values: Dict[str, str]) -> Dict[str, object]:
    blockers: List[str] = []
    warnings: List[str] = []

    if values.get("_load_error"):
        blockers.append(f"handoff digest smoke index summary could not be loaded: {values['_load_error']}")

    missing = sorted(REQUIRED_KEYS.difference(values))
    if missing:
        blockers.append("missing required handoff digest smoke index summary keys: " + ", ".join(missing))

    if values.get("_parse_warnings"):
        warnings.append(values["_parse_warnings"])

    index_status = values.get(f"{PREFIX}_STATUS", "unknown").lower()
    index_blockers = parse_non_negative_int(values, f"{PREFIX}_BLOCKERS", blockers)
    index_warnings = parse_non_negative_int(values, f"{PREFIX}_WARNINGS", blockers)
    index_artifacts = parse_non_negative_int(values, f"{PREFIX}_ARTIFACTS", blockers)
    privacy_scope = values.get(f"{PREFIX}_PRIVACY_SCOPE", "unknown")

    if index_status != "pass":
        blockers.append(f"handoff digest smoke index status is {index_status}")
    if index_blockers:
        blockers.append(f"handoff digest smoke index reports {index_blockers} blocker(s)")
    if privacy_scope != EXPECTED_PRIVACY_SCOPE:
        blockers.append(f"privacy scope is {privacy_scope}")
    if index_artifacts < MIN_INDEX_ARTIFACTS:
        blockers.append(f"handoff digest smoke index reports only {index_artifacts} artifact(s)")
    if index_warnings:
        warnings.append(f"handoff digest smoke index reports {index_warnings} warning(s)")

    status = "ready" if not blockers else "hold"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "source": "firstboot_final_readiness_release_receipt_handoff_digest_smoke_index",
        "source_path": values.get("_source_path"),
        "input_summary_contract": sorted(REQUIRED_KEYS),
        "index_status": index_status,
        "index_blockers": index_blockers,
        "index_warnings": index_warnings,
        "index_artifacts": index_artifacts,
        "privacy_scope": privacy_scope,
        "decision_contract": {
            "ready_requires_index_status": "pass",
            "ready_requires_index_blockers": 0,
            "ready_requires_privacy_scope": EXPECTED_PRIVACY_SCOPE,
            "ready_requires_min_index_artifacts": MIN_INDEX_ARTIFACTS,
        },
        "promotion_artifacts": [
            {
                "name": "handoff_digest_smoke_index_json",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.json",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
            {
                "name": "handoff_digest_smoke_index_markdown",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.md",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
            {
                "name": "handoff_digest_smoke_index_summary",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_receipt_handoff_digest_smoke_index.summary.env",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
            {
                "name": "release_promotion_checkpoint_json",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.json",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
            {
                "name": "release_promotion_checkpoint_markdown",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.md",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
            {
                "name": "release_promotion_checkpoint_summary",
                "path": "/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.summary.env",
                "required": True,
                "privacy_scope": EXPECTED_PRIVACY_SCOPE,
            },
        ],
        "blockers": blockers,
        "warnings": warnings,
        "safe_automation_boundary": "passive_release_promotion_checkpoint_only_no_host_vm_firewall_service_network_restore_or_model_changes",
        "operator_guidance": [
            "Treat hold status as a release blocker until the upstream aggregate evidence is corrected.",
            "Use this checkpoint as the last passive firstboot handoff summary before ISO or branch promotion review.",
            "Do not treat this checkpoint as a substitute for required GitHub checks, review-thread resolution, branch protection, or stacked dependency verification.",
        ],
        "rollback_guidance": [
            "Remove firstboot_final_readiness_release_promotion_checkpoint.py from build_custom_iso.sh.",
            "Remove the release promotion checkpoint ExecStartPost lines from firstboot_release_gate.service.",
            "Delete generated /var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.* artifacts.",
            "No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback.",
        ],
    }


def write_summary(path: pathlib.Path, checkpoint: Dict[str, object]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_PROMOTION_CHECKPOINT_STATUS="{checkpoint["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_PROMOTION_CHECKPOINT_BLOCKERS="{len(checkpoint["blockers"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_PROMOTION_CHECKPOINT_WARNINGS="{len(checkpoint["warnings"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_PROMOTION_CHECKPOINT_ARTIFACTS="{len(checkpoint["promotion_artifacts"])}"',
        f'FIRSTBOOT_FINAL_READINESS_RELEASE_PROMOTION_CHECKPOINT_PRIVACY_SCOPE="{checkpoint["privacy_scope"]}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(checkpoint: Dict[str, object]) -> str:
    lines = [
        "# Firstboot Final Readiness Release Promotion Checkpoint",
        "",
        f"- Generated UTC: `{checkpoint['generated_utc']}`",
        f"- Status: `{checkpoint['status']}`",
        f"- Source: `{checkpoint['source']}`",
        f"- Index status: `{checkpoint['index_status']}`",
        f"- Index blockers: `{checkpoint['index_blockers']}`",
        f"- Index warnings: `{checkpoint['index_warnings']}`",
        f"- Index artifacts: `{checkpoint['index_artifacts']}`",
        f"- Privacy scope: `{checkpoint['privacy_scope']}`",
        "",
        "## Decision contract",
        "",
    ]
    for key, value in checkpoint["decision_contract"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Promotion artifacts", ""])
    for artifact in checkpoint["promotion_artifacts"]:
        lines.append(f"- `{artifact['name']}` -> `{artifact['path']}` (required: `{artifact['required']}`)")
    lines.extend(["", "## Input summary contract", ""])
    lines.extend(f"- `{item}`" for item in checkpoint["input_summary_contract"])
    lines.extend(["", "## Blockers", ""])
    if checkpoint["blockers"]:
        lines.extend(f"- {item}" for item in checkpoint["blockers"])
    else:
        lines.append("- None.")
    lines.extend(["", "## Warnings", ""])
    if checkpoint["warnings"]:
        lines.extend(f"- {item}" for item in checkpoint["warnings"])
    else:
        lines.append("- None.")
    lines.extend(["", "## Operator guidance", ""])
    lines.extend(f"- {item}" for item in checkpoint["operator_guidance"])
    lines.extend(
        [
            "",
            "## Safe automation boundary",
            "",
            "This checkpoint is passive aggregate-evidence validation only and performs no policy, firewall, service, restore, model, dataset, host, VM, account, credential, or network changes.",
            "",
            "## Rollback",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in checkpoint["rollback_guidance"])
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot release promotion checkpoint evidence.")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_release_promotion_checkpoint.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--require-ready", action="store_true", help="Exit non-zero when checkpoint status is hold.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    checkpoint = build_checkpoint(parse_summary(pathlib.Path(args.input)))
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(checkpoint), encoding="utf-8")
    else:
        output.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), checkpoint)
    if args.require_ready and checkpoint["status"] != "ready":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
