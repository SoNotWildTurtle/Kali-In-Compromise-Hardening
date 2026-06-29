#!/usr/bin/env python3
"""Build a passive operator bundle index from firstboot readiness smoke evidence.

MINC - Defensive evidence helper only. This script reads a summary.env file
produced by the firstboot operator-bundle smoke gate and writes review-only
JSON or Markdown that helps an operator find the final readiness artifacts.
It does not change firewall, policy, service, account, or network state.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shlex
import sys
from datetime import datetime, timezone
from typing import Dict, Iterable, List

DEFAULT_ARTIFACTS = [
    "/var/log/firstboot_release_gate.json",
    "/var/log/firstboot_release_gate.md",
    "/var/log/firstboot_release_gate.status.json",
    "/var/log/firstboot_release_gate.bundle_manifest.json",
    "/var/log/firstboot_release_gate.operator_digest.json",
    "/var/log/firstboot_release_gate.handoff_index.json",
    "/var/log/firstboot_release_gate.handoff_verify.json",
    "/var/log/firstboot_release_gate.handoff_freshness.json",
    "/var/log/firstboot_release_gate.handoff_env_policy.json",
    "/var/log/firstboot_release_gate.final_readiness.json",
    "/var/log/firstboot_release_gate.final_readiness_manifest.json",
    "/var/log/firstboot_release_gate.final_readiness_contract_seal.json",
    "/var/log/firstboot_release_gate.final_readiness_operator_verdict.json",
    "/var/log/firstboot_release_gate.final_readiness_operator_bundle.json",
    "/var/log/firstboot_release_gate.final_readiness_operator_bundle_smoke.json",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_env(path: pathlib.Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError:
            parsed = [value.strip().strip('"')]
        values[key.strip()] = parsed[0] if parsed else ""
    return values


def artifact_status(paths: Iterable[str]) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    for item in paths:
        path = pathlib.Path(item)
        try:
            stat = path.stat()
            present = path.is_file()
            size = stat.st_size if present else 0
            mtime = datetime.fromtimestamp(stat.st_mtime, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") if present else None
        except OSError:
            present = False
            size = 0
            mtime = None
        records.append({"path": item, "present": present, "size_bytes": size, "modified_utc": mtime})
    return records


def build_index(summary: Dict[str, str], artifact_paths: Iterable[str]) -> Dict[str, object]:
    artifacts = artifact_status(artifact_paths)
    missing = [record["path"] for record in artifacts if not record["present"]]
    zero_byte = [record["path"] for record in artifacts if record["present"] and record["size_bytes"] == 0]
    upstream_status = summary.get("FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_SMOKE_STATUS", "unknown")
    status = "pass" if upstream_status == "pass" and not missing and not zero_byte else "review"
    return {
        "schema_version": "1.0",
        "generated_utc": utc_now(),
        "status": status,
        "upstream_smoke_status": upstream_status,
        "upstream_summary": summary,
        "artifact_count": len(artifacts),
        "missing_artifacts": missing,
        "zero_byte_artifacts": zero_byte,
        "artifacts": artifacts,
        "operator_guidance": [
            "Review this index before promoting the image or firstboot bundle.",
            "Treat missing or zero-byte artifacts as review blockers, not auto-repair triggers.",
            "This helper is passive and intentionally performs no policy, firewall, service, or network changes.",
        ],
    }


def write_summary(path: pathlib.Path, index: Dict[str, object]) -> None:
    lines = [
        f'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_INDEX_STATUS="{index["status"]}"',
        f'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_INDEX_ARTIFACTS="{index["artifact_count"]}"',
        f'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_INDEX_MISSING="{len(index["missing_artifacts"])}"',
        f'FIRSTBOOT_FINAL_READINESS_OPERATOR_BUNDLE_INDEX_ZERO_BYTE="{len(index["zero_byte_artifacts"])}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def to_markdown(index: Dict[str, object]) -> str:
    lines = [
        "# Firstboot Final Readiness Operator Bundle Index",
        "",
        f"- Generated UTC: `{index['generated_utc']}`",
        f"- Status: `{index['status']}`",
        f"- Upstream smoke status: `{index['upstream_smoke_status']}`",
        f"- Artifact count: `{index['artifact_count']}`",
        f"- Missing artifacts: `{len(index['missing_artifacts'])}`",
        f"- Zero-byte artifacts: `{len(index['zero_byte_artifacts'])}`",
        "",
        "## Artifact inventory",
        "",
        "| Artifact | Present | Size bytes | Modified UTC |",
        "| --- | --- | ---: | --- |",
    ]
    for record in index["artifacts"]:
        lines.append(
            f"| `{record['path']}` | `{record['present']}` | `{record['size_bytes']}` | `{record['modified_utc'] or ''}` |"
        )
    lines.extend(["", "## Operator guidance", ""])
    for item in index["operator_guidance"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write passive firstboot operator bundle index evidence.")
    parser.add_argument("--input", default="/var/log/firstboot_release_gate.final_readiness_operator_bundle_smoke.summary.env")
    parser.add_argument("--output", default="/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.json")
    parser.add_argument("--summary", default="/var/log/firstboot_release_gate.final_readiness_operator_bundle_index.summary.env")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--artifact", action="append", default=[], help="Additional artifact path to include in the index.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = parse_env(pathlib.Path(args.input))
    index = build_index(summary, [*DEFAULT_ARTIFACTS, *args.artifact])
    output = pathlib.Path(args.output)
    if args.format == "markdown":
        output.write_text(to_markdown(index), encoding="utf-8")
    else:
        output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_summary(pathlib.Path(args.summary), index)
    return 0


if __name__ == "__main__":
    sys.exit(main())
