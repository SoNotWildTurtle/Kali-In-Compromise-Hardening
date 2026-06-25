#!/usr/bin/env python3
"""Summarize host/VM channel-policy JSON evidence artifacts.

This reader is intentionally passive: it reads JSON produced by
host_vm_channel_policy.py --json and emits a compact status summary for CI,
dashboards, and operator review. It never opens network sockets and never
modifies host or VM state.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable


@dataclass(frozen=True)
class EvidenceSummary:
    path: str
    ok: bool
    pass_count: int
    fail_count: int
    warn_count: int
    finding_count: int
    failing_controls: tuple[str, ...]
    warning_controls: tuple[str, ...]


def _load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return payload


def _finding_level(finding: Any) -> str:
    if not isinstance(finding, dict):
        return "fail"
    raw = finding.get("level") or finding.get("severity") or finding.get("status")
    if raw is None:
        return "pass" if finding.get("ok") is True else "fail"
    value = str(raw).strip().lower()
    if value in {"ok", "passed", "success"}:
        return "pass"
    if value in {"warn", "warning"}:
        return "warn"
    if value in {"fail", "failed", "error", "critical"}:
        return "fail"
    return value


def _finding_control(finding: Any, index: int) -> str:
    if not isinstance(finding, dict):
        return f"finding[{index}]"
    for key in ("control", "field", "name", "id", "message"):
        value = finding.get(key)
        if value:
            return str(value)
    return f"finding[{index}]"


def summarize_evidence(path: str) -> EvidenceSummary:
    payload = _load_json(path)
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError(f"{path}: findings must be a list")

    pass_count = 0
    fail_count = 0
    warn_count = 0
    failing_controls: list[str] = []
    warning_controls: list[str] = []

    for index, finding in enumerate(findings):
        level = _finding_level(finding)
        control = _finding_control(finding, index)
        if level == "pass":
            pass_count += 1
        elif level == "warn":
            warn_count += 1
            warning_controls.append(control)
        else:
            fail_count += 1
            failing_controls.append(control)

    reported_ok = payload.get("ok")
    ok = bool(reported_ok) and fail_count == 0 if isinstance(reported_ok, bool) else fail_count == 0

    return EvidenceSummary(
        path=path,
        ok=ok,
        pass_count=pass_count,
        fail_count=fail_count,
        warn_count=warn_count,
        finding_count=len(findings),
        failing_controls=tuple(failing_controls),
        warning_controls=tuple(warning_controls),
    )


def expand_inputs(patterns: Iterable[str]) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        paths.extend(matches or [pattern])
    return sorted(dict.fromkeys(paths))


def render_text(summaries: list[EvidenceSummary]) -> str:
    lines = ["Host/VM channel policy evidence summary", ""]
    if not summaries:
        lines.append("No evidence files were provided.")
        return "\n".join(lines)

    overall_ok = all(summary.ok for summary in summaries)
    lines.append(f"Overall status: {'PASS' if overall_ok else 'FAIL'}")
    lines.append(f"Evidence files: {len(summaries)}")
    lines.append("")

    for summary in summaries:
        lines.append(f"- {summary.path}: {'PASS' if summary.ok else 'FAIL'}")
        lines.append(
            "  findings: "
            f"{summary.finding_count} total, "
            f"{summary.pass_count} pass, "
            f"{summary.warn_count} warn, "
            f"{summary.fail_count} fail"
        )
        if summary.failing_controls:
            lines.append("  failing controls: " + ", ".join(summary.failing_controls))
        if summary.warning_controls:
            lines.append("  warning controls: " + ", ".join(summary.warning_controls))

    return "\n".join(lines)


def render_json(summaries: list[EvidenceSummary]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": all(summary.ok for summary in summaries) if summaries else False,
        "evidence_files": [
            {
                "path": summary.path,
                "ok": summary.ok,
                "finding_count": summary.finding_count,
                "pass_count": summary.pass_count,
                "warn_count": summary.warn_count,
                "fail_count": summary.fail_count,
                "failing_controls": list(summary.failing_controls),
                "warning_controls": list(summary.warning_controls),
            }
            for summary in summaries
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize host/VM channel-policy JSON evidence artifacts."
    )
    parser.add_argument(
        "evidence",
        nargs="+",
        help="One or more JSON evidence files or shell glob patterns.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable aggregate JSON summary.",
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Exit non-zero when any evidence file fails or no files are provided.",
    )
    args = parser.parse_args(argv)

    paths = expand_inputs(args.evidence)
    missing = [path for path in paths if not os.path.exists(path)]
    if missing:
        print("Missing evidence file(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    summaries = [summarize_evidence(path) for path in paths]
    print(render_json(summaries) if args.json else render_text(summaries))

    if args.require_pass and (not summaries or not all(summary.ok for summary in summaries)):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
