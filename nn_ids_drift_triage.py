#!/usr/bin/env python3
"""Render passive NN IDS drift evidence into operator triage artifacts.

MINC - Defensive validation only. This utility reads JSON drift evidence that was
already produced by nn_ids_drift_evidence.py and turns it into privacy-safe
Markdown or compact JSON handoff material. It never opens network sockets,
executes remote commands, changes firewall state, or modifies host/VM config.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

STATUS_ORDER = {"pass": 0, "warn": 1, "fail": 2}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_evidence(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return payload


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _status(value: Any) -> str:
    status = str(value or "fail").lower()
    return status if status in STATUS_ORDER else "fail"


def _sort_features(features: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(
        features,
        key=lambda item: (-STATUS_ORDER.get(_status(item.get("status")), 2), str(item.get("feature", ""))),
    )


def _format_number(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "n/a"


def build_triage(evidence: Mapping[str, Any], max_actions: int) -> dict[str, Any]:
    features = [item for item in _as_list(evidence.get("features")) if isinstance(item, Mapping)]
    sorted_features = _sort_features(features)
    failed = [item for item in sorted_features if _status(item.get("status")) == "fail"]
    warned = [item for item in sorted_features if _status(item.get("status")) == "warn"]
    passed = [item for item in sorted_features if _status(item.get("status")) == "pass"]

    actions: list[str] = []
    for item in failed[:max_actions]:
        feature = item.get("feature", "unknown")
        actions.append(
            f"Pause promotion and inspect recent capture/training inputs for `{feature}` before retraining or release."
        )
    for item in warned[: max(0, max_actions - len(actions))]:
        feature = item.get("feature", "unknown")
        actions.append(f"Track `{feature}` in the next health window and compare against a fresh baseline.")
    if not actions:
        actions.append("No immediate drift action required; keep routine evidence collection enabled.")

    status = _status(evidence.get("status"))
    return {
        "component": "nn_ids_drift_triage",
        "generated_at": utc_now(),
        "source_component": evidence.get("component", "nn_ids_drift"),
        "source_generated_at": evidence.get("generated_at"),
        "status": status,
        "ok": status == "pass",
        "summary": {
            "failed_features": len(failed),
            "warning_features": len(warned),
            "passing_features": len(passed),
            "total_features": len(sorted_features),
        },
        "recommended_actions": actions,
        "privacy_note": "Triage is derived from aggregate feature statistics only; it contains no packets, payloads, credentials, or host secrets.",
        "rollback": "Remove generated triage files and continue using raw nn_ids_drift_evidence.py JSON evidence.",
        "features": [
            {
                "feature": item.get("feature", "unknown"),
                "status": _status(item.get("status")),
                "psi": item.get("psi"),
                "mean_shift_sigma": item.get("mean_shift_sigma"),
                "missing_rate_delta": item.get("missing_rate_delta"),
                "messages": [str(message) for message in _as_list(item.get("messages"))],
            }
            for item in sorted_features
        ],
    }


def render_markdown(triage: Mapping[str, Any]) -> str:
    summary = triage.get("summary") if isinstance(triage.get("summary"), Mapping) else {}
    actions = [str(action) for action in _as_list(triage.get("recommended_actions"))]
    features = [item for item in _as_list(triage.get("features")) if isinstance(item, Mapping)]

    lines = [
        "# NN IDS Drift Triage",
        "",
        f"- Status: `{triage.get('status', 'unknown')}`",
        f"- Generated: `{triage.get('generated_at', 'unknown')}`",
        f"- Source evidence: `{triage.get('source_component', 'unknown')}` at `{triage.get('source_generated_at', 'unknown')}`",
        f"- Failed features: {summary.get('failed_features', 0)}",
        f"- Warning features: {summary.get('warning_features', 0)}",
        f"- Passing features: {summary.get('passing_features', 0)}",
        "",
        "## Recommended actions",
        "",
    ]
    lines.extend(f"- {action}" for action in actions)
    lines.extend(
        [
            "",
            "## Feature evidence",
            "",
            "| Feature | Status | PSI | Mean shift σ | Missing delta | Notes |",
            "| --- | --- | ---: | ---: | ---: | --- |",
        ]
    )
    for item in features:
        messages = "; ".join(str(message).replace("|", "\\|") for message in _as_list(item.get("messages")))
        lines.append(
            "| "
            f"{item.get('feature', 'unknown')} | "
            f"{_status(item.get('status'))} | "
            f"{_format_number(item.get('psi'))} | "
            f"{_format_number(item.get('mean_shift_sigma'))} | "
            f"{_format_number(item.get('missing_rate_delta'))} | "
            f"{messages or 'n/a'} |"
        )
    lines.extend(
        [
            "",
            "## Privacy and rollback",
            "",
            f"- Privacy: {triage.get('privacy_note')}",
            f"- Rollback: {triage.get('rollback')}",
        ]
    )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render NN IDS drift evidence into operator triage artifacts.")
    parser.add_argument("--evidence", required=True, help="JSON output from nn_ids_drift_evidence.py.")
    parser.add_argument("--output", help="Optional path for rendered output; defaults to stdout.")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--max-actions", type=int, default=5, help="Maximum feature-specific recommended actions.")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the source evidence passes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.max_actions < 1:
        print("nn_ids_drift_triage error: --max-actions must be at least 1", file=sys.stderr)
        return 2
    try:
        evidence = _load_evidence(Path(args.evidence))
        triage = build_triage(evidence, args.max_actions)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"nn_ids_drift_triage error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps(triage, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_markdown(triage)

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if not args.require_pass or triage.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
