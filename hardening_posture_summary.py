#!/usr/bin/env python3
"""Aggregate defensive Kali hardening component health into one posture report.

This tool is intentionally passive. It reads local JSON status documents from
channel-policy evidence summaries, IDS health checks, resource monitors, time
sync checks, port monitors, snapshot checks, or other defensive modules and
emits a compact pass/warn/fail posture report for CI and operator review. It
never opens network sockets, never executes remote commands, and never modifies
host or VM state.
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

PASS_STATES = {"ok", "pass", "passed", "success", "healthy", "green"}
WARN_STATES = {"warn", "warning", "degraded", "partial", "amber", "yellow"}
FAIL_STATES = {"fail", "failed", "error", "critical", "blocked", "red", "unhealthy"}
DEFAULT_COMPONENT = "unknown"


@dataclass(frozen=True)
class ComponentStatus:
    path: str
    component: str
    status: str
    ok: bool
    warning: bool
    message: str
    failing_controls: tuple[str, ...]
    warning_controls: tuple[str, ...]


def _load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return payload


def _normalize_state(value: Any) -> str:
    if isinstance(value, bool):
        return "pass" if value else "fail"
    if value is None:
        return "unknown"
    state = str(value).strip().lower()
    if state in PASS_STATES:
        return "pass"
    if state in WARN_STATES:
        return "warn"
    if state in FAIL_STATES:
        return "fail"
    return state or "unknown"


def _controls_from_sequence(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(str(value) for value in values if value is not None and str(value).strip())


def _controls_from_findings(findings: Any, desired: str) -> tuple[str, ...]:
    if not isinstance(findings, list):
        return ()
    controls: list[str] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            level = "fail"
            control = f"finding[{index}]"
        else:
            level = _normalize_state(
                finding.get("level")
                or finding.get("severity")
                or finding.get("status")
                or finding.get("ok")
            )
            control = str(
                finding.get("control")
                or finding.get("field")
                or finding.get("name")
                or finding.get("id")
                or finding.get("message")
                or f"finding[{index}]"
            )
        if level == desired:
            controls.append(control)
    return tuple(controls)


def _derive_component(path: str, payload: dict[str, Any]) -> str:
    for key in ("component", "name", "module", "check"):
        value = payload.get(key)
        if value:
            return str(value)
    basename = os.path.basename(path)
    stem, _dot, _suffix = basename.partition(".")
    return stem or DEFAULT_COMPONENT


def _derive_status(payload: dict[str, Any]) -> tuple[str, bool, bool]:
    raw_status = payload.get("status") or payload.get("state") or payload.get("result")
    status = _normalize_state(raw_status)
    if status == "unknown" and "ok" in payload:
        status = _normalize_state(payload.get("ok"))

    failing_controls = _controls_from_sequence(payload.get("failing_controls")) or _controls_from_findings(
        payload.get("findings"), "fail"
    )
    warning_controls = _controls_from_sequence(payload.get("warning_controls")) or _controls_from_findings(
        payload.get("findings"), "warn"
    )

    if status == "unknown":
        status = "fail" if failing_controls else "warn" if warning_controls else "pass"

    ok = status == "pass" and not failing_controls
    warning = status == "warn" or bool(warning_controls)
    if failing_controls:
        ok = False
        status = "fail"
    elif warning and status == "pass":
        status = "warn"
    return status, ok, warning


def summarize_component(path: str) -> ComponentStatus:
    payload = _load_json(path)
    status, ok, warning = _derive_status(payload)
    failing_controls = _controls_from_sequence(payload.get("failing_controls")) or _controls_from_findings(
        payload.get("findings"), "fail"
    )
    warning_controls = _controls_from_sequence(payload.get("warning_controls")) or _controls_from_findings(
        payload.get("findings"), "warn"
    )
    message = str(payload.get("message") or payload.get("summary") or "")
    return ComponentStatus(
        path=path,
        component=_derive_component(path, payload),
        status=status,
        ok=ok,
        warning=warning,
        message=message,
        failing_controls=failing_controls,
        warning_controls=warning_controls,
    )


def expand_inputs(patterns: Iterable[str]) -> list[str]:
    paths: list[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        paths.extend(matches or [pattern])
    return sorted(dict.fromkeys(paths))


def _safe_summarize(paths: list[str]) -> tuple[list[ComponentStatus], list[str]]:
    components: list[ComponentStatus] = []
    errors: list[str] = []
    for path in paths:
        try:
            components.append(summarize_component(path))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(str(exc))
    return components, errors


def posture_state(components: list[ComponentStatus]) -> str:
    if not components:
        return "fail"
    if any(not component.ok for component in components):
        return "fail"
    if any(component.warning for component in components):
        return "warn"
    return "pass"


def render_json(components: list[ComponentStatus]) -> str:
    state = posture_state(components)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": state == "pass",
        "status": state,
        "component_count": len(components),
        "components": [
            {
                "path": component.path,
                "component": component.component,
                "status": component.status,
                "ok": component.ok,
                "warning": component.warning,
                "message": component.message,
                "failing_controls": list(component.failing_controls),
                "warning_controls": list(component.warning_controls),
            }
            for component in components
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_text(components: list[ComponentStatus]) -> str:
    lines = ["Kali hardening posture summary", ""]
    if not components:
        lines.append("No component health files were provided.")
        return "\n".join(lines)

    state = posture_state(components).upper()
    lines.append(f"Overall status: {state}")
    lines.append(f"Components: {len(components)}")
    lines.append("")
    for component in components:
        lines.append(f"- {component.component} ({component.path}): {component.status.upper()}")
        if component.message:
            lines.append(f"  message: {component.message}")
        if component.failing_controls:
            lines.append("  failing controls: " + ", ".join(component.failing_controls))
        if component.warning_controls:
            lines.append("  warning controls: " + ", ".join(component.warning_controls))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Aggregate defensive Kali hardening component health into one posture report."
    )
    parser.add_argument(
        "health_files",
        nargs="+",
        help="One or more local JSON health files or shell glob patterns.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable posture summary.")
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Exit non-zero unless every component reports a clean pass.",
    )
    args = parser.parse_args(argv)

    paths = expand_inputs(args.health_files)
    missing = [path for path in paths if not os.path.exists(path)]
    if missing:
        print("Missing health file(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    components, errors = _safe_summarize(paths)
    if errors:
        for error in errors:
            print(f"Posture summary error: {error}", file=sys.stderr)
        return 2

    print(render_json(components) if args.json else render_text(components))

    if args.require_pass and posture_state(components) != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
