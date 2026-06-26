#!/usr/bin/env python3
"""Build a privacy-safe NN IDS posture bundle manifest.

MINC - Defensive validation only. This utility reads local JSON evidence files
produced by the NN IDS health, drift, and triage helpers, then emits a compact
manifest for release gates and operator handoff. It is read-only and does not
modify services, networking, model artifacts, or host/VM configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

DEFAULT_HEALTH_EVIDENCE = Path("/var/log/nn_ids_health_evidence.json")
DEFAULT_DRIFT_EVIDENCE = Path("/var/log/nn_ids_drift_evidence.json")
DEFAULT_DRIFT_TRIAGE = Path("/var/log/nn_ids_drift_triage.json")
DEFAULT_OUTPUT = Path("/var/log/nn_ids_posture_bundle_manifest.json")
STATUS_RANK = {"pass": 0, "warn": 1, "fail": 2, "missing": 2}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _status(value: Any) -> str:
    status = str(value or "missing").lower()
    return status if status in STATUS_RANK else "fail"


def _worse(left: str, right: str) -> str:
    return left if STATUS_RANK.get(left, 2) >= STATUS_RANK.get(right, 2) else right


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"missing evidence file: {path}"
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable evidence file {path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"{path}: expected top-level JSON object"
    return payload, None


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _collect_controls(payload: Mapping[str, Any] | None, key: str) -> list[str]:
    if not payload:
        return []
    return sorted({str(item) for item in _as_list(payload.get(key))})


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _artifact_age_minutes(generated_at: Any, now: datetime) -> float | None:
    parsed = _parse_timestamp(generated_at)
    if parsed is None:
        return None
    return max(0.0, (now - parsed).total_seconds() / 60)


def _apply_freshness_gate(
    entry: dict[str, Any],
    max_age_minutes: float | None,
    now: datetime,
) -> tuple[str, str | None]:
    generated_at = entry.get("generated_at")
    age_minutes = _artifact_age_minutes(generated_at, now)
    entry["artifact_age_minutes"] = round(age_minutes, 2) if age_minutes is not None else None
    entry["freshness_status"] = "not_enforced"

    if max_age_minutes is None:
        return entry["status"], None

    entry["max_artifact_age_minutes"] = max_age_minutes
    if not entry.get("exists"):
        entry["freshness_status"] = "missing"
        return entry["status"], None
    if age_minutes is None:
        entry["freshness_status"] = "fail"
        return "fail", f"{entry['name']} missing parseable generated_at timestamp"
    if age_minutes > max_age_minutes:
        entry["freshness_status"] = "fail"
        return "fail", (
            f"{entry['name']} stale: {age_minutes:.2f} minutes old exceeds "
            f"{max_age_minutes:.2f} minute freshness window"
        )

    entry["freshness_status"] = "pass"
    return entry["status"], None


def _artifact_entry(
    name: str,
    path: Path,
    payload: Mapping[str, Any] | None,
    error: str | None,
    max_age_minutes: float | None,
    now: datetime,
) -> tuple[dict[str, Any], str | None]:
    exists = path.exists()
    entry = {
        "name": name,
        "path": str(path),
        "exists": exists,
        "sha256": _sha256(path) if exists else None,
        "component": payload.get("component") if payload else None,
        "generated_at": payload.get("generated_at") if payload else None,
        "status": _status(payload.get("status") if payload else "missing"),
        "ok": bool(payload.get("ok")) if payload else False,
        "error": error,
    }
    entry["status"], freshness_error = _apply_freshness_gate(entry, max_age_minutes, now)
    if freshness_error:
        entry["ok"] = False
        entry["error"] = freshness_error if not error else f"{error}; {freshness_error}"
    return entry, freshness_error


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    artifact_specs = [
        ("health_evidence", Path(args.health_evidence)),
        ("drift_evidence", Path(args.drift_evidence)),
        ("drift_triage", Path(args.drift_triage)),
    ]

    max_age_minutes = args.max_artifact_age_minutes
    generated_now = datetime.now(timezone.utc)
    artifacts: list[dict[str, Any]] = []
    failing_controls: set[str] = set()
    warning_controls: set[str] = set()
    status = "pass"

    for name, path in artifact_specs:
        payload, error = _load_json(path)
        entry, freshness_error = _artifact_entry(
            name=name,
            path=path,
            payload=payload,
            error=error,
            max_age_minutes=max_age_minutes,
            now=generated_now,
        )
        artifacts.append(entry)
        status = _worse(status, entry["status"])
        if error:
            failing_controls.add(f"nn_ids.posture_bundle.{name}.present")
        if freshness_error:
            failing_controls.add(f"nn_ids.posture_bundle.{name}.fresh")
        failing_controls.update(_collect_controls(payload, "failing_controls"))
        warning_controls.update(_collect_controls(payload, "warning_controls"))

    aggregate_status = "fail" if status == "missing" else status
    release_gate = {
        "status": aggregate_status,
        "ok": aggregate_status == "pass",
        "required_artifacts": [entry["name"] for entry in artifacts],
        "promotion_blockers": sorted(failing_controls),
        "promotion_warnings": sorted(warning_controls),
        "freshness_policy": {
            "enforced": max_age_minutes is not None,
            "max_artifact_age_minutes": max_age_minutes,
        },
        "message": (
            "Promotion is blocked until all required NN IDS evidence artifacts "
            "exist, are fresh when a freshness window is enforced, and report pass."
            if aggregate_status == "fail"
            else "NN IDS posture evidence is available for release review."
        ),
    }

    return {
        "component": "nn_ids_posture_bundle_manifest",
        "schema_version": 1,
        "generated_at": generated_now.isoformat(),
        "status": aggregate_status,
        "ok": aggregate_status == "pass",
        "message": (
            "Posture bundle manifest is passive and privacy-safe; it records "
            "file hashes, artifact freshness, and aggregate statuses only."
        ),
        "artifacts": artifacts,
        "summary": {
            "health_status": artifacts[0]["status"],
            "drift_status": artifacts[1]["status"],
            "triage_status": artifacts[2]["status"],
            "artifact_count": len(artifacts),
            "present_artifacts": sum(1 for entry in artifacts if entry["exists"]),
            "missing_artifacts": [entry["name"] for entry in artifacts if not entry["exists"]],
            "stale_artifacts": [
                entry["name"] for entry in artifacts if entry.get("freshness_status") == "fail"
            ],
            "failing_controls": sorted(failing_controls),
            "warning_controls": sorted(warning_controls),
        },
        "release_gate": release_gate,
        "privacy_note": (
            "The manifest does not embed packets, payloads, raw captures, "
            "credentials, hostnames, usernames, or secrets."
        ),
        "rollback": (
            "Delete the generated manifest and continue consuming the individual "
            "NN IDS health, drift, and triage evidence files."
        ),
    }


def _markdown_list(values: list[Any], empty: str) -> str:
    if not values:
        return f"- {empty}"
    return "\n".join(f"- `{value}`" for value in values)


def _short_digest(value: Any) -> str:
    if not value:
        return "n/a"
    return f"`{str(value)[:12]}`"


def render_markdown(manifest: Mapping[str, Any]) -> str:
    """Render a privacy-safe operator handoff report from a posture manifest."""
    artifacts = _as_list(manifest.get("artifacts"))
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    release_gate = (
        manifest.get("release_gate") if isinstance(manifest.get("release_gate"), dict) else {}
    )
    freshness_policy = (
        release_gate.get("freshness_policy")
        if isinstance(release_gate.get("freshness_policy"), dict)
        else {}
    )
    freshness_window = freshness_policy.get("max_artifact_age_minutes")
    freshness_text = (
        f"`{freshness_window}` minutes"
        if freshness_policy.get("enforced")
        else "`not enforced`"
    )
    status = str(manifest.get("status", "missing")).upper()
    ok = "yes" if manifest.get("ok") else "no"

    lines = [
        "# NN IDS posture bundle handoff",
        "",
        f"- Status: `{status}`",
        f"- Release gate ok: `{ok}`",
        f"- Freshness window: {freshness_text}",
        f"- Generated at: `{manifest.get('generated_at', 'unknown')}`",
        f"- Present artifacts: `{summary.get('present_artifacts', 0)}` / `{summary.get('artifact_count', len(artifacts))}`",
        "",
        "## Artifact summary",
        "",
        "| Artifact | Status | Freshness | Age minutes | Present | Component | Generated | SHA-256 |",
        "| --- | --- | --- | ---: | --- | --- | --- | --- |",
    ]

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        age = artifact.get("artifact_age_minutes")
        lines.append(
            "| {name} | `{status}` | `{freshness}` | `{age}` | `{present}` | `{component}` | `{generated}` | {sha} |".format(
                name=artifact.get("name", "unknown"),
                status=artifact.get("status", "missing"),
                freshness=artifact.get("freshness_status", "unknown"),
                age=age if age is not None else "n/a",
                present="yes" if artifact.get("exists") else "no",
                component=artifact.get("component") or "n/a",
                generated=artifact.get("generated_at") or "n/a",
                sha=_short_digest(artifact.get("sha256")),
            )
        )

    lines.extend(
        [
            "",
            "## Promotion blockers",
            "",
            _markdown_list(_as_list(release_gate.get("promotion_blockers")), "None."),
            "",
            "## Promotion warnings",
            "",
            _markdown_list(_as_list(release_gate.get("promotion_warnings")), "None."),
            "",
            "## Operator notes",
            "",
            f"- {release_gate.get('message', 'No release-gate message was provided.')}",
            f"- Privacy: {manifest.get('privacy_note', 'No privacy note was provided.')}",
            f"- Rollback: {manifest.get('rollback', 'No rollback note was provided.')}",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a passive NN IDS posture bundle manifest."
    )
    parser.add_argument(
        "--health-evidence",
        default=str(DEFAULT_HEALTH_EVIDENCE),
        help="JSON from nn_ids_health_evidence.py.",
    )
    parser.add_argument(
        "--drift-evidence",
        default=str(DEFAULT_DRIFT_EVIDENCE),
        help="JSON from nn_ids_drift_evidence.py.",
    )
    parser.add_argument(
        "--drift-triage",
        default=str(DEFAULT_DRIFT_TRIAGE),
        help="JSON from nn_ids_drift_triage.py --format json.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to write the manifest; use '-' for stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Render machine-readable JSON or a privacy-safe Markdown handoff.",
    )
    parser.add_argument(
        "--max-artifact-age-minutes",
        type=float,
        default=None,
        help=(
            "Optional release-gate freshness window. When set, evidence artifacts "
            "without parseable generated_at timestamps or older than this many "
            "minutes fail the posture gate."
        ),
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Exit non-zero unless every required artifact exists and passes.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(args)
    if args.format == "markdown":
        rendered = render_markdown(manifest)
    else:
        rendered = json.dumps(manifest, indent=2, sort_keys=True)
    if args.output == "-":
        print(rendered)
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.require_pass or manifest.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
