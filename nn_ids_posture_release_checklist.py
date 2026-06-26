#!/usr/bin/env python3
"""Render a privacy-safe NN IDS posture release checklist.

MINC - Defensive validation only. This utility reads the aggregate posture
manifest emitted by nn_ids_posture_bundle_manifest.py and emits an actionable
operator checklist for release, firstboot, and recovery handoffs. It is
read-only and does not inspect raw captures, packets, payloads, credentials, or
host-specific secrets.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

DEFAULT_MANIFEST = Path("/var/log/nn_ids_posture_bundle_manifest.json")
DEFAULT_OUTPUT = Path("/var/log/nn_ids_posture_release_checklist.md")
STATUS_RANK = {"pass": 0, "warn": 1, "fail": 2, "missing": 2, "unknown": 2}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _status(value: Any) -> str:
    normalized = str(value or "unknown").lower()
    return normalized if normalized in STATUS_RANK else "fail"


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"manifest not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"unable to read manifest {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"manifest {path} must be a top-level JSON object")
    return payload


def _artifact_lookup(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    artifacts: dict[str, Mapping[str, Any]] = {}
    for artifact in _as_list(manifest.get("artifacts")):
        if isinstance(artifact, dict):
            name = str(artifact.get("name") or "unknown")
            artifacts[name] = artifact
    return artifacts


def _item(
    item_id: str,
    title: str,
    status: str,
    evidence: str,
    action: str,
    required: bool = True,
) -> dict[str, Any]:
    normalized_status = _status(status)
    return {
        "id": item_id,
        "title": title,
        "status": normalized_status,
        "ok": normalized_status == "pass" or (normalized_status == "warn" and not required),
        "required": required,
        "evidence": evidence,
        "action": action,
    }


def build_checklist(manifest: Mapping[str, Any]) -> dict[str, Any]:
    release_gate = manifest.get("release_gate") if isinstance(manifest.get("release_gate"), dict) else {}
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    freshness_policy = (
        release_gate.get("freshness_policy")
        if isinstance(release_gate.get("freshness_policy"), dict)
        else {}
    )
    artifacts = _artifact_lookup(manifest)
    required_artifacts = [str(name) for name in _as_list(release_gate.get("required_artifacts"))]
    if not required_artifacts:
        required_artifacts = sorted(artifacts)

    checklist: list[dict[str, Any]] = []
    gate_status = _status(release_gate.get("status") or manifest.get("status"))
    blockers = [str(item) for item in _as_list(release_gate.get("promotion_blockers"))]
    warnings = [str(item) for item in _as_list(release_gate.get("promotion_warnings"))]
    checklist.append(
        _item(
            "release_gate.status",
            "Aggregate release gate reports pass",
            gate_status,
            f"status={gate_status}; blockers={len(blockers)}; warnings={len(warnings)}",
            "Resolve every promotion blocker and regenerate the posture manifest before release.",
        )
    )

    for name in required_artifacts:
        artifact = artifacts.get(name, {})
        present = bool(artifact.get("exists"))
        artifact_status = _status(artifact.get("status"))
        freshness_status = str(artifact.get("freshness_status") or "unknown")
        status = artifact_status
        if not present:
            status = "missing"
        elif freshness_policy.get("enforced") and freshness_status != "pass":
            status = "fail"
        checklist.append(
            _item(
                f"artifact.{name}",
                f"Required evidence artifact is present and acceptable: {name}",
                status,
                "present={present}; status={status}; freshness={freshness}; age_minutes={age}".format(
                    present="yes" if present else "no",
                    status=artifact_status,
                    freshness=freshness_status,
                    age=artifact.get("artifact_age_minutes", "n/a"),
                ),
                "Regenerate the named evidence artifact, then rebuild the posture bundle manifest.",
            )
        )

    checklist.append(
        _item(
            "privacy.aggregate_only",
            "Checklist remains privacy-safe and aggregate-only",
            "pass",
            "Consumes manifest metadata, control IDs, statuses, timestamps, and SHA-256 digests only.",
            "Do not attach raw packet captures, payloads, credentials, usernames, hostnames, or raw IDS logs to release notes.",
            required=False,
        )
    )

    if warnings:
        checklist.append(
            _item(
                "release_gate.warnings_reviewed",
                "Promotion warnings have named owners before release",
                "warn",
                ", ".join(warnings),
                "Assign each warning to an owner or document why it is acceptable for this release.",
                required=False,
            )
        )

    failed_required = [item["id"] for item in checklist if item["required"] and not item["ok"]]
    return {
        "component": "nn_ids_posture_release_checklist",
        "schema_version": 1,
        "source_component": manifest.get("component"),
        "source_generated_at": manifest.get("generated_at"),
        "status": "fail" if failed_required else ("warn" if warnings else "pass"),
        "ok": not failed_required,
        "summary": {
            "required_items": sum(1 for item in checklist if item["required"]),
            "failed_required_items": failed_required,
            "warning_count": len(warnings),
            "present_artifacts": summary.get("present_artifacts"),
            "artifact_count": summary.get("artifact_count"),
        },
        "checklist": checklist,
        "privacy_note": (
            "This checklist is generated from the aggregate posture manifest only; it does not embed raw packets, "
            "payloads, captures, credentials, hostnames, usernames, secrets, or raw IDS logs."
        ),
        "rollback": (
            "Stop generating this checklist and continue using nn_ids_posture_bundle_manifest.py JSON/Markdown output directly."
        ),
    }


def _checkbox(item: Mapping[str, Any]) -> str:
    if item.get("status") == "pass":
        return "[x]"
    if item.get("required"):
        return "[!]"
    return "[ ]"


def render_markdown(checklist: Mapping[str, Any]) -> str:
    summary = checklist.get("summary") if isinstance(checklist.get("summary"), dict) else {}
    lines = [
        "# NN IDS posture release checklist",
        "",
        f"- Status: `{str(checklist.get('status', 'unknown')).upper()}`",
        f"- Release ready: `{'yes' if checklist.get('ok') else 'no'}`",
        f"- Source generated at: `{checklist.get('source_generated_at') or 'unknown'}`",
        f"- Failed required items: `{len(_as_list(summary.get('failed_required_items')))}`",
        f"- Warnings: `{summary.get('warning_count', 0)}`",
        "",
        "## Checklist",
        "",
    ]
    for item in _as_list(checklist.get("checklist")):
        if not isinstance(item, dict):
            continue
        required = "required" if item.get("required") else "advisory"
        lines.extend(
            [
                f"- {_checkbox(item)} `{item.get('id', 'unknown')}` **{item.get('title', 'Untitled')}** ({required}, `{item.get('status', 'unknown')}`)",
                f"  - Evidence: {item.get('evidence', 'n/a')}",
                f"  - Action: {item.get('action', 'n/a')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Privacy and rollback",
            "",
            f"- Privacy: {checklist.get('privacy_note')}",
            f"- Rollback: {checklist.get('rollback')}",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render an actionable, privacy-safe NN IDS posture release checklist."
    )
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to JSON output from nn_ids_posture_bundle_manifest.py.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to write the checklist; use '-' for stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Render a human checklist or machine-readable JSON.",
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="Exit non-zero unless every required checklist item passes.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = _load_manifest(Path(args.manifest))
    checklist = build_checklist(manifest)
    rendered = (
        json.dumps(checklist, indent=2, sort_keys=True)
        if args.format == "json"
        else render_markdown(checklist)
    )
    if args.output == "-":
        print(rendered)
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.require_pass or checklist.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
