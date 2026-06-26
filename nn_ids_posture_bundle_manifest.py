#!/usr/bin/env python3
"""Build a privacy-safe NN IDS posture bundle manifest.

MINC - Defensive validation only. This utility reads local JSON evidence files
produced by the NN IDS health, drift, and triage helpers, then emits a compact
manifest for release gates and operator handoff. It never opens network sockets,
executes commands, changes firewall state, or modifies host/VM configuration.
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


def _artifact_entry(
    name: str,
    path: Path,
    payload: Mapping[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    exists = path.exists()
    return {
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


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    artifact_specs = [
        ("health_evidence", Path(args.health_evidence)),
        ("drift_evidence", Path(args.drift_evidence)),
        ("drift_triage", Path(args.drift_triage)),
    ]

    artifacts: list[dict[str, Any]] = []
    failing_controls: set[str] = set()
    warning_controls: set[str] = set()
    status = "pass"

    for name, path in artifact_specs:
        payload, error = _load_json(path)
        entry = _artifact_entry(name, path, payload, error)
        artifacts.append(entry)
        status = _worse(status, entry["status"])
        if error:
            failing_controls.add(f"nn_ids.posture_bundle.{name}.present")
        failing_controls.update(_collect_controls(payload, "failing_controls"))
        warning_controls.update(_collect_controls(payload, "warning_controls"))

    release_gate = {
        "status": status,
        "ok": status == "pass",
        "required_artifacts": [entry["name"] for entry in artifacts],
        "promotion_blockers": sorted(failing_controls),
        "promotion_warnings": sorted(warning_controls),
        "message": (
            "Promotion is blocked until all required NN IDS evidence artifacts "
            "exist and report pass."
            if status == "fail"
            else "NN IDS posture evidence is available for release review."
        ),
    }

    return {
        "component": "nn_ids_posture_bundle_manifest",
        "schema_version": 1,
        "generated_at": utc_now(),
        "status": status,
        "ok": status == "pass",
        "message": (
            "Posture bundle manifest is passive and privacy-safe; it records "
            "file hashes and aggregate statuses only."
        ),
        "artifacts": artifacts,
        "summary": {
            "health_status": artifacts[0]["status"],
            "drift_status": artifacts[1]["status"],
            "triage_status": artifacts[2]["status"],
            "artifact_count": len(artifacts),
            "present_artifacts": sum(1 for entry in artifacts if entry["exists"]),
            "missing_artifacts": [entry["name"] for entry in artifacts if not entry["exists"]],
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
        help="Path to write the manifest JSON; use '-' for stdout.",
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
