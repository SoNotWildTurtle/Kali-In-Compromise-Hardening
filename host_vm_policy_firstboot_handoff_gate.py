#!/usr/bin/env python3
# MINC - Passive firstboot handoff release gate; validates aggregate JSON evidence only.
"""Validate Host/VM firstboot dry-run handoff evidence for release gates.

The gate consumes the aggregate handoff JSON emitted by
``host_vm_policy_firstboot_dry_run.py``. It never reads raw telemetry, secrets,
packet captures, models, datasets, hostnames, usernames, or live system state.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

GATE_NAME = "host_vm_policy_firstboot_handoff_gate.py"
GATE_VERSION = "1.0.0"
REQUIRED_ARTIFACT_KEYS = [
    "validator_evidence_json",
    "firstboot_manifest_json",
]
FORBIDDEN_PRESENT_KEYS = {
    "raw_logs",
    "packets",
    "captures",
    "credentials",
    "hostnames",
    "usernames",
    "secrets",
    "model_binaries",
    "datasets",
    "private_keys",
    "tokens",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, [f"handoff file is missing: {path}"]
    except json.JSONDecodeError as exc:
        return {}, [f"handoff JSON is invalid: {exc}"]
    if not isinstance(data, dict):
        return {}, ["handoff JSON root must be an object"]
    return data, []


def add_check(checks: list[dict[str, str]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if passed else "fail", "detail": detail})


def nested_bool(data: dict[str, Any], keys: list[str]) -> Optional[bool]:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    if isinstance(current, bool):
        return current
    return None


def artifact_path(base_dir: Path, value: Any) -> Optional[Path]:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return path


def check_artifacts(
    handoff: dict[str, Any],
    checks: list[dict[str, str]],
    *,
    base_dir: Path,
    require_files: bool,
) -> None:
    artifacts = handoff.get("generated_artifacts")
    add_check(
        checks,
        "generated_artifacts_object",
        isinstance(artifacts, dict),
        "generated_artifacts must be an object containing aggregate artifact paths",
    )
    if not isinstance(artifacts, dict):
        return

    for key in REQUIRED_ARTIFACT_KEYS:
        path = artifact_path(base_dir, artifacts.get(key))
        add_check(checks, f"artifact_key:{key}", path is not None, f"required artifact key {key} is present")
        if path is not None and require_files:
            add_check(checks, f"artifact_exists:{key}", path.is_file(), f"required aggregate artifact exists at {path}")


def evaluate(
    handoff_path: Path,
    *,
    require_files: bool = True,
    allow_invalid_profile: bool = False,
) -> dict[str, Any]:
    handoff, load_errors = load_json(handoff_path)
    checks: list[dict[str, str]] = []
    for error in load_errors:
        add_check(checks, "load_handoff", False, error)

    base_dir = handoff_path.parent
    if not load_errors:
        add_check(checks, "schema_version", handoff.get("handoff_schema_version") == 1, "handoff schema version must be 1")
        add_check(checks, "wrapper_name", handoff.get("wrapper") == "host_vm_policy_firstboot_dry_run.py", "handoff must come from the passive dry-run wrapper")
        validation_valid = nested_bool(handoff, ["validation", "valid"])
        add_check(
            checks,
            "validation_valid",
            validation_valid is True or allow_invalid_profile,
            "profile validation must be green for release promotion unless explicitly reviewing invalid evidence",
        )
        add_check(checks, "safety_passive_only", nested_bool(handoff, ["safety", "passive_only"]) is True, "handoff must mark the workflow passive-only")
        add_check(checks, "safety_no_mutation", nested_bool(handoff, ["safety", "mutates_host_or_vm_state"]) is False, "handoff must not mutate host or VM state")
        add_check(checks, "safety_no_secret_collection", nested_bool(handoff, ["safety", "collects_credentials_or_secrets"]) is False, "handoff must not collect credentials or secrets")
        add_check(checks, "safety_no_persistence", nested_bool(handoff, ["safety", "enables_persistence_or_remote_access"]) is False, "handoff must not enable persistence or remote access")
        add_check(checks, "privacy_no_raw_telemetry", nested_bool(handoff, ["privacy_boundaries", "contains_raw_telemetry"]) is False, "handoff must not contain raw telemetry")
        add_check(checks, "privacy_no_secret_material", nested_bool(handoff, ["privacy_boundaries", "contains_secret_material"]) is False, "handoff must not contain secret material")
        add_check(checks, "rollback_no_live_state", nested_bool(handoff, ["rollback", "live_state_rollback_required"]) is False, "rollback must not require live-state changes")

        forbidden = handoff.get("privacy_boundaries", {}).get("forbidden_handoff_keys", [])
        forbidden_set = {str(item) for item in forbidden} if isinstance(forbidden, list) else set()
        add_check(
            checks,
            "privacy_forbidden_keys_declared",
            FORBIDDEN_PRESENT_KEYS.issubset(forbidden_set),
            "handoff declares forbidden raw/secret/material key boundaries",
        )
        handoff_text = json.dumps(handoff, sort_keys=True)
        for marker in ("private_key_material", "credential_value", "packet_capture_bytes", "raw_event_payload"):
            add_check(checks, f"forbidden_marker_absent:{marker}", marker not in handoff_text, f"handoff omits forbidden marker {marker}")
        check_artifacts(handoff, checks, base_dir=base_dir, require_files=require_files)

    failed = [item for item in checks if item["status"] != "pass"]
    return {
        "schema_version": 1,
        "gate": GATE_NAME,
        "gate_version": GATE_VERSION,
        "created_utc": utc_now(),
        "handoff_path": str(handoff_path),
        "decision": "release_ready" if not failed else "release_blocked",
        "changes_live_state": False,
        "reads_raw_telemetry": False,
        "checks_passed": len(checks) - len(failed),
        "checks_failed": len(failed),
        "checks": checks,
    }


def write_outputs(result: dict[str, Any], output: Optional[Path], report: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"created_utc={result['created_utc']}",
            f"decision={result['decision']}",
            f"changes_live_state={result['changes_live_state']}",
            f"reads_raw_telemetry={result['reads_raw_telemetry']}",
            f"checks_passed={result['checks_passed']}",
            f"checks_failed={result['checks_failed']}",
        ]
        for item in result["checks"]:
            if item["status"] != "pass":
                lines.append(f"issue={item['name']}|{item['detail']}")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate passive firstboot handoff evidence for release promotion.")
    parser.add_argument("handoff", type=Path, help="Path to host_vm_policy_firstboot_handoff.json")
    parser.add_argument("--output", type=Path, help="optional JSON gate evidence path")
    parser.add_argument("--report", type=Path, help="optional compact report path")
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless the handoff is release-ready")
    parser.add_argument("--no-require-files", action="store_true", help="skip local existence checks for referenced artifacts")
    parser.add_argument("--allow-invalid-profile", action="store_true", help="review invalid-profile evidence without making validation.valid a blocker")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    result = evaluate(
        args.handoff,
        require_files=not args.no_require_files,
        allow_invalid_profile=args.allow_invalid_profile,
    )
    write_outputs(result, args.output, args.report)
    print(json.dumps({"decision": result["decision"], "checks_failed": result["checks_failed"]}, sort_keys=True))
    if args.strict and result["decision"] != "release_ready":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
