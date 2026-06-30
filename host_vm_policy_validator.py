#!/usr/bin/env python3
# MINC - Passive host/VM policy profile validator; reads files and emits review evidence only.
"""Validate passive host/VM policy profiles without mutating host or VM state.

The validator intentionally uses only the Python standard library so it can run in
minimal recovery, firstboot-review, or handoff environments. It implements the
repository's documented Host VM Policy Configuration schema contract and emits
machine-readable JSON or operator-friendly Markdown evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
VALIDATOR_VERSION = "1.1.0"
MANIFEST_SCHEMA_VERSION = 1
VALID_MODES = {"passive_review", "firstboot_release_gate", "operator_handoff"}
FORBIDDEN_FIELDS = {
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
POLICY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,80}$")
ARTIFACT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,100}$")
ARTIFACT_PATH_RE = re.compile(r"^/(var/log|var/lib)/[A-Za-z0-9._/-]+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _load_json(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, [f"profile not found: {path}"]
    except json.JSONDecodeError as exc:
        return None, [f"profile is not valid JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}"]
    if not isinstance(data, dict):
        return None, ["profile root must be a JSON object"]
    return data, []


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def validate_profile(profile: dict[str, Any]) -> list[str]:
    """Return deterministic validation errors for a host/VM policy profile."""
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "mode",
        "authorization",
        "freshness",
        "artifacts",
        "privacy_boundaries",
        "rollback",
    }
    extra = sorted(set(profile) - required)
    missing = sorted(required - set(profile))
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")
    if extra:
        errors.append(f"unsupported fields: {', '.join(extra)}")

    if profile.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version must be 1")
    policy_id = profile.get("policy_id")
    if not isinstance(policy_id, str) or not POLICY_ID_RE.match(policy_id):
        errors.append("policy_id must be lowercase, stable, and 3-81 characters")
    if profile.get("mode") not in VALID_MODES:
        errors.append("mode must be passive_review, firstboot_release_gate, or operator_handoff")

    authorization = profile.get("authorization")
    if not isinstance(authorization, dict):
        errors.append("authorization must be an object")
    else:
        if authorization.get("authorized_defensive_use_only") is not True:
            errors.append("authorization.authorized_defensive_use_only must be true")
        if authorization.get("operator_acknowledgement_required") is not True:
            errors.append("authorization.operator_acknowledgement_required must be true")
        if authorization.get("remote_host_mutation_allowed") is not False:
            errors.append("authorization.remote_host_mutation_allowed must be false for passive validation")
        unknown_auth = sorted(
            set(authorization)
            - {
                "authorized_defensive_use_only",
                "operator_acknowledgement_required",
                "remote_host_mutation_allowed",
            }
        )
        if unknown_auth:
            errors.append(f"authorization has unsupported fields: {', '.join(unknown_auth)}")

    freshness = profile.get("freshness")
    if not isinstance(freshness, dict):
        errors.append("freshness must be an object")
    else:
        enabled = freshness.get("enabled")
        max_age = freshness.get("max_artifact_age_minutes")
        skew = freshness.get("future_clock_skew_tolerance_seconds")
        if not _is_bool(enabled):
            errors.append("freshness.enabled must be a boolean")
        if enabled and not isinstance(max_age, (int, float)):
            errors.append("freshness.max_artifact_age_minutes must be numeric when freshness is enabled")
        if isinstance(max_age, (int, float)) and not (0 < max_age <= 10080):
            errors.append("freshness.max_artifact_age_minutes must be greater than 0 and at most 10080")
        if max_age is not None and not isinstance(max_age, (int, float)):
            errors.append("freshness.max_artifact_age_minutes must be numeric or null")
        if not isinstance(skew, int) or not (0 <= skew <= 3600):
            errors.append("freshness.future_clock_skew_tolerance_seconds must be an integer from 0 to 3600")

    artifacts = profile.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("artifacts must be a non-empty array")
    else:
        for index, artifact in enumerate(artifacts):
            prefix = f"artifacts[{index}]"
            if not isinstance(artifact, dict):
                errors.append(f"{prefix} must be an object")
                continue
            if not isinstance(artifact.get("name"), str) or not ARTIFACT_NAME_RE.match(artifact["name"]):
                errors.append(f"{prefix}.name must be a lowercase stable identifier")
            if not isinstance(artifact.get("path"), str) or not ARTIFACT_PATH_RE.match(artifact["path"]):
                errors.append(f"{prefix}.path must stay under /var/log or /var/lib")
            if not _is_bool(artifact.get("required")):
                errors.append(f"{prefix}.required must be a boolean")
            if not isinstance(artifact.get("producer"), str) or not (3 <= len(artifact["producer"]) <= 120):
                errors.append(f"{prefix}.producer must be 3-120 characters")
            unknown_artifact = sorted(set(artifact) - {"name", "path", "required", "producer"})
            if unknown_artifact:
                errors.append(f"{prefix} has unsupported fields: {', '.join(unknown_artifact)}")

    privacy = profile.get("privacy_boundaries")
    if not isinstance(privacy, dict):
        errors.append("privacy_boundaries must be an object")
    else:
        forbidden = privacy.get("forbidden_fields")
        if privacy.get("aggregate_only") is not True:
            errors.append("privacy_boundaries.aggregate_only must be true")
        if not isinstance(forbidden, list) or len(forbidden) < 8:
            errors.append("privacy_boundaries.forbidden_fields must contain at least 8 entries")
        else:
            unknown_forbidden = sorted(set(forbidden) - FORBIDDEN_FIELDS)
            if unknown_forbidden:
                errors.append(f"privacy_boundaries.forbidden_fields has unsupported entries: {', '.join(unknown_forbidden)}")
            if len(forbidden) != len(set(forbidden)):
                errors.append("privacy_boundaries.forbidden_fields must be unique")
            minimum_sensitive_fields = {"raw_logs", "packets", "credentials", "secrets", "tokens"}
            missing_sensitive_fields = sorted(minimum_sensitive_fields - set(forbidden))
            if missing_sensitive_fields:
                errors.append(
                    "privacy_boundaries.forbidden_fields missing required privacy exclusions: "
                    + ", ".join(missing_sensitive_fields)
                )

    rollback = profile.get("rollback")
    if not isinstance(rollback, dict):
        errors.append("rollback must be an object")
    else:
        if rollback.get("revert_files_only") is not True:
            errors.append("rollback.revert_files_only must be true")
        if rollback.get("live_state_rollback_required") is not False:
            errors.append("rollback.live_state_rollback_required must be false")
        notes = rollback.get("notes")
        if not isinstance(notes, str) or not (20 <= len(notes) <= 500):
            errors.append("rollback.notes must be 20-500 characters")

    return errors


def _build_evidence(profile_path: Path, profile: dict[str, Any] | None, errors: list[str]) -> dict[str, Any]:
    policy_id = profile.get("policy_id") if isinstance(profile, dict) else None
    artifacts = profile.get("artifacts", []) if isinstance(profile, dict) else []
    required_artifacts = [item.get("name") for item in artifacts if isinstance(item, dict) and item.get("required") is True]
    return {
        "validator": "host_vm_policy_validator.py",
        "validator_version": VALIDATOR_VERSION,
        "schema_version": SCHEMA_VERSION,
        "profile_path": str(profile_path),
        "profile_sha256": _sha256_file(profile_path),
        "policy_id": policy_id,
        "valid": not errors,
        "errors": errors,
        "summary": {
            "checked_at_utc": _utc_now(),
            "mode": profile.get("mode") if isinstance(profile, dict) else None,
            "required_artifacts": required_artifacts,
            "remote_host_mutation_allowed": (
                profile.get("authorization", {}).get("remote_host_mutation_allowed") if isinstance(profile, dict) else None
            ),
            "aggregate_only": (
                profile.get("privacy_boundaries", {}).get("aggregate_only") if isinstance(profile, dict) else None
            ),
        },
        "safety": {
            "passive_only": True,
            "mutates_host_or_vm_state": False,
            "reads_raw_telemetry": False,
            "emits_aggregate_review_evidence": True,
        },
    }


def _build_manifest(evidence: dict[str, Any], evidence_path: Path | None, evidence_format: str) -> dict[str, Any]:
    """Build a compact manifest that lets later gates tie evidence to a profile hash."""
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at_utc": _utc_now(),
        "validator": evidence["validator"],
        "validator_version": evidence["validator_version"],
        "profile_path": evidence["profile_path"],
        "profile_sha256": evidence["profile_sha256"],
        "policy_id": evidence.get("policy_id"),
        "mode": evidence["summary"].get("mode"),
        "valid": evidence["valid"],
        "evidence": {
            "format": evidence_format,
            "path": str(evidence_path) if evidence_path else "stdout",
            "aggregate_only": evidence["summary"].get("aggregate_only"),
            "required_artifacts": evidence["summary"].get("required_artifacts", []),
        },
        "safety": {
            "passive_only": True,
            "mutates_host_or_vm_state": False,
            "reads_raw_telemetry": False,
            "remote_host_mutation_allowed": evidence["summary"].get("remote_host_mutation_allowed"),
        },
        "handoff": {
            "follow_up_owner": "operator",
            "rollback_scope": "revert generated manifest/evidence files or checked-in docs only; no live host or VM state rollback",
            "next_step": "Feed this manifest into firstboot or release aggregation after the consuming gate has static coverage.",
        },
    }


def _to_markdown(evidence: dict[str, Any]) -> str:
    status = "PASS" if evidence["valid"] else "FAIL"
    lines = [
        f"# Host/VM Policy Validation: {status}",
        "",
        f"- Profile: `{evidence['profile_path']}`",
        f"- Profile SHA-256: `{evidence.get('profile_sha256')}`",
        f"- Policy ID: `{evidence.get('policy_id')}`",
        f"- Mode: `{evidence['summary'].get('mode')}`",
        f"- Passive only: `{evidence['safety']['passive_only']}`",
        f"- Mutates host or VM state: `{evidence['safety']['mutates_host_or_vm_state']}`",
        f"- Aggregate-only evidence: `{evidence['summary'].get('aggregate_only')}`",
        "",
        "## Errors",
    ]
    if evidence["errors"]:
        lines.extend(f"- {error}" for error in evidence["errors"])
    else:
        lines.append("- None")
    lines.extend(["", "## Required artifacts"])
    required_artifacts = evidence["summary"].get("required_artifacts") or []
    lines.extend(f"- `{artifact}`" for artifact in required_artifacts) if required_artifacts else lines.append("- None declared")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a passive host/VM policy profile.")
    parser.add_argument("profile", type=Path, help="Path to a host/VM policy JSON profile")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Evidence output format")
    parser.add_argument("--output", type=Path, help="Optional evidence output path")
    parser.add_argument(
        "--manifest-output",
        type=Path,
        help="Optional JSON manifest path recording validator version, profile hash, evidence path, and handoff notes",
    )
    args = parser.parse_args(argv)

    profile, load_errors = _load_json(args.profile)
    errors = load_errors if load_errors else validate_profile(profile or {})
    evidence = _build_evidence(args.profile, profile, errors)
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n" if args.format == "json" else _to_markdown(evidence)

    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    if args.manifest_output:
        manifest = _build_manifest(evidence, args.output, args.format)
        args.manifest_output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return 0 if evidence["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
