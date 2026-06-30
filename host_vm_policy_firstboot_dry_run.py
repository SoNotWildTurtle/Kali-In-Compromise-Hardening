#!/usr/bin/env python3
# MINC - Passive firstboot dry-run wrapper; writes aggregate policy evidence only.
"""Generate passive Host/VM policy firstboot dry-run evidence.

This wrapper composes ``host_vm_policy_validator.py`` without changing host or VM
state. It is intended for firstboot-review, release-gate, and operator-handoff
workflows that need predictable aggregate artifacts before any live hardening
integration is considered.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from host_vm_policy_validator import (
    VALIDATOR_VERSION,
    _build_evidence,
    _build_manifest,
    _load_json,
    _to_markdown,
    validate_profile,
)

WRAPPER_NAME = "host_vm_policy_firstboot_dry_run.py"
WRAPPER_VERSION = "1.0.0"
DEFAULT_OUTPUT_DIR = Path("/var/log/kali-hardening/host-vm-policy")
TEST_OUTPUT_SENTINEL = "test-only"
FORBIDDEN_HANDOFF_KEYS = {
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


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_standard_output_dir(path: Path) -> bool:
    text = str(path)
    return text.startswith("/var/log/") or text.startswith("/var/lib/")


def _ensure_output_dir(path: Path, *, allow_test_output_dir: bool) -> None:
    if not _is_standard_output_dir(path) and not allow_test_output_dir:
        raise ValueError(
            "output directory must stay under /var/log or /var/lib unless "
            "--allow-test-output-dir is used for local tests"
        )
    path.mkdir(parents=True, exist_ok=True)


def _safe_required_artifacts(evidence: dict[str, Any]) -> list[str]:
    artifacts = evidence.get("summary", {}).get("required_artifacts", [])
    return [str(item) for item in artifacts if item]


def build_handoff(
    *,
    profile_path: Path,
    evidence: dict[str, Any],
    evidence_path: Path,
    manifest_path: Path,
    markdown_path: Path | None,
    output_dir: Path,
    allow_test_output_dir: bool,
) -> dict[str, Any]:
    """Return a privacy-safe firstboot handoff index for aggregate evidence."""
    generated_paths = {
        "validator_evidence_json": str(evidence_path),
        "firstboot_manifest_json": str(manifest_path),
    }
    if markdown_path is not None:
        generated_paths["operator_markdown"] = str(markdown_path)

    return {
        "handoff_schema_version": 1,
        "generated_at_utc": _utc_now(),
        "wrapper": WRAPPER_NAME,
        "wrapper_version": WRAPPER_VERSION,
        "validator": evidence.get("validator"),
        "validator_version": evidence.get("validator_version", VALIDATOR_VERSION),
        "profile": {
            "path": str(profile_path),
            "sha256": evidence.get("profile_sha256"),
            "policy_id": evidence.get("policy_id"),
            "mode": evidence.get("summary", {}).get("mode"),
        },
        "validation": {
            "valid": bool(evidence.get("valid")),
            "error_count": len(evidence.get("errors", [])),
            "errors": list(evidence.get("errors", [])),
        },
        "generated_artifacts": generated_paths,
        "required_artifacts": _safe_required_artifacts(evidence),
        "output_policy": {
            "directory": str(output_dir),
            "standard_runtime_location": _is_standard_output_dir(output_dir),
            "test_only_override": bool(allow_test_output_dir),
            "test_only_sentinel": TEST_OUTPUT_SENTINEL if allow_test_output_dir else None,
        },
        "safety": {
            "passive_only": True,
            "mutates_host_or_vm_state": False,
            "reads_raw_telemetry": False,
            "collects_credentials_or_secrets": False,
            "enables_persistence_or_remote_access": False,
            "writes_aggregate_evidence_only": True,
        },
        "privacy_boundaries": {
            "aggregate_only": evidence.get("summary", {}).get("aggregate_only"),
            "forbidden_handoff_keys": sorted(FORBIDDEN_HANDOFF_KEYS),
            "contains_raw_telemetry": False,
            "contains_secret_material": False,
        },
        "rollback": {
            "scope": "delete generated dry-run evidence files only",
            "live_state_rollback_required": False,
            "paths": list(generated_paths.values()),
        },
        "next_step": (
            "Review aggregate evidence and only wire packaging or firstboot execution "
            "after this dry-run evidence is green in CI and accepted by an operator."
        ),
    }


def run_dry_run(
    profile_path: Path,
    output_dir: Path,
    *,
    allow_test_output_dir: bool = False,
    write_markdown: bool = False,
) -> tuple[int, dict[str, Path]]:
    """Generate dry-run artifacts and return ``(exit_code, paths)``."""
    _ensure_output_dir(output_dir, allow_test_output_dir=allow_test_output_dir)

    profile, load_errors = _load_json(profile_path)
    errors = load_errors if load_errors else validate_profile(profile or {})
    evidence = _build_evidence(profile_path, profile, errors)

    evidence_path = output_dir / "host_vm_policy_validator_evidence.json"
    manifest_path = output_dir / "host_vm_policy_firstboot_manifest.json"
    handoff_path = output_dir / "host_vm_policy_firstboot_handoff.json"
    markdown_path = output_dir / "host_vm_policy_firstboot_evidence.md" if write_markdown else None

    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = _build_manifest(evidence, evidence_path, "json")
    manifest["firstboot_dry_run"] = {
        "wrapper": WRAPPER_NAME,
        "wrapper_version": WRAPPER_VERSION,
        "handoff_path": str(handoff_path),
        "passive_only": True,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    handoff = build_handoff(
        profile_path=profile_path,
        evidence=evidence,
        evidence_path=evidence_path,
        manifest_path=manifest_path,
        markdown_path=markdown_path,
        output_dir=output_dir,
        allow_test_output_dir=allow_test_output_dir,
    )
    handoff_path.write_text(json.dumps(handoff, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    paths = {
        "evidence": evidence_path,
        "manifest": manifest_path,
        "handoff": handoff_path,
    }
    if markdown_path is not None:
        markdown_path.write_text(_to_markdown(evidence), encoding="utf-8")
        paths["markdown"] = markdown_path

    return (0 if evidence.get("valid") else 2), paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate passive Host/VM firstboot dry-run evidence.")
    parser.add_argument("profile", type=Path, help="Path to a host/VM policy JSON profile")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for aggregate evidence files; defaults under /var/log",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Also write operator-friendly Markdown evidence next to JSON artifacts",
    )
    parser.add_argument(
        "--allow-test-output-dir",
        action="store_true",
        help="Permit non-/var/log and non-/var/lib output paths for local tests only",
    )
    args = parser.parse_args(argv)

    try:
        exit_code, paths = run_dry_run(
            args.profile,
            args.output_dir,
            allow_test_output_dir=args.allow_test_output_dir,
            write_markdown=args.markdown,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 64
    except OSError as exc:
        print(f"error: unable to write dry-run evidence: {exc}", file=sys.stderr)
        return 74

    for name, path in paths.items():
        print(f"{name}: {path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
