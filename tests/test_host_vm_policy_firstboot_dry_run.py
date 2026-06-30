import json
from pathlib import Path

import pytest

from host_vm_policy_firstboot_dry_run import main, run_dry_run


def _valid_profile(path: Path) -> Path:
    profile = {
        "schema_version": 1,
        "policy_id": "default_firstboot_review",
        "mode": "firstboot_release_gate",
        "authorization": {
            "authorized_defensive_use_only": True,
            "operator_acknowledgement_required": True,
            "remote_host_mutation_allowed": False,
        },
        "freshness": {
            "enabled": True,
            "max_artifact_age_minutes": 1440,
            "future_clock_skew_tolerance_seconds": 300,
        },
        "artifacts": [
            {
                "name": "firstboot_handoff_index_json",
                "path": "/var/log/host_vm_policy_firstboot_handoff.json",
                "required": True,
                "producer": "host_vm_policy_firstboot_dry_run.py",
            },
            {
                "name": "firstboot_manifest_json",
                "path": "/var/log/host_vm_policy_firstboot_manifest.json",
                "required": True,
                "producer": "host_vm_policy_firstboot_dry_run.py",
            },
        ],
        "privacy_boundaries": {
            "aggregate_only": True,
            "forbidden_fields": [
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
            ],
        },
        "rollback": {
            "revert_files_only": True,
            "live_state_rollback_required": False,
            "notes": "Delete generated dry-run evidence files only; no live host, VM, firewall, service, IDS, model, dataset, credential, or account state changes.",
        },
    }
    path.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return path


def test_dry_run_generates_required_aggregate_artifacts(tmp_path: Path) -> None:
    profile_path = _valid_profile(tmp_path / "profile.json")
    output_dir = tmp_path / "evidence"

    code, paths = run_dry_run(profile_path, output_dir, allow_test_output_dir=True, write_markdown=True)

    assert code == 0
    assert set(paths) == {"evidence", "manifest", "handoff", "markdown"}
    for path in paths.values():
        assert path.exists()

    handoff = json.loads(paths["handoff"].read_text(encoding="utf-8"))
    assert handoff["wrapper"] == "host_vm_policy_firstboot_dry_run.py"
    assert handoff["validation"]["valid"] is True
    assert handoff["safety"]["passive_only"] is True
    assert handoff["safety"]["mutates_host_or_vm_state"] is False
    assert handoff["safety"]["collects_credentials_or_secrets"] is False
    assert handoff["privacy_boundaries"]["contains_raw_telemetry"] is False
    assert handoff["privacy_boundaries"]["contains_secret_material"] is False
    assert handoff["rollback"]["live_state_rollback_required"] is False


def test_dry_run_writes_evidence_for_invalid_profiles(tmp_path: Path) -> None:
    profile_path = tmp_path / "invalid.json"
    profile_path.write_text('{"schema_version": 1}', encoding="utf-8")
    output_dir = tmp_path / "invalid-evidence"

    code, paths = run_dry_run(profile_path, output_dir, allow_test_output_dir=True)

    assert code == 2
    evidence = json.loads(paths["evidence"].read_text(encoding="utf-8"))
    handoff = json.loads(paths["handoff"].read_text(encoding="utf-8"))
    assert evidence["valid"] is False
    assert evidence["errors"]
    assert handoff["validation"]["valid"] is False
    assert handoff["validation"]["error_count"] == len(evidence["errors"])


def test_nonstandard_output_dir_requires_explicit_test_flag(tmp_path: Path) -> None:
    profile_path = _valid_profile(tmp_path / "profile.json")

    with pytest.raises(ValueError, match="output directory must stay under"):
        run_dry_run(profile_path, tmp_path / "not-runtime-safe")


def test_cli_returns_usage_error_for_nonstandard_output_dir(tmp_path: Path) -> None:
    profile_path = _valid_profile(tmp_path / "profile.json")

    code = main([str(profile_path), "--output-dir", str(tmp_path / "blocked")])

    assert code == 64


def test_handoff_does_not_embed_forbidden_raw_fields(tmp_path: Path) -> None:
    profile_path = _valid_profile(tmp_path / "profile.json")
    _, paths = run_dry_run(profile_path, tmp_path / "evidence", allow_test_output_dir=True)

    handoff_text = paths["handoff"].read_text(encoding="utf-8")
    handoff = json.loads(handoff_text)

    assert "default_firstboot_review" in handoff_text
    assert handoff["privacy_boundaries"]["forbidden_handoff_keys"]
    for forbidden in ("raw_logs", "packets", "credentials", "secrets", "tokens"):
        assert forbidden in handoff["privacy_boundaries"]["forbidden_handoff_keys"]
    assert "private_key_material" not in handoff_text
    assert "credential_value" not in handoff_text
