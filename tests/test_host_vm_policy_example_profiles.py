# MINC - Regression coverage for checked-in passive Host/VM policy example profiles.
import json
import subprocess
import sys
from pathlib import Path


VALIDATOR_PATH = Path("host_vm_policy_validator.py")
EXAMPLE_DIR = Path("examples")
DOC_PATH = Path("docs/host_vm_policy_validator_cli.md")
CHANGELOG_PATH = Path("docs/changelog_host_vm_policy_example_profiles.md")
EXAMPLE_PROFILE_NAMES = {
    "host_vm_policy_default_review.json",
    "host_vm_policy_strict_review.json",
    "host_vm_policy_recovery_handoff.json",
}


def run_validator(profile_path: Path, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), str(profile_path), *extra_args],
        check=False,
        text=True,
        capture_output=True,
    )


def example_profile_paths() -> list[Path]:
    return sorted(EXAMPLE_DIR / name for name in EXAMPLE_PROFILE_NAMES)


def test_checked_in_example_profiles_are_valid_and_passive() -> None:
    assert {path.name for path in example_profile_paths()} == EXAMPLE_PROFILE_NAMES

    for profile_path in example_profile_paths():
        result = run_validator(profile_path)
        assert result.returncode == 0, result.stdout + result.stderr
        evidence = json.loads(result.stdout)
        assert evidence["valid"] is True
        assert evidence["summary"]["remote_host_mutation_allowed"] is False
        assert evidence["summary"]["aggregate_only"] is True
        assert evidence["safety"]["passive_only"] is True
        assert evidence["safety"]["mutates_host_or_vm_state"] is False
        assert evidence["safety"]["reads_raw_telemetry"] is False
        assert evidence["safety"]["emits_aggregate_review_evidence"] is True


def test_example_profiles_preserve_privacy_and_file_only_rollback_contract() -> None:
    required_forbidden_fields = {
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

    for profile_path in example_profile_paths():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        assert profile["authorization"]["authorized_defensive_use_only"] is True
        assert profile["authorization"]["operator_acknowledgement_required"] is True
        assert profile["authorization"]["remote_host_mutation_allowed"] is False
        assert profile["privacy_boundaries"]["aggregate_only"] is True
        assert set(profile["privacy_boundaries"]["forbidden_fields"]) == required_forbidden_fields
        assert profile["rollback"]["revert_files_only"] is True
        assert profile["rollback"]["live_state_rollback_required"] is False
        assert len(profile["rollback"]["notes"]) >= 20
        for artifact in profile["artifacts"]:
            assert artifact["path"].startswith(("/var/log/", "/var/lib/"))


def test_example_profiles_cover_default_strict_and_recovery_workflows() -> None:
    profiles = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in example_profile_paths()
    }

    assert profiles["host_vm_policy_default_review.json"]["policy_id"] == "default_firstboot_review"
    assert profiles["host_vm_policy_default_review.json"]["freshness"]["max_artifact_age_minutes"] == 1440
    assert profiles["host_vm_policy_strict_review.json"]["policy_id"] == "strict_review"
    assert profiles["host_vm_policy_strict_review.json"]["freshness"]["max_artifact_age_minutes"] == 60
    assert profiles["host_vm_policy_recovery_handoff.json"]["policy_id"] == "recovery_handoff"
    assert profiles["host_vm_policy_recovery_handoff.json"]["mode"] == "operator_handoff"
    assert profiles["host_vm_policy_recovery_handoff.json"]["freshness"]["max_artifact_age_minutes"] == 10080


def test_example_profile_docs_and_changelog_are_traceable() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8")
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    for name in EXAMPLE_PROFILE_NAMES:
        assert name in doc
        assert name in changelog
    assert "python3 host_vm_policy_validator.py examples/host_vm_policy_default_review.json" in doc
    assert "--format markdown" in doc
    assert "file-only rollback" in changelog
    assert "no live host or VM state" in changelog
