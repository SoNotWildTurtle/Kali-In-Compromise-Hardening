# MINC - Regression coverage for passive host/VM policy validation CLI evidence.
import hashlib
import json
import subprocess
import sys
from pathlib import Path


VALIDATOR_PATH = Path("host_vm_policy_validator.py")
DOC_PATH = Path("docs/host_vm_policy_validator_cli.md")
CHANGELOG_PATH = Path("docs/changelog_host_vm_policy_validator_cli.md")
MANIFEST_CHANGELOG_PATH = Path("docs/changelog_host_vm_policy_manifest_evidence.md")


def valid_profile() -> dict:
    return {
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
                "producer": "host_vm_policy_firstboot_handoff.py",
            }
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
            "notes": "Revert policy profile files only; no live host, VM, firewall, service, IDS, credential, or account state changes are required.",
        },
    }


def run_validator(profile_path: Path, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATOR_PATH), str(profile_path), *extra_args],
        check=False,
        text=True,
        capture_output=True,
    )


def test_validator_accepts_valid_profile_and_emits_passive_json_evidence(tmp_path: Path) -> None:
    profile_path = tmp_path / "valid_policy.json"
    profile_path.write_text(json.dumps(valid_profile()), encoding="utf-8")

    result = run_validator(profile_path)

    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["valid"] is True
    assert evidence["policy_id"] == "default_firstboot_review"
    assert evidence["validator_version"] == "1.1.0"
    assert evidence["profile_sha256"] == hashlib.sha256(profile_path.read_bytes()).hexdigest()
    assert evidence["summary"]["remote_host_mutation_allowed"] is False
    assert evidence["summary"]["aggregate_only"] is True
    assert evidence["safety"] == {
        "passive_only": True,
        "mutates_host_or_vm_state": False,
        "reads_raw_telemetry": False,
        "emits_aggregate_review_evidence": True,
    }


def test_validator_rejects_unsafe_mutation_and_privacy_profile(tmp_path: Path) -> None:
    profile = valid_profile()
    profile["authorization"]["remote_host_mutation_allowed"] = True
    profile["privacy_boundaries"]["aggregate_only"] = False
    profile["privacy_boundaries"]["forbidden_fields"] = ["raw_logs", "packets", "captures"]
    profile["artifacts"][0]["path"] = "/home/alex/raw_capture.pcap"
    profile_path = tmp_path / "unsafe_policy.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    result = run_validator(profile_path)

    assert result.returncode == 2
    evidence = json.loads(result.stdout)
    errors = "\n".join(evidence["errors"])
    assert "remote_host_mutation_allowed must be false" in errors
    assert "aggregate_only must be true" in errors
    assert "forbidden_fields must contain at least 8 entries" in errors
    assert "path must stay under /var/log or /var/lib" in errors
    assert evidence["safety"]["mutates_host_or_vm_state"] is False


def test_validator_markdown_output_and_file_write_are_operator_friendly(tmp_path: Path) -> None:
    profile_path = tmp_path / "valid_policy.json"
    output_path = tmp_path / "evidence.md"
    profile_path.write_text(json.dumps(valid_profile()), encoding="utf-8")

    result = run_validator(profile_path, "--format", "markdown", "--output", str(output_path))

    assert result.returncode == 0
    assert result.stdout == ""
    markdown = output_path.read_text(encoding="utf-8")
    assert "# Host/VM Policy Validation: PASS" in markdown
    assert "Profile SHA-256" in markdown
    assert "Passive only: `True`" in markdown
    assert "Mutates host or VM state: `False`" in markdown
    assert "firstboot_handoff_index_json" in markdown


def test_validator_manifest_output_records_hash_evidence_path_and_handoff(tmp_path: Path) -> None:
    profile_path = tmp_path / "valid_policy.json"
    evidence_path = tmp_path / "evidence.json"
    manifest_path = tmp_path / "manifest.json"
    profile_path.write_text(json.dumps(valid_profile(), sort_keys=True), encoding="utf-8")

    result = run_validator(
        profile_path,
        "--output",
        str(evidence_path),
        "--manifest-output",
        str(manifest_path),
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_hash = hashlib.sha256(profile_path.read_bytes()).hexdigest()

    assert evidence["profile_sha256"] == expected_hash
    assert manifest["manifest_schema_version"] == 1
    assert manifest["validator"] == "host_vm_policy_validator.py"
    assert manifest["validator_version"] == evidence["validator_version"] == "1.1.0"
    assert manifest["profile_path"] == str(profile_path)
    assert manifest["profile_sha256"] == expected_hash
    assert manifest["evidence"]["format"] == "json"
    assert manifest["evidence"]["path"] == str(evidence_path)
    assert manifest["evidence"]["aggregate_only"] is True
    assert manifest["safety"]["passive_only"] is True
    assert manifest["safety"]["mutates_host_or_vm_state"] is False
    assert manifest["safety"]["reads_raw_telemetry"] is False
    assert manifest["handoff"]["follow_up_owner"] == "operator"
    assert "no live host or VM state rollback" in manifest["handoff"]["rollback_scope"]


def test_validator_docs_and_changelog_describe_safe_usage() -> None:
    source = VALIDATOR_PATH.read_text(encoding="utf-8")
    doc = DOC_PATH.read_text(encoding="utf-8")
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")
    manifest_changelog = MANIFEST_CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "Passive host/VM policy profile validator" in source
    assert "standard library" in source
    assert "mutates_host_or_vm_state" in source
    assert "reads_raw_telemetry" in source
    assert "--manifest-output" in source
    assert "host_vm_policy_validator.py" in doc
    assert "python3 host_vm_policy_validator.py examples/host_vm_policy_default_review.json" in doc
    assert "profile_sha256" in doc
    assert "does not mutate host or VM state" in doc
    assert "Rollback" in doc
    assert "host_vm_policy_validator.py" in changelog
    assert "No service, timer, firstboot hook, firewall rule, network interface" in changelog
    assert "manifest" in manifest_changelog
    assert "profile SHA-256" in manifest_changelog
