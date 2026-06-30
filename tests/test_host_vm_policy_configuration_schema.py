# MINC - Static validation for passive host/VM policy configuration schema evidence.
import json
from pathlib import Path


SCHEMA_PATH = Path("docs/host_vm_policy_configuration_schema.json")
DOC_PATH = Path("docs/host_vm_policy_configuration_schema.md")
CHANGELOG_PATH = Path("docs/changelog_host_vm_policy_configuration_schema.md")
ROADMAP_PATH = Path("docs/repository_module_roadmap.json")


def test_host_vm_policy_configuration_schema_contract() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "Host VM Policy Configuration"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False

    required = set(schema["required"])
    assert required == {
        "schema_version",
        "policy_id",
        "mode",
        "authorization",
        "freshness",
        "artifacts",
        "privacy_boundaries",
        "rollback",
    }

    properties = schema["properties"]
    assert properties["schema_version"]["const"] == 1
    assert properties["mode"]["enum"] == [
        "passive_review",
        "firstboot_release_gate",
        "operator_handoff",
    ]

    authorization = properties["authorization"]
    assert authorization["additionalProperties"] is False
    assert authorization["properties"]["authorized_defensive_use_only"]["const"] is True
    assert authorization["properties"]["operator_acknowledgement_required"]["const"] is True
    assert authorization["properties"]["remote_host_mutation_allowed"]["const"] is False

    freshness = properties["freshness"]["properties"]
    assert freshness["max_artifact_age_minutes"]["exclusiveMinimum"] == 0
    assert freshness["max_artifact_age_minutes"]["maximum"] == 10080
    assert freshness["future_clock_skew_tolerance_seconds"]["maximum"] == 3600

    artifact = properties["artifacts"]["items"]
    assert artifact["additionalProperties"] is False
    assert artifact["properties"]["path"]["pattern"] == "^/(var/log|var/lib)/[A-Za-z0-9._/-]+$"


def test_host_vm_policy_schema_privacy_and_rollback_boundaries() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    properties = schema["properties"]

    privacy = properties["privacy_boundaries"]
    forbidden_fields = set(privacy["properties"]["forbidden_fields"]["items"]["enum"])
    assert privacy["additionalProperties"] is False
    assert privacy["properties"]["aggregate_only"]["const"] is True
    assert {
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
    } <= forbidden_fields

    rollback = properties["rollback"]
    assert rollback["additionalProperties"] is False
    assert rollback["properties"]["revert_files_only"]["const"] is True
    assert rollback["properties"]["live_state_rollback_required"]["const"] is False

    description = schema["description"]
    assert "does not mutate host, VM, firewall, service, network, IDS, approval, restore, model, dataset, credential, or account state" in description


def test_host_vm_policy_schema_docs_changelog_and_roadmap_alignment() -> None:
    doc = DOC_PATH.read_text(encoding="utf-8")
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")
    roadmap = json.loads(ROADMAP_PATH.read_text(encoding="utf-8"))

    assert "Host/VM Policy Configuration Schema" in doc
    assert "passive schema" in doc
    assert "remote_host_mutation_allowed" in doc
    assert "aggregate-only evidence" in doc
    assert "JSON Schema draft 2020-12" in doc
    assert "No live host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, account, or package state requires rollback." in doc

    assert "host_vm_policy_configuration_schema.json" in changelog
    assert "tests/test_host_vm_policy_configuration_schema.py" in changelog
    assert "Documentation/static-validation only" in changelog
    assert "No deployed host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, account, or package state requires rollback." in changelog

    candidates = roadmap["next_increment_candidates"]
    assert any(candidate["title"] == "Host/VM policy configuration schema" for candidate in candidates)
