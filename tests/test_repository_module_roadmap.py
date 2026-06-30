# MINC - Static validation for the passive repository module roadmap.
import json
from pathlib import Path


def test_repository_module_roadmap_contract() -> None:
    roadmap_path = Path("docs/repository_module_roadmap.json")
    doc_path = Path("docs/repository_module_roadmap.md")
    changelog_path = Path("docs/changelog_repository_module_roadmap.md")

    roadmap = json.loads(roadmap_path.read_text(encoding="utf-8"))
    doc = doc_path.read_text(encoding="utf-8")
    changelog = changelog_path.read_text(encoding="utf-8")

    assert roadmap["schema_version"] == 1
    assert roadmap["artifact"] == "repository_module_roadmap"
    assert roadmap["safety_model"]["default_behavior"] == "read-only planning evidence"
    assert "must_not_change" in roadmap["safety_model"]
    assert "required_boundaries" in roadmap["safety_model"]

    module_ids = {module["id"] for module in roadmap["modules"]}
    assert "kali_guest_firstboot_hardening" in module_ids
    assert "host_vm_policy_and_isolation" in module_ids
    assert "nn_ids_posture_pipeline" in module_ids
    assert "recovery_restore_and_release_gates" in module_ids
    assert "operator_docs_and_ci_static_coverage" in module_ids

    for module in roadmap["modules"]:
        assert module["owner_role"]
        assert module["primary_files"]
        assert module["generated_artifacts"]
        assert module["validation_focus"]
        assert module["rollback_procedure"]

    candidates = {candidate["title"] for candidate in roadmap["next_increment_candidates"]}
    assert "README duplicate-module drift static check" in candidates
    assert "Unified aggregate posture gate" in candidates

    assert "Repository Module Roadmap" in doc
    assert "passive, documentation-only companion" in doc
    assert "Kali guest firstboot hardening" in doc
    assert "Host/VM policy and isolation" in doc
    assert "NN IDS posture pipeline" in doc
    assert "Recovery, restore, and release gates" in doc
    assert "Operator docs and CI static coverage" in doc
    assert "No live firewall, service, host, VM, IDS, approval, restore, model, dataset, account, credential, or network state requires rollback." in doc

    assert "repository_module_roadmap.json" in changelog
    assert "passive machine-readable roadmap artifact" in changelog
    assert "does not change host, VM, firewall, service, network, restore, approval, model, dataset, credential, or account state" in changelog
    assert "Rollback" in changelog
