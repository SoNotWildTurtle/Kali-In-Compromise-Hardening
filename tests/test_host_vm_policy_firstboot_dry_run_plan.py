from pathlib import Path


PLAN_PATH = Path("docs/host_vm_policy_firstboot_dry_run_plan.md")
CHANGELOG_PATH = Path("docs/changelog_host_vm_policy_firstboot_dry_run_plan.md")


def test_firstboot_dry_run_plan_preserves_passive_boundary() -> None:
    plan = PLAN_PATH.read_text(encoding="utf-8")

    assert "documentation-only" in plan
    assert "passive" in plan
    assert "aggregate evidence files" in plan
    assert "only permitted side effect" in plan


def test_firstboot_dry_run_plan_defines_machine_readable_outputs() -> None:
    plan = PLAN_PATH.read_text(encoding="utf-8")

    assert "host_vm_policy_validator_evidence.json" in plan
    assert "host_vm_policy_firstboot_manifest.json" in plan
    assert "host_vm_policy_firstboot_handoff.json" in plan
    assert "profile path and SHA-256" in plan
    assert "validation status and error count" in plan
    assert "rollback scope limited to deleting generated evidence files" in plan


def test_changelog_records_safe_additive_planning_scope() -> None:
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "documentation-only" in changelog
    assert "Existing validator CLI behavior remains unchanged" in changelog
    assert "Rollback is limited to reverting this planning document" in changelog
    assert "Add the standard-library dry-run wrapper" in changelog
