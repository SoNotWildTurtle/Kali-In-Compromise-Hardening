from pathlib import Path


PLAN_PATH = Path("docs/host_vm_policy_firstboot_dry_run_plan.md")
README_PATH = Path("README.md")
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


def test_readme_and_changelog_reference_firstboot_dry_run_plan() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "host_vm_policy_firstboot_dry_run_plan.md" in readme
    assert "Host/VM policy firstboot dry-run" in readme
    assert "documentation-only" in changelog
    assert "No live host, VM" in changelog
