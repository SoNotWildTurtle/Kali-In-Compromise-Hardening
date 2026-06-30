# MINC - Static validation for passive README duplicate-module drift evidence.
from collections import Counter
from pathlib import Path


def _normalise_bullet(line: str) -> str:
    text = line.strip()
    assert text.startswith("- ")
    return " ".join(text[2:].strip().lower().split())


def _duplicate_bullets(readme_text: str) -> set[str]:
    bullets = [
        _normalise_bullet(line)
        for line in readme_text.splitlines()
        if line.strip().startswith("- ")
    ]
    counts = Counter(bullets)
    return {bullet for bullet, count in counts.items() if count > 1}


def test_readme_duplicate_module_drift_is_documented() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    drift_doc = Path("docs/readme_duplicate_module_drift.md").read_text(encoding="utf-8")
    changelog = Path("docs/changelog_readme_duplicate_module_drift.md").read_text(
        encoding="utf-8"
    )

    duplicates = _duplicate_bullets(readme)

    expected_duplicate_fragments = [
        "automated windows 11 host hardening",
        "automated windows remote setup",
        "windows host-aware vm hardening",
        "mac address randomization",
        "neural network ids",
        "packet sanitization",
        "initial network discovery",
        "`firstboot.sh`",
        "`host_hardening_windows.sh`",
        "`vm_windows_env_hardening.sh`",
        "`security_scan_scheduler.sh`",
        "`process_service_monitor.py`",
        "`port_socket_monitor.py`",
        "`nn_ids_healthcheck.py`",
        "`setup_nn_ids.sh`",
    ]

    for fragment in expected_duplicate_fragments:
        assert any(fragment in duplicate for duplicate in duplicates), fragment

    assert "README Duplicate Module Drift Check" in drift_doc
    assert "passive documentation-quality check" in drift_doc
    assert "does not rewrite the README" in drift_doc
    assert "Static check contract" in drift_doc
    assert "Future cleanup PR" in drift_doc or "future cleanup PR" in drift_doc
    assert "No live host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, or account state requires rollback." in drift_doc

    assert "readme_duplicate_module_drift.md" in changelog
    assert "tests/test_readme_duplicate_module_drift.py" in changelog
    assert "documentation/static-validation only" in changelog
    assert "No deployed host, VM, firewall, service, network, firstboot, approval, restore, IDS, model, dataset, credential, or account state requires rollback." in changelog
