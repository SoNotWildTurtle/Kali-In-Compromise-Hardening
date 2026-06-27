import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "firstboot_release_gate_bundle_manifest.py"


def write_status(path: Path, **overrides: object) -> None:
    payload = {
        "schema_version": 1,
        "component": "firstboot_release_gate_status",
        "ok": True,
        "decision": "approved",
        "release_gate": "pass",
        "source_created_utc": "2026-06-27T18:00:00Z",
        "artifact_count": 2,
        "blocker_count": 0,
        "stale_or_skewed_count": 0,
        "validation_blockers": [],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")


def run_manifest(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--gate-json",
            str(tmp_path / "firstboot_release_gate.json"),
            "--gate-markdown",
            str(tmp_path / "firstboot_release_gate.md"),
            "--summary",
            str(tmp_path / "firstboot_release_gate.summary.env"),
            "--status-json",
            str(tmp_path / "firstboot_release_gate.status.json"),
            "--output",
            str(tmp_path / "firstboot_release_gate.bundle_manifest.json"),
            *extra,
        ],
        check=False,
        text=True,
        capture_output=True,
    )


def write_required_artifacts(tmp_path: Path) -> None:
    (tmp_path / "firstboot_release_gate.json").write_text('{"ok": true}\n', encoding="utf-8")
    (tmp_path / "firstboot_release_gate.md").write_text("# Firstboot Release Gate\n", encoding="utf-8")
    (tmp_path / "firstboot_release_gate.summary.env").write_text('FIRSTBOOT_RELEASE_GATE_OK="true"\n', encoding="utf-8")
    write_status(tmp_path / "firstboot_release_gate.status.json")


def test_bundle_manifest_records_artifact_hashes_and_privacy_scope(tmp_path: Path) -> None:
    write_required_artifacts(tmp_path)

    result = run_manifest(tmp_path, "--require-pass")

    assert result.returncode == 0, result.stderr
    payload = json.loads((tmp_path / "firstboot_release_gate.bundle_manifest.json").read_text(encoding="utf-8"))
    assert payload["component"] == "firstboot_release_gate_bundle_manifest"
    assert payload["ok"] is True
    assert payload["release_gate"] == "pass"
    assert len(payload["artifacts"]) == 4
    assert all(artifact["sha256"] for artifact in payload["artifacts"])
    assert payload["privacy_scope"] == "aggregate_references_only"
    assert "read-only" in payload["safe_default"]


def test_bundle_manifest_blocks_missing_required_artifact(tmp_path: Path) -> None:
    write_required_artifacts(tmp_path)
    (tmp_path / "firstboot_release_gate.md").unlink()

    result = run_manifest(tmp_path, "--require-pass")

    assert result.returncode == 7
    payload = json.loads((tmp_path / "firstboot_release_gate.bundle_manifest.json").read_text(encoding="utf-8"))
    assert payload["ok"] is False
    assert "missing_required_artifact:firstboot_release_gate_markdown" in payload["blockers"]
    assert any("Regenerate all firstboot" in step for step in payload["operator_next_steps"])


def test_bundle_manifest_blocks_nonpassing_status(tmp_path: Path) -> None:
    write_required_artifacts(tmp_path)
    write_status(
        tmp_path / "firstboot_release_gate.status.json",
        ok=False,
        decision="deferred",
        release_gate="stop",
        validation_blockers=["privacy_scope_not_aggregate_only"],
    )

    result = run_manifest(tmp_path, "--require-pass")

    assert result.returncode == 7
    payload = json.loads((tmp_path / "firstboot_release_gate.bundle_manifest.json").read_text(encoding="utf-8"))
    assert payload["release_gate"] == "stop"
    assert "status_not_passing" in payload["blockers"]
    assert "status_validation_blockers_present" in payload["blockers"]
