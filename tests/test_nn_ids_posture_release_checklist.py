import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "nn_ids_posture_release_checklist.py"


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_release_checklist_passes_for_complete_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "checklist.md"
    write_json(
        manifest,
        {
            "component": "nn_ids_posture_bundle_manifest",
            "generated_at": "2026-06-26T00:00:00+00:00",
            "status": "pass",
            "ok": True,
            "artifacts": [
                {"name": "health_evidence", "exists": True, "status": "pass", "freshness_status": "pass", "artifact_age_minutes": 5},
                {"name": "drift_evidence", "exists": True, "status": "pass", "freshness_status": "pass", "artifact_age_minutes": 6},
                {"name": "drift_triage", "exists": True, "status": "pass", "freshness_status": "pass", "artifact_age_minutes": 7},
            ],
            "summary": {"present_artifacts": 3, "artifact_count": 3},
            "release_gate": {
                "status": "pass",
                "required_artifacts": ["health_evidence", "drift_evidence", "drift_triage"],
                "promotion_blockers": [],
                "promotion_warnings": [],
                "freshness_policy": {"enforced": True, "max_artifact_age_minutes": 60},
            },
        },
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--manifest", str(manifest), "--output", str(output), "--require-pass"],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    rendered = output.read_text(encoding="utf-8")
    assert "Release ready: `yes`" in rendered
    assert "artifact.health_evidence" in rendered
    assert "aggregate posture manifest only" in rendered


def test_release_checklist_fails_for_missing_required_artifact(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "checklist.md"
    write_json(
        manifest,
        {
            "component": "nn_ids_posture_bundle_manifest",
            "generated_at": "2026-06-26T00:00:00+00:00",
            "status": "fail",
            "ok": False,
            "artifacts": [
                {"name": "health_evidence", "exists": False, "status": "missing", "freshness_status": "missing"}
            ],
            "summary": {"present_artifacts": 0, "artifact_count": 1},
            "release_gate": {
                "status": "fail",
                "required_artifacts": ["health_evidence"],
                "promotion_blockers": ["nn_ids.health.model.present"],
                "promotion_warnings": ["nn_ids.health.restart.marker.review"],
                "freshness_policy": {"enforced": True, "max_artifact_age_minutes": 60},
            },
        },
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--manifest", str(manifest), "--output", str(output), "--require-pass"],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    rendered = output.read_text(encoding="utf-8")
    assert "Release ready: `no`" in rendered
    assert "artifact.health_evidence" in rendered
    assert "Regenerate the named evidence artifact" in rendered


def test_release_checklist_json_contract(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "checklist.json"
    write_json(
        manifest,
        {
            "component": "nn_ids_posture_bundle_manifest",
            "generated_at": "2026-06-26T00:00:00+00:00",
            "status": "pass",
            "ok": True,
            "artifacts": [{"name": "health_evidence", "exists": True, "status": "pass", "freshness_status": "pass"}],
            "summary": {"present_artifacts": 1, "artifact_count": 1},
            "release_gate": {"status": "pass", "required_artifacts": ["health_evidence"], "promotion_blockers": [], "promotion_warnings": []},
        },
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--manifest", str(manifest), "--format", "json", "--output", str(output)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["component"] == "nn_ids_posture_release_checklist"
    assert payload["ok"] is True
    assert payload["summary"]["failed_required_items"] == []
