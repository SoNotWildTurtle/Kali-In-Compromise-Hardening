import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "nn_ids_posture_release_receipt.py"


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def passing_checklist() -> dict:
    return {
        "component": "nn_ids_posture_release_checklist",
        "source_generated_at": "2026-06-26T00:00:00+00:00",
        "status": "pass",
        "ok": True,
        "summary": {"failed_required_items": [], "warning_count": 0},
        "checklist": [
            {
                "id": "release_gate.status",
                "title": "Aggregate release gate reports pass",
                "status": "pass",
                "ok": True,
                "required": True,
                "action": "Resolve blockers before release.",
            },
            {
                "id": "privacy.aggregate_only",
                "title": "Checklist remains privacy-safe",
                "status": "pass",
                "ok": True,
                "required": False,
                "action": "Do not attach sensitive telemetry.",
            },
        ],
    }


def failing_checklist() -> dict:
    payload = passing_checklist()
    payload["status"] = "fail"
    payload["ok"] = False
    payload["summary"] = {
        "failed_required_items": ["artifact.health_evidence"],
        "warning_count": 1,
    }
    payload["checklist"] = [
        {
            "id": "artifact.health_evidence",
            "title": "Required evidence artifact is present",
            "status": "missing",
            "ok": False,
            "required": True,
            "action": "Regenerate the health evidence artifact.",
        },
        {
            "id": "release_gate.warnings_reviewed",
            "title": "Promotion warnings have named owners",
            "status": "warn",
            "ok": True,
            "required": False,
            "action": "Assign each warning to an owner.",
        },
    ]
    return payload


def test_release_receipt_approves_ready_checklist(tmp_path: Path) -> None:
    checklist = tmp_path / "checklist.json"
    output = tmp_path / "receipt.json"
    write_json(checklist, passing_checklist())

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--checklist",
            str(checklist),
            "--output",
            str(output),
            "--release-id",
            "firstboot-2026-06-26",
            "--environment",
            "firstboot",
            "--approver",
            "release-gate",
            "--require-ready",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["component"] == "nn_ids_posture_release_receipt"
    assert receipt["decision"] == "approved"
    assert receipt["ok"] is True
    assert receipt["summary"]["failed_required_items"] == []
    assert receipt["action_items"] == []
    assert "aggregate checklist IDs" in receipt["privacy_note"]


def test_release_receipt_defers_failed_checklist_with_action_items(tmp_path: Path) -> None:
    checklist = tmp_path / "checklist.json"
    output = tmp_path / "receipt.md"
    write_json(checklist, failing_checklist())

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--checklist",
            str(checklist),
            "--output",
            str(output),
            "--format",
            "markdown",
            "--require-ready",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    rendered = output.read_text(encoding="utf-8")
    assert "Decision: `DEFERRED`" in rendered
    assert "artifact.health_evidence" in rendered
    assert "Regenerate the health evidence artifact" in rendered
    assert "raw IDS logs" in rendered


def test_release_receipt_json_contract_infers_failed_items_from_items(tmp_path: Path) -> None:
    checklist_payload = passing_checklist()
    checklist_payload["ok"] = False
    checklist_payload["summary"] = {"failed_required_items": []}
    checklist_payload["checklist"][0]["ok"] = False
    checklist_payload["checklist"][0]["status"] = "fail"
    checklist = tmp_path / "checklist.json"
    output = tmp_path / "receipt.json"
    write_json(checklist, checklist_payload)

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--checklist", str(checklist), "--output", str(output)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["decision"] == "deferred"
    assert receipt["summary"]["failed_required_items"] == ["release_gate.status"]
    assert receipt["summary"]["action_item_count"] == 1
    assert "service, firewall, model" in receipt["rollback"]
