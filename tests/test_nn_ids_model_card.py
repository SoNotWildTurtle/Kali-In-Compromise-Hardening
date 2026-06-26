import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "nn_ids_model_card.py"


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def schema_payload() -> dict:
    return {
        "version": 1,
        "feature_order": ["len", "ttl", "dport", "tcp_flags"],
        "ranges": {"len": [1, 65535]},
        "ok": True,
    }


def health_payload() -> dict:
    return {
        "component": "nn_ids_health_evidence",
        "status": "pass",
        "ok": True,
        "metrics": {"accuracy": 0.94, "f1": 0.91, "precision": 0.9, "recall": 0.92},
    }


def drift_payload(status: str = "pass") -> dict:
    return {
        "component": "nn_ids_drift_evidence",
        "status": status,
        "ok": status == "pass",
        "features": {
            "len": {"status": status, "psi": 0.03},
            "ttl": {"status": "pass", "psi": 0.01},
        },
    }


def receipt_payload(decision: str = "approved") -> dict:
    return {
        "component": "nn_ids_posture_release_receipt",
        "decision": decision,
        "status": "pass" if decision == "approved" else "fail",
        "ok": decision == "approved",
    }


def test_model_card_passes_with_aggregate_evidence(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    health = tmp_path / "health.json"
    drift = tmp_path / "drift.json"
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "model-card.json"
    write_json(schema, schema_payload())
    write_json(health, health_payload())
    write_json(drift, drift_payload())
    write_json(receipt, receipt_payload())

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--schema",
            str(schema),
            "--health",
            str(health),
            "--drift",
            str(drift),
            "--receipt",
            str(receipt),
            "--output",
            str(output),
            "--require-pass",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    card = json.loads(output.read_text(encoding="utf-8"))
    assert card["component"] == "nn_ids_model_card"
    assert card["ok"] is True
    assert card["feature_contract"]["feature_order"] == ["len", "ttl", "dport", "tcp_flags"]
    assert card["health"]["metrics"]["f1"] == 0.91
    assert card["blockers"] == []
    assert "raw packets" in card["privacy_note"]
    assert "read-only" in card["rollback"]


def test_model_card_blocks_failed_drift_and_deferred_receipt(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    health = tmp_path / "health.json"
    drift = tmp_path / "drift.json"
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "model-card.md"
    write_json(schema, schema_payload())
    write_json(health, health_payload())
    write_json(drift, drift_payload("fail"))
    write_json(receipt, receipt_payload("deferred"))

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--schema",
            str(schema),
            "--health",
            str(health),
            "--drift",
            str(drift),
            "--receipt",
            str(receipt),
            "--output",
            str(output),
            "--format",
            "markdown",
            "--require-pass",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    rendered = output.read_text(encoding="utf-8")
    assert "Status: `FAIL`" in rendered
    assert "drift_evidence.fail" in rendered
    assert "release_receipt.deferred" in rendered
    assert "Regenerate drift evidence" in rendered
    assert "raw IDS logs" in rendered


def test_model_card_missing_artifacts_are_explicit_blockers(tmp_path: Path) -> None:
    output = tmp_path / "model-card.json"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--schema",
            str(tmp_path / "missing-schema.json"),
            "--health",
            str(tmp_path / "missing-health.json"),
            "--drift",
            str(tmp_path / "missing-drift.json"),
            "--receipt",
            str(tmp_path / "missing-receipt.json"),
            "--output",
            str(output),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    card = json.loads(output.read_text(encoding="utf-8"))
    assert card["ok"] is False
    assert "feature_schema.missing_or_invalid" in card["blockers"]
    assert "health_evidence.missing" in card["blockers"]
    assert "drift_evidence.missing" in card["blockers"]
    assert "release_receipt.missing" in card["blockers"]
    assert any(action.startswith("Review evidence artifact problem") for action in card["operator_actions"])
