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
        "generated_at": "2026-06-26T23:00:00+00:00",
        "ok": True,
    }


def health_payload() -> dict:
    return {
        "component": "nn_ids_health_evidence",
        "status": "pass",
        "ok": True,
        "generated_at": "2026-06-26T23:00:00+00:00",
        "metrics": {"accuracy": 0.94, "f1": 0.91, "precision": 0.9, "recall": 0.92},
    }


def drift_payload(status: str = "pass") -> dict:
    return {
        "component": "nn_ids_drift_evidence",
        "status": status,
        "ok": status == "pass",
        "generated_at": "2026-06-26T23:00:00+00:00",
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
        "generated_at": "2026-06-26T23:00:00+00:00",
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
    assert card["freshness"]["enforced"] is False
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
    assert "Freshness window: `not enforced`" in rendered
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


def test_model_card_freshness_gate_blocks_stale_evidence(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    health = tmp_path / "health.json"
    drift = tmp_path / "drift.json"
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "model-card.json"
    stale_health = health_payload()
    stale_health["generated_at"] = "2000-01-01T00:00:00+00:00"
    write_json(schema, schema_payload())
    write_json(health, stale_health)
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
            "--max-artifact-age-minutes",
            "60",
            "--require-pass",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    card = json.loads(output.read_text(encoding="utf-8"))
    assert "freshness.health_evidence.stale" in card["blockers"]
    assert card["freshness"]["enforced"] is True
    health_entry = next(item for item in card["freshness"]["artifacts"] if item["name"] == "health_evidence")
    assert health_entry["freshness_status"] == "fail"
    assert any("Regenerate stale" in action for action in card["operator_actions"])


def test_model_card_freshness_gate_blocks_missing_timestamp_in_markdown(tmp_path: Path) -> None:
    schema = tmp_path / "schema.json"
    health = tmp_path / "health.json"
    drift = tmp_path / "drift.json"
    receipt = tmp_path / "receipt.json"
    output = tmp_path / "model-card.md"
    missing_timestamp_receipt = receipt_payload()
    missing_timestamp_receipt.pop("generated_at")
    write_json(schema, schema_payload())
    write_json(health, health_payload())
    write_json(drift, drift_payload())
    write_json(receipt, missing_timestamp_receipt)

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
            "--max-artifact-age-minutes",
            "60",
            "--require-pass",
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    rendered = output.read_text(encoding="utf-8")
    assert "Freshness window: `60.0` minutes" in rendered
    assert "freshness.release_receipt.missing_generated_at" in rendered
    assert "Artifact freshness" in rendered
    assert "Regenerate stale or timestamp-missing NN IDS evidence" in rendered
