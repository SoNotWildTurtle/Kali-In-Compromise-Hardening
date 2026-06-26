from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import nn_ids_drift_triage as triage


def sample_evidence() -> dict[str, object]:
    return {
        "component": "nn_ids_drift",
        "generated_at": "2026-06-26T12:00:00+00:00",
        "status": "warn",
        "ok": False,
        "features": [
            {
                "feature": "ttl",
                "status": "warn",
                "psi": 0.13,
                "mean_shift_sigma": 2.5,
                "missing_rate_delta": 0.01,
                "messages": ["PSI exceeded warning threshold"],
            },
            {
                "feature": "len",
                "status": "pass",
                "psi": 0.01,
                "mean_shift_sigma": 0.2,
                "missing_rate_delta": 0.0,
                "messages": ["feature drift is within configured thresholds"],
            },
        ],
    }


def test_build_triage_summarizes_status_and_actions() -> None:
    report = triage.build_triage(sample_evidence(), max_actions=3)

    assert report["component"] == "nn_ids_drift_triage"
    assert report["status"] == "warn"
    assert report["ok"] is False
    assert report["summary"] == {
        "failed_features": 0,
        "warning_features": 1,
        "passing_features": 1,
        "total_features": 2,
    }
    assert "ttl" in report["recommended_actions"][0]
    assert "packets" in report["privacy_note"]


def test_markdown_renderer_is_operator_readable_and_privacy_safe() -> None:
    report = triage.build_triage(sample_evidence(), max_actions=3)
    markdown = triage.render_markdown(report)

    assert markdown.startswith("# NN IDS Drift Triage")
    assert "| ttl | warn | 0.130 | 2.500 | 0.010 |" in markdown
    assert "Privacy:" in markdown
    assert "credentials" in markdown
    assert "Rollback:" in markdown


def test_cli_writes_json_and_require_pass_reflects_source_status(tmp_path: Path) -> None:
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "triage.json"
    evidence_path.write_text(json.dumps(sample_evidence()), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "nn_ids_drift_triage.py",
            "--evidence",
            str(evidence_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--require-pass",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["summary"]["warning_features"] == 1
    assert payload["recommended_actions"]
