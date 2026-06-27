import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "firstboot_release_gate_status.py"


def write_summary(path: Path, **overrides: str) -> None:
    fields = {
        "FIRSTBOOT_RELEASE_GATE_SCHEMA_VERSION": "1",
        "FIRSTBOOT_RELEASE_GATE_COMPONENT": "firstboot_release_gate",
        "FIRSTBOOT_RELEASE_GATE_CREATED_UTC": "2026-06-27T17:00:00Z",
        "FIRSTBOOT_RELEASE_GATE_OK": "true",
        "FIRSTBOOT_RELEASE_GATE_DECISION": "approved",
        "FIRSTBOOT_RELEASE_GATE_STATUS": "pass",
        "FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT": "0",
        "FIRSTBOOT_RELEASE_GATE_ARTIFACT_COUNT": "2",
        "FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT": "0",
        "FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE": "aggregate_only",
    }
    fields.update(overrides)
    path.write_text("\n".join(f'{key}=\"{value}\"' for key, value in fields.items()) + "\n", encoding="utf-8")


def run_status(summary: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--summary", str(summary), *extra],
        check=False,
        text=True,
        capture_output=True,
    )


def test_status_reader_passes_valid_aggregate_summary(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(summary)

    result = run_status(summary, "--format", "json", "--require-pass")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["component"] == "firstboot_release_gate_status"
    assert payload["ok"] is True
    assert payload["decision"] == "approved"
    assert payload["release_gate"] == "pass"
    assert payload["artifact_count"] == 2
    assert payload["validation_blockers"] == []
    assert "raw logs" in payload["privacy_note"]
    assert "read-only" in payload["safe_default"]


def test_status_reader_blocks_deferred_source_status(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(
        summary,
        FIRSTBOOT_RELEASE_GATE_OK="false",
        FIRSTBOOT_RELEASE_GATE_DECISION="deferred",
        FIRSTBOOT_RELEASE_GATE_STATUS="stop",
        FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="2",
        FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT="1",
    )

    result = run_status(summary, "--format", "json", "--require-pass")

    assert result.returncode == 7
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["release_gate"] == "stop"
    assert payload["blocker_count"] == 2
    assert payload["stale_or_skewed_count"] == 1
    assert any("authoritative firstboot release-gate" in step for step in payload["operator_next_steps"])


def test_status_reader_rejects_malformed_summary_without_sourcing(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(summary, FIRSTBOOT_RELEASE_GATE_PRIVACY_SCOPE="raw_logs")
    with summary.open("a", encoding="utf-8") as handle:
        handle.write("BAD LINE WITHOUT EQUALS\n")
        handle.write('FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="not-a-number"\n')

    result = run_status(summary, "--format", "json", "--require-pass")

    assert result.returncode == 7
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "privacy_scope_not_aggregate_only" in payload["validation_blockers"]
    assert "invalid_integer_field:FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT" in payload["validation_blockers"]
    assert any(blocker.startswith("invalid_summary_line:") for blocker in payload["validation_blockers"])


def test_status_reader_text_mode_is_handoff_friendly(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(summary)

    result = run_status(summary, "--format", "text")

    assert result.returncode == 0
    assert "Firstboot release-gate status" in result.stdout
    assert "decision: approved" in result.stdout
    assert "validation_blockers:" in result.stdout
    assert "- none" in result.stdout


def test_status_reader_markdown_mode_is_manager_handoff_friendly(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(summary)

    result = run_status(summary, "--format", "markdown", "--require-pass")

    assert result.returncode == 0, result.stderr
    assert "# Firstboot release-gate status" in result.stdout
    assert "| Decision | `approved` |" in result.stdout
    assert "| Release gate | `pass` |" in result.stdout
    assert "## Validation blockers" in result.stdout
    assert "- none" in result.stdout
    assert "## Safety and privacy" in result.stdout
    assert "raw logs" in result.stdout
    assert "## Rollback" in result.stdout


def test_status_reader_markdown_mode_preserves_deferred_blockers(tmp_path: Path) -> None:
    summary = tmp_path / "firstboot_release_gate.summary.env"
    write_summary(
        summary,
        FIRSTBOOT_RELEASE_GATE_OK="false",
        FIRSTBOOT_RELEASE_GATE_DECISION="deferred",
        FIRSTBOOT_RELEASE_GATE_STATUS="stop",
        FIRSTBOOT_RELEASE_GATE_BLOCKER_COUNT="1",
        FIRSTBOOT_RELEASE_GATE_STALE_OR_SKEWED_COUNT="1",
    )

    result = run_status(summary, "--format", "markdown", "--require-pass")

    assert result.returncode == 7
    assert "| Decision | `deferred` |" in result.stdout
    assert "| Release gate | `stop` |" in result.stdout
    assert "| Blocker count | `1` |" in result.stdout
    assert "Regenerate stale or clock-skewed firstboot release evidence" in result.stdout
