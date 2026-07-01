#!/usr/bin/env bash
# MINC - Static coverage for passive NN IDS alert triage examples.
# Defensive documentation validation only; does not inspect live IDS, host, VM, or hypervisor state.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT_DIR

python3 - <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(os.environ["ROOT_DIR"])
doc_path = root / "docs" / "nn_ids_alert_triage_examples.md"
changelog_path = root / "changelog.d" / "nn_ids_alert_triage_examples.md"

errors = []

for path in (doc_path, changelog_path):
    if not path.is_file():
        errors.append(f"missing required file: {path}")

if not errors:
    doc = doc_path.read_text(encoding="utf-8")
    changelog = changelog_path.read_text(encoding="utf-8")

    doc_tokens = [
        "aggregate-only evidence",
        "analytical estimates, not certainty",
        "human_review_required=true",
        "live_action_authorized=false",
        "no remediation, restore, retrain, firewall, service, or hypervisor action",
        "no raw telemetry or secrets",
        "nn_ids_release_readiness_summary.json",
        "nn_ids_release_readiness_summary.report",
        "nn_ids_health_evidence.json",
        "nn_ids_drift_evidence.json",
        "nn_ids_drift_triage.md",
        "nn_ids_model_card",
        "nn_ids_posture_bundle_manifest.json",
        "release_ready=",
        "source_artifacts=",
        "artifact_hashes=",
        "blocking_issues=",
        "uncertainty_note=",
        "privacy_scope=",
        "rollback_reference=",
        "next_evidence_needed=",
        "owner=",
        "Fail closed",
        "Accessibility and handoff notes",
        "Compatibility and rollback",
        "documentation-only",
    ]
    changelog_tokens = [
        "nn_ids_alert_triage_examples.md",
        "synthetic",
        "documentation-only",
        "does not inspect live IDS, host, VM, or hypervisor state",
        "bash tests/test_nn_ids_alert_triage_examples_static.sh",
    ]

    for token in doc_tokens:
        if token not in doc:
            errors.append(f"{doc_path} missing required token: {token}")

    for token in changelog_tokens:
        if token not in changelog:
            errors.append(f"{changelog_path} missing required token: {token}")

    for decision in ("pass", "watch", "degraded", "blocked"):
        if f"## Example: {decision}" not in doc:
            errors.append(f"{doc_path} missing section for triage decision: {decision}")
        if f"triage_decision={decision}" not in doc:
            errors.append(f"{doc_path} missing record field for triage decision: {decision}")

if errors:
    for error in errors:
        print(f"[triage-examples-static][FAIL] {error}", file=sys.stderr)
    sys.exit(1)

print("[triage-examples-static] NN IDS alert triage examples static checks passed")
PY
