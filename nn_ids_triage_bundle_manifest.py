#!/usr/bin/env python3
"""Build a passive manifest from validated NN IDS triage JSON records.

MINC - Defensive release evidence helper only.

This tool reads local schema-compatible triage JSON records that were already
emitted by nn_ids_triage_record_validate.sh --emit-json. It summarizes decision
counts, release readiness, blockers, source hashes, and follow-up needs for
reviewer handoff bundles. It does not inspect live IDS, host, VM, hypervisor,
packet, payload, firewall, restore, retraining, telemetry, service, or network
state and never authorizes live action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any

REQUIRED_KEYS = (
    "triage_decision",
    "release_ready",
    "source_artifacts",
    "artifact_hashes",
    "blocking_issues",
    "uncertainty_note",
    "privacy_scope",
    "human_review_required",
    "live_action_authorized",
    "rollback_reference",
    "next_evidence_needed",
    "owner",
)

DECISIONS = ("pass", "watch", "degraded", "blocked")


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_record(path: pathlib.Path) -> tuple[str, dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc

    if not isinstance(record, dict):
        raise ValueError(f"{path}: triage record must be a JSON object")

    missing = [key for key in REQUIRED_KEYS if key not in record]
    extra = sorted(set(record) - set(REQUIRED_KEYS))
    if missing:
        raise ValueError(f"{path}: missing required keys: {', '.join(missing)}")
    if extra:
        raise ValueError(f"{path}: unexpected keys: {', '.join(extra)}")

    decision = record["triage_decision"]
    if decision not in DECISIONS:
        raise ValueError(f"{path}: unsupported triage_decision: {decision!r}")
    if not isinstance(record["release_ready"], bool):
        raise ValueError(f"{path}: release_ready must be a JSON boolean")
    if record["human_review_required"] is not True:
        raise ValueError(f"{path}: human_review_required must be true")
    if record["live_action_authorized"] is not False:
        raise ValueError(f"{path}: live_action_authorized must be false")
    if "aggregate-only" not in record["privacy_scope"]:
        raise ValueError(f"{path}: privacy_scope must include aggregate-only")
    if "no raw telemetry or secrets" not in record["privacy_scope"]:
        raise ValueError(f"{path}: privacy_scope must reject raw telemetry and secrets")
    if "sha256" not in record["artifact_hashes"] and "manifest:" not in record["artifact_hashes"]:
        raise ValueError(f"{path}: artifact_hashes must include sha256 evidence or a manifest reference")

    return text, record


def build_manifest(paths: list[pathlib.Path], generated_at: str) -> dict[str, Any]:
    if not paths:
        raise ValueError("at least one triage JSON record is required")

    records: list[dict[str, Any]] = []
    decision_counts = {decision: 0 for decision in DECISIONS}
    release_ready_count = 0
    blocking_count = 0
    aggregate_follow_up: list[str] = []

    for path in paths:
        text, record = _load_record(path)
        decision = record["triage_decision"]
        decision_counts[decision] += 1
        release_ready_count += int(record["release_ready"])
        blocking_issue = str(record["blocking_issues"])
        if not blocking_issue.startswith("none"):
            blocking_count += 1
        aggregate_follow_up.append(str(record["next_evidence_needed"]))
        records.append(
            {
                "path": str(path),
                "sha256": _sha256_text(text),
                "triage_decision": decision,
                "release_ready": record["release_ready"],
                "blocking_issues": blocking_issue,
                "next_evidence_needed": record["next_evidence_needed"],
                "owner": record["owner"],
            }
        )

    overall_status = "release-ready"
    if blocking_count:
        overall_status = "blocked"
    elif release_ready_count != len(records):
        overall_status = "review-required"
    elif decision_counts["degraded"] or decision_counts["blocked"]:
        overall_status = "review-required"

    return {
        "manifest_type": "nn_ids_triage_bundle_manifest",
        "schema_version": 1,
        "generated_at": generated_at,
        "record_count": len(records),
        "overall_status": overall_status,
        "decision_counts": decision_counts,
        "release_ready_count": release_ready_count,
        "blocking_record_count": blocking_count,
        "human_review_required": True,
        "live_action_authorized": False,
        "privacy_scope": "aggregate-only; no raw telemetry or secrets",
        "records": records,
        "next_evidence_needed": aggregate_follow_up,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a passive NN IDS triage bundle manifest from validated JSON records."
    )
    parser.add_argument(
        "records",
        nargs="+",
        type=pathlib.Path,
        help="Schema-compatible triage JSON records emitted by nn_ids_triage_record_validate.sh --emit-json.",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Optional ISO-8601 timestamp for reproducible tests and release receipts.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    generated_at = args.generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    try:
        manifest = build_manifest(args.records, generated_at)
    except ValueError as exc:
        print(f"[triage-bundle-manifest][FAIL] {exc}", file=sys.stderr)
        return 1
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
