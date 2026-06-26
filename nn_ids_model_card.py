#!/usr/bin/env python3
"""Generate a privacy-safe NN IDS model card from aggregate evidence.

MINC - Defensive validation only. This utility is read-only: it consumes existing
schema, health, drift, and release artifacts and emits aggregate review evidence.
It does not inspect packets, payloads, captures, credentials, hostnames,
usernames, model binaries, firewall state, or host/VM configuration.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

DEFAULT_SCHEMA = Path("/opt/nnids/feature_schema.json")
DEFAULT_HEALTH = Path("/var/log/nn_ids_health_evidence.json")
DEFAULT_DRIFT = Path("/var/log/nn_ids_drift_evidence.json")
DEFAULT_RECEIPT = Path("/var/log/nn_ids_posture_release_receipt.json")
DEFAULT_OUTPUT = Path("/var/log/nn_ids_model_card.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_optional_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, f"missing:{path}"
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable:{path}:{exc}"
    if not isinstance(payload, dict):
        return None, f"invalid:{path}:top-level JSON must be an object"
    return payload, None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _feature_order(schema: Mapping[str, Any] | None) -> list[str]:
    if not schema:
        return []
    order = schema.get("feature_order")
    return [str(item) for item in _as_list(order)]


def _health_metrics(health: Mapping[str, Any] | None) -> dict[str, Any]:
    if not health:
        return {}
    for key in ("metrics", "latest_metrics", "training_metrics", "summary"):
        value = health.get(key)
        if isinstance(value, dict):
            return {
                str(metric): value[metric]
                for metric in sorted(value)
                if metric in {"accuracy", "f1", "precision", "recall", "roc_auc", "model_age_hours"}
            }
    return {}


def _status(payload: Mapping[str, Any] | None) -> str:
    if not payload:
        return "missing"
    status = payload.get("status")
    if isinstance(status, str) and status:
        return status.lower()
    if payload.get("ok") is True:
        return "pass"
    if payload.get("ok") is False:
        return "fail"
    return "unknown"


def _drift_summary(drift: Mapping[str, Any] | None) -> dict[str, Any]:
    if not drift:
        return {"status": "missing", "failing_features": [], "warning_features": []}
    failing: list[str] = []
    warnings: list[str] = []
    features = drift.get("features")
    if isinstance(features, dict):
        for name, evidence in sorted(features.items()):
            if not isinstance(evidence, dict):
                continue
            status = str(evidence.get("status") or "unknown").lower()
            if status == "fail":
                failing.append(str(name))
            elif status == "warn":
                warnings.append(str(name))
    summary = drift.get("summary") if isinstance(drift.get("summary"), dict) else {}
    return {
        "status": _status(drift),
        "failing_features": failing or [str(item) for item in _as_list(summary.get("failing_features"))],
        "warning_features": warnings or [str(item) for item in _as_list(summary.get("warning_features"))],
    }


def _release_decision(receipt: Mapping[str, Any] | None) -> str:
    if not receipt:
        return "missing"
    decision = receipt.get("decision")
    return str(decision).lower() if decision else _status(receipt)


def build_model_card(
    schema: Mapping[str, Any] | None,
    health: Mapping[str, Any] | None,
    drift: Mapping[str, Any] | None,
    receipt: Mapping[str, Any] | None,
    errors: list[str],
    generated_at: str | None = None,
) -> dict[str, Any]:
    feature_order = _feature_order(schema)
    health_status = _status(health)
    drift = drift or None
    drift_summary = _drift_summary(drift)
    release_decision = _release_decision(receipt)
    blockers = list(errors)

    if not feature_order:
        blockers.append("feature_schema.missing_or_invalid")
    if health_status in {"missing", "fail", "unknown"}:
        blockers.append(f"health_evidence.{health_status}")
    if drift_summary["status"] in {"missing", "fail", "unknown"}:
        blockers.append(f"drift_evidence.{drift_summary['status']}")
    if release_decision not in {"approved", "pass"}:
        blockers.append(f"release_receipt.{release_decision}")

    ok = not blockers
    return {
        "component": "nn_ids_model_card",
        "schema_version": 1,
        "generated_at": generated_at or utc_now(),
        "ok": ok,
        "status": "pass" if ok else "fail",
        "model_scope": {
            "purpose": "defensive Kali NN IDS posture review and release handoff",
            "not_for": "operational targeting, certainty claims, or raw traffic disclosure",
        },
        "feature_contract": {
            "feature_order": feature_order,
            "feature_count": len(feature_order),
            "source_status": _status(schema),
        },
        "health": {
            "status": health_status,
            "metrics": _health_metrics(health),
        },
        "drift": drift_summary,
        "release": {
            "decision": release_decision,
            "source_status": _status(receipt),
        },
        "blockers": sorted(set(blockers)),
        "operator_actions": operator_actions(blockers),
        "privacy_note": (
            "This model card contains only aggregate statuses, feature names, metric keys, "
            "and release decisions. It excludes raw packets, payloads, captures, credentials, "
            "hostnames, usernames, secrets, model binaries, raw IDS logs, and host/VM state."
        ),
        "rollback": (
            "Stop generating the model card and continue reviewing the existing schema, health, "
            "drift, checklist, and receipt artifacts directly. This tool is read-only and changes "
            "no services, timers, firewall rules, model files, datasets, host settings, or VM settings."
        ),
    }


def operator_actions(blockers: list[str]) -> list[str]:
    actions: list[str] = []
    for blocker in sorted(set(blockers)):
        if blocker.startswith("feature_schema"):
            actions.append("Regenerate /opt/nnids/feature_schema.json from the canonical NN IDS feature schema before release.")
        elif blocker.startswith("health_evidence"):
            actions.append("Regenerate NN IDS health evidence and investigate missing/failing model, metrics, or service-health markers.")
        elif blocker.startswith("drift_evidence"):
            actions.append("Regenerate drift evidence and review failing or missing drift controls before model promotion.")
        elif blocker.startswith("release_receipt"):
            actions.append("Regenerate the posture release checklist and receipt after resolving blockers.")
        elif blocker.startswith("missing:") or blocker.startswith("unreadable:"):
            actions.append(f"Review evidence artifact problem: {blocker}")
        else:
            actions.append(f"Review blocker before release: {blocker}")
    return actions


def render_markdown(card: Mapping[str, Any]) -> str:
    lines = [
        "# NN IDS model card",
        "",
        f"- Status: `{str(card.get('status') or 'unknown').upper()}`",
        f"- Release ready: `{'yes' if card.get('ok') else 'no'}`",
        f"- Generated at: `{card.get('generated_at') or 'unknown'}`",
        f"- Feature count: `{card.get('feature_contract', {}).get('feature_count', 0)}`",
        f"- Health status: `{card.get('health', {}).get('status', 'unknown')}`",
        f"- Drift status: `{card.get('drift', {}).get('status', 'unknown')}`",
        f"- Release decision: `{card.get('release', {}).get('decision', 'unknown')}`",
        "",
        "## Feature contract",
        "",
    ]
    feature_order = _as_list(card.get("feature_contract", {}).get("feature_order"))
    lines.append("- " + ", ".join(f"`{name}`" for name in feature_order) if feature_order else "- Missing feature contract.")
    lines.extend(["", "## Blockers", ""])
    blockers = _as_list(card.get("blockers"))
    if blockers:
        lines.extend(f"- `{blocker}`" for blocker in blockers)
    else:
        lines.append("- None. Aggregate model-card evidence is release-ready.")
    lines.extend(["", "## Operator actions", ""])
    actions = _as_list(card.get("operator_actions"))
    if actions:
        lines.extend(f"- {action}" for action in actions)
    else:
        lines.append("- Continue standard monitoring and regenerate evidence before the next release gate.")
    lines.extend(
        [
            "",
            "## Privacy and rollback",
            "",
            f"- Privacy: {card.get('privacy_note')}",
            f"- Rollback: {card.get('rollback')}",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a privacy-safe NN IDS model card from aggregate evidence.")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA), help="Path to NN IDS feature schema JSON.")
    parser.add_argument("--health", default=str(DEFAULT_HEALTH), help="Path to NN IDS health evidence JSON.")
    parser.add_argument("--drift", default=str(DEFAULT_DRIFT), help="Path to NN IDS drift evidence JSON.")
    parser.add_argument("--receipt", default=str(DEFAULT_RECEIPT), help="Path to posture release receipt JSON.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output path, or '-' for stdout.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Output format.")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the model card is release-ready.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors: list[str] = []
    schema, error = _load_optional_json(Path(args.schema))
    if error:
        errors.append(error)
    health, error = _load_optional_json(Path(args.health))
    if error:
        errors.append(error)
    drift, error = _load_optional_json(Path(args.drift))
    if error:
        errors.append(error)
    receipt, error = _load_optional_json(Path(args.receipt))
    if error:
        errors.append(error)

    card = build_model_card(schema, health, drift, receipt, errors)
    rendered = json.dumps(card, indent=2, sort_keys=True) if args.format == "json" else render_markdown(card)
    if args.output == "-":
        print(rendered)
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.require_pass or card.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
