#!/usr/bin/env python3
"""Render a privacy-safe NN IDS posture release receipt.

MINC - Defensive validation only. This utility reads the aggregate checklist
emitted by nn_ids_posture_release_checklist.py and emits a compact release
receipt for operator handoff, CI gates, and rollback review. It is read-only and
does not inspect raw captures, packets, payloads, credentials, hostnames,
usernames, model files, services, firewall state, or host/VM configuration.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

DEFAULT_CHECKLIST = Path("/var/log/nn_ids_posture_release_checklist.json")
DEFAULT_OUTPUT = Path("/var/log/nn_ids_posture_release_receipt.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"checklist not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"unable to read checklist {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"checklist {path} must be a top-level JSON object")
    return payload


def _checklist_items(checklist: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    items: list[Mapping[str, Any]] = []
    for item in _as_list(checklist.get("checklist")):
        if isinstance(item, dict):
            items.append(item)
    return items


def _failed_required_items(checklist: Mapping[str, Any]) -> list[str]:
    summary = checklist.get("summary") if isinstance(checklist.get("summary"), dict) else {}
    from_summary = [str(item) for item in _as_list(summary.get("failed_required_items"))]
    if from_summary:
        return sorted(from_summary)
    return sorted(
        str(item.get("id") or "unknown")
        for item in _checklist_items(checklist)
        if item.get("required") and not item.get("ok")
    )


def _warning_items(checklist: Mapping[str, Any]) -> list[str]:
    return sorted(
        str(item.get("id") or "unknown")
        for item in _checklist_items(checklist)
        if str(item.get("status") or "").lower() == "warn"
    )


def _action_items(checklist: Mapping[str, Any]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    for item in _checklist_items(checklist):
        if item.get("required") and item.get("ok"):
            continue
        status = str(item.get("status") or "unknown").lower()
        if status not in {"fail", "missing", "unknown", "warn"}:
            continue
        actions.append(
            {
                "id": str(item.get("id") or "unknown"),
                "status": status,
                "required": "yes" if item.get("required") else "no",
                "action": str(item.get("action") or "Review the checklist item before release."),
            }
        )
    return actions


def build_receipt(
    checklist: Mapping[str, Any],
    release_id: str,
    environment: str,
    approver: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    failed_required = _failed_required_items(checklist)
    warnings = _warning_items(checklist)
    checklist_ok = bool(checklist.get("ok")) and not failed_required
    decision = "approved" if checklist_ok else "deferred"
    receipt = {
        "component": "nn_ids_posture_release_receipt",
        "schema_version": 1,
        "generated_at": generated_at or utc_now(),
        "release_id": release_id,
        "environment": environment,
        "approver": approver,
        "decision": decision,
        "ok": checklist_ok,
        "source_component": checklist.get("component"),
        "source_generated_at": checklist.get("source_generated_at"),
        "source_status": checklist.get("status"),
        "source_ok": bool(checklist.get("ok")),
        "summary": {
            "failed_required_items": failed_required,
            "warning_items": warnings,
            "action_item_count": len(_action_items(checklist)),
        },
        "action_items": _action_items(checklist),
        "receipt_contract": {
            "approved_means": (
                "The aggregate checklist reported ready and no required checklist "
                "item failed at receipt generation time."
            ),
            "deferred_means": (
                "At least one required checklist item is missing, failing, or unknown; "
                "regenerate evidence and checklist artifacts before promotion."
            ),
        },
        "privacy_note": (
            "This receipt contains only aggregate checklist IDs, status fields, "
            "timestamps, decisions, and remediation text. It does not embed raw "
            "packets, payloads, captures, credentials, hostnames, usernames, secrets, "
            "model files, or raw IDS logs."
        ),
        "rollback": (
            "Stop generating release receipts and continue using the posture bundle "
            "manifest plus release checklist directly; no service, firewall, model, "
            "dataset, host, or VM state is changed by this tool."
        ),
    }
    return receipt


def render_markdown(receipt: Mapping[str, Any]) -> str:
    summary = receipt.get("summary") if isinstance(receipt.get("summary"), dict) else {}
    lines = [
        "# NN IDS posture release receipt",
        "",
        f"- Release ID: `{receipt.get('release_id') or 'unknown'}`",
        f"- Environment: `{receipt.get('environment') or 'unknown'}`",
        f"- Decision: `{str(receipt.get('decision') or 'unknown').upper()}`",
        f"- Release ready: `{'yes' if receipt.get('ok') else 'no'}`",
        f"- Approver: `{receipt.get('approver') or 'unassigned'}`",
        f"- Generated at: `{receipt.get('generated_at') or 'unknown'}`",
        f"- Source generated at: `{receipt.get('source_generated_at') or 'unknown'}`",
        f"- Failed required items: `{len(_as_list(summary.get('failed_required_items')))}`",
        f"- Warning items: `{len(_as_list(summary.get('warning_items')))}`",
        "",
        "## Action items",
        "",
    ]
    action_items = _as_list(receipt.get("action_items"))
    if not action_items:
        lines.append("- None. The checklist is release-ready at receipt generation time.")
    for item in action_items:
        if not isinstance(item, dict):
            continue
        required = "required" if item.get("required") == "yes" else "advisory"
        lines.extend(
            [
                f"- `{item.get('id', 'unknown')}` ({required}, `{item.get('status', 'unknown')}`)",
                f"  - Action: {item.get('action', 'Review the checklist item before release.')}",
            ]
        )
    lines.extend(
        [
            "",
            "## Contract, privacy, and rollback",
            "",
            f"- Approved means: {receipt.get('receipt_contract', {}).get('approved_means')}",
            f"- Deferred means: {receipt.get('receipt_contract', {}).get('deferred_means')}",
            f"- Privacy: {receipt.get('privacy_note')}",
            f"- Rollback: {receipt.get('rollback')}",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render a privacy-safe NN IDS release receipt from a checklist JSON artifact."
    )
    parser.add_argument(
        "--checklist",
        default=str(DEFAULT_CHECKLIST),
        help="Path to JSON output from nn_ids_posture_release_checklist.py --format json.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path to write the receipt; use '-' for stdout.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Render machine-readable JSON or a privacy-safe Markdown receipt.",
    )
    parser.add_argument(
        "--release-id",
        default="manual-review",
        help="Operator-supplied release, recovery, or handoff identifier.",
    )
    parser.add_argument(
        "--environment",
        default="kali-vm",
        help="Deployment context for the receipt, such as kali-vm, firstboot, or recovery.",
    )
    parser.add_argument(
        "--approver",
        default="unassigned",
        help="Operator or automation role recording the receipt. Avoid personal data if not needed.",
    )
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="Exit non-zero unless the receipt decision is approved.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checklist = _load_json(Path(args.checklist))
    receipt = build_receipt(
        checklist=checklist,
        release_id=args.release_id,
        environment=args.environment,
        approver=args.approver,
    )
    rendered = (
        json.dumps(receipt, indent=2, sort_keys=True)
        if args.format == "json"
        else render_markdown(receipt)
    )
    if args.output == "-":
        print(rendered)
    else:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.require_ready or receipt.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
