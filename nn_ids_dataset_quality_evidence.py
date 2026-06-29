#!/usr/bin/env python3
"""Emit passive NN IDS dataset-quality evidence as JSON or Markdown.

This helper is intentionally read-only. It inspects CSV structure and aggregate
label/feature quality indicators so operators can catch poisoned, stale, tiny,
imbalanced, malformed, or non-reproducible training inputs before retraining,
release promotion, or firstboot handoff. It never opens network sockets, never
executes system commands, never reads packet payloads beyond the supplied CSV
file, and never modifies host, VM, firewall, service, or model state.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DEFAULT_DATASET = Path("/opt/nnids/datasets/dataset.csv")
DEFAULT_LABEL_COLUMN = "label"
DEFAULT_MIN_ROWS = 100
DEFAULT_MIN_CLASSES = 2
DEFAULT_MAX_MISSING_RATE = 0.05
DEFAULT_MAX_CLASS_IMBALANCE = 0.95
DEFAULT_MAX_DUPLICATE_RATE = 0.20
DEFAULT_MAX_NUMERIC_RATIO = 0.98
DEFAULT_MAX_COLUMNS = 256
DEFAULT_SAMPLE_LIMIT = 5000


@dataclass(frozen=True)
class Finding:
    control: str
    status: str
    message: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def bounded_rate(value: str) -> float:
    parsed = float(value)
    if parsed < 0 or parsed > 1:
        raise argparse.ArgumentTypeError("rate must be between 0 and 1")
    return parsed


def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def normalize_header(header: Iterable[str]) -> list[str]:
    return [name.strip() for name in header]


def is_missing(value: str | None) -> bool:
    if value is None:
        return True
    return value.strip().lower() in {"", "na", "n/a", "null", "none", "nan", "?"}


def looks_numeric(value: str) -> bool:
    try:
        parsed = float(value)
    except ValueError:
        return False
    return math.isfinite(parsed)


def summarize_dataset(path: Path, label_column: str, sample_limit: int) -> tuple[dict[str, object], list[str]]:
    errors: list[str] = []
    summary: dict[str, object] = {
        "rows": 0,
        "columns": 0,
        "label_column": label_column,
        "label_counts": {},
        "missing_cells": 0,
        "total_cells": 0,
        "duplicate_sample_rows": 0,
        "sampled_rows": 0,
        "feature_numeric_columns": 0,
        "feature_columns": [],
    }

    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                errors.append("dataset has no CSV header")
                return summary, errors

            header = normalize_header(reader.fieldnames)
            summary["columns"] = len(header)
            summary["feature_columns"] = [column for column in header if column != label_column]
            if label_column not in header:
                errors.append(f"label column '{label_column}' is missing")
                return summary, errors

            label_counts: Counter[str] = Counter()
            missing_cells = 0
            total_cells = 0
            sampled_rows = 0
            duplicate_rows = 0
            row_hashes: set[str] = set()
            numeric_hits: Counter[str] = Counter()
            non_missing_hits: Counter[str] = Counter()

            for row in reader:
                summary["rows"] = int(summary["rows"]) + 1
                row_values = [row.get(column, "") for column in header]
                total_cells += len(header)
                missing_cells += sum(1 for value in row_values if is_missing(value))

                label = (row.get(label_column) or "").strip()
                label_counts[label or "<missing>"] += 1

                if sampled_rows < sample_limit:
                    sampled_rows += 1
                    stable_row = "\x1f".join((row.get(column) or "") for column in header)
                    row_digest = hashlib.sha256(stable_row.encode("utf-8", errors="replace")).hexdigest()
                    if row_digest in row_hashes:
                        duplicate_rows += 1
                    row_hashes.add(row_digest)

                    for column in header:
                        if column == label_column:
                            continue
                        value = row.get(column)
                        if is_missing(value):
                            continue
                        non_missing_hits[column] += 1
                        if looks_numeric(str(value)):
                            numeric_hits[column] += 1

            feature_numeric_columns = 0
            for column, count in non_missing_hits.items():
                if count and numeric_hits[column] / count >= 0.95:
                    feature_numeric_columns += 1

            summary["label_counts"] = dict(label_counts)
            summary["missing_cells"] = missing_cells
            summary["total_cells"] = total_cells
            summary["duplicate_sample_rows"] = duplicate_rows
            summary["sampled_rows"] = sampled_rows
            summary["feature_numeric_columns"] = feature_numeric_columns
    except csv.Error as exc:
        errors.append(f"CSV parser error: {exc}")
    except OSError as exc:
        errors.append(f"dataset could not be read: {exc}")

    return summary, errors


def add_finding(findings: list[Finding], failures: list[str], warnings: list[str], control: str, status: str, message: str) -> None:
    findings.append(Finding(control=control, status=status, message=message))
    if status == "fail":
        failures.append(control)
    elif status == "warn":
        warnings.append(control)


def build_evidence(args: argparse.Namespace) -> dict[str, object]:
    path = Path(args.dataset)
    findings: list[Finding] = []
    failures: list[str] = []
    warnings: list[str] = []

    file_hash = sha256_file(path)
    if not path.exists():
        add_finding(findings, failures, warnings, "nn_ids.dataset.present", "fail", f"Dataset is missing: {path}")
        summary: dict[str, object] = {
            "rows": 0,
            "columns": 0,
            "label_column": args.label_column,
            "label_counts": {},
            "missing_cells": 0,
            "total_cells": 0,
            "duplicate_sample_rows": 0,
            "sampled_rows": 0,
            "feature_numeric_columns": 0,
            "feature_columns": [],
        }
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.present", "pass", f"Dataset is readable target: {path}")
        summary, parse_errors = summarize_dataset(path, args.label_column, args.sample_limit)
        for error in parse_errors:
            add_finding(findings, failures, warnings, "nn_ids.dataset.csv_parse", "fail", error)

    rows = int(summary.get("rows") or 0)
    columns = int(summary.get("columns") or 0)
    label_counts = dict(summary.get("label_counts") or {})
    total_cells = int(summary.get("total_cells") or 0)
    missing_cells = int(summary.get("missing_cells") or 0)
    sampled_rows = int(summary.get("sampled_rows") or 0)
    duplicate_sample_rows = int(summary.get("duplicate_sample_rows") or 0)
    feature_columns = list(summary.get("feature_columns") or [])
    numeric_features = int(summary.get("feature_numeric_columns") or 0)

    if rows < args.min_rows:
        add_finding(findings, failures, warnings, "nn_ids.dataset.rows", "fail", f"Dataset has {rows} row(s), below minimum {args.min_rows}.")
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.rows", "pass", f"Dataset has {rows} row(s).")

    if columns < 2:
        add_finding(findings, failures, warnings, "nn_ids.dataset.columns", "fail", f"Dataset has only {columns} column(s).")
    elif columns > args.max_columns:
        add_finding(findings, failures, warnings, "nn_ids.dataset.columns", "warn", f"Dataset has {columns} columns, above review target {args.max_columns}.")
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.columns", "pass", f"Dataset has {columns} column(s).")

    non_empty_labels = {label: count for label, count in label_counts.items() if label != "<missing>" and count > 0}
    if len(non_empty_labels) < args.min_classes:
        add_finding(findings, failures, warnings, "nn_ids.dataset.label_classes", "fail", f"Dataset has {len(non_empty_labels)} non-empty class(es), below minimum {args.min_classes}.")
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.label_classes", "pass", f"Dataset has {len(non_empty_labels)} non-empty class(es).")

    if rows > 0 and label_counts:
        majority = max(label_counts.values()) / rows
        if majority > args.max_class_imbalance:
            status = "warn" if args.imbalance_warn_only else "fail"
            add_finding(findings, failures, warnings, "nn_ids.dataset.class_imbalance", status, f"Majority class ratio {majority:.3f} exceeds {args.max_class_imbalance:.3f}.")
        else:
            add_finding(findings, failures, warnings, "nn_ids.dataset.class_imbalance", "pass", f"Majority class ratio {majority:.3f} is within target.")

    missing_rate = (missing_cells / total_cells) if total_cells else 0.0
    if missing_rate > args.max_missing_rate:
        add_finding(findings, failures, warnings, "nn_ids.dataset.missing_rate", "fail", f"Missing-cell rate {missing_rate:.3f} exceeds {args.max_missing_rate:.3f}.")
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.missing_rate", "pass", f"Missing-cell rate {missing_rate:.3f} is within target.")

    duplicate_rate = (duplicate_sample_rows / sampled_rows) if sampled_rows else 0.0
    if duplicate_rate > args.max_duplicate_rate:
        add_finding(findings, failures, warnings, "nn_ids.dataset.duplicate_sample_rate", "fail", f"Sample duplicate rate {duplicate_rate:.3f} exceeds {args.max_duplicate_rate:.3f}.")
    else:
        add_finding(findings, failures, warnings, "nn_ids.dataset.duplicate_sample_rate", "pass", f"Sample duplicate rate {duplicate_rate:.3f} is within target.")

    numeric_ratio = (numeric_features / len(feature_columns)) if feature_columns else 0.0
    if feature_columns and numeric_ratio > args.max_numeric_ratio:
        add_finding(findings, failures, warnings, "nn_ids.dataset.numeric_feature_ratio", "warn", f"Numeric feature ratio {numeric_ratio:.3f} is unusually high; review for IDs, timestamps, or leaked labels.")
    elif feature_columns:
        add_finding(findings, failures, warnings, "nn_ids.dataset.numeric_feature_ratio", "pass", f"Numeric feature ratio {numeric_ratio:.3f} is within review target.")

    failing_controls = sorted(set(failures))
    warning_controls = sorted(set(warnings))
    if failing_controls:
        status = "fail"
    elif warning_controls:
        status = "warn"
    else:
        status = "pass"

    return {
        "component": "nn_ids_dataset_quality",
        "generated_at": utc_now(),
        "status": status,
        "ok": status == "pass",
        "message": "NN IDS dataset-quality evidence is passive and read-only; no services, firewall rules, host state, VM state, or model files were modified.",
        "dataset": str(path),
        "dataset_sha256": file_hash,
        "thresholds": {
            "min_rows": args.min_rows,
            "min_classes": args.min_classes,
            "max_missing_rate": args.max_missing_rate,
            "max_class_imbalance": args.max_class_imbalance,
            "max_duplicate_rate": args.max_duplicate_rate,
            "max_numeric_ratio": args.max_numeric_ratio,
            "max_columns": args.max_columns,
            "sample_limit": args.sample_limit,
            "imbalance_warn_only": args.imbalance_warn_only,
        },
        "summary": summary,
        "failing_controls": failing_controls,
        "warning_controls": warning_controls,
        "findings": [finding.__dict__ for finding in findings],
        "privacy": {
            "raw_rows_included": False,
            "packet_payloads_included": False,
            "only_aggregate_counts_and_hashes": True,
        },
        "rollback": "Remove nn_ids_dataset_quality_evidence.py from build_custom_iso.sh if this optional evidence helper is not needed; no runtime state migration is required.",
    }


def render_markdown(evidence: dict[str, object]) -> str:
    summary = dict(evidence.get("summary") or {})
    lines = [
        "# NN IDS Dataset Quality Evidence",
        "",
        f"- Status: `{evidence['status']}`",
        f"- Dataset: `{evidence['dataset']}`",
        f"- Rows: `{summary.get('rows', 0)}`",
        f"- Columns: `{summary.get('columns', 0)}`",
        f"- Failing controls: `{len(evidence.get('failing_controls', []))}`",
        f"- Warning controls: `{len(evidence.get('warning_controls', []))}`",
        "",
        "## Findings",
        "",
    ]
    for finding in evidence.get("findings", []):
        lines.append(f"- `{finding['status']}` `{finding['control']}` - {finding['message']}")
    lines.extend(
        [
            "",
            "## Privacy and safety",
            "",
            "- Raw dataset rows and packet payloads are not embedded in this report.",
            "- The helper is passive and read-only and does not modify services, firewall state, host state, VM state, or model files.",
            "",
            "## Rollback",
            "",
            str(evidence.get("rollback")),
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit passive NN IDS dataset-quality evidence.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET), help="CSV dataset to inspect.")
    parser.add_argument("--label-column", default=DEFAULT_LABEL_COLUMN, help="Label column name.")
    parser.add_argument("--min-rows", type=positive_int, default=DEFAULT_MIN_ROWS)
    parser.add_argument("--min-classes", type=positive_int, default=DEFAULT_MIN_CLASSES)
    parser.add_argument("--max-missing-rate", type=bounded_rate, default=DEFAULT_MAX_MISSING_RATE)
    parser.add_argument("--max-class-imbalance", type=bounded_rate, default=DEFAULT_MAX_CLASS_IMBALANCE)
    parser.add_argument("--max-duplicate-rate", type=bounded_rate, default=DEFAULT_MAX_DUPLICATE_RATE)
    parser.add_argument("--max-numeric-ratio", type=bounded_rate, default=DEFAULT_MAX_NUMERIC_RATIO)
    parser.add_argument("--max-columns", type=positive_int, default=DEFAULT_MAX_COLUMNS)
    parser.add_argument("--sample-limit", type=positive_int, default=DEFAULT_SAMPLE_LIMIT)
    parser.add_argument("--imbalance-warn-only", action="store_true", help="Warn instead of fail on class imbalance.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", help="Optional output path.")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero unless evidence status is pass.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    evidence = build_evidence(args)
    rendered = render_markdown(evidence) if args.format == "markdown" else json.dumps(evidence, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if not args.require_pass or evidence.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
