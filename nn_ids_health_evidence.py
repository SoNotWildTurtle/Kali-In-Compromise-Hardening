#!/usr/bin/env python3
"""Emit passive NN IDS health evidence as JSON.

This utility is intentionally read-only. It inspects local model metadata, IDS
training logs, service-health logs, and optional capture/dataset files, then
emits a small JSON health document that can be consumed by
hardening_posture_summary.py or CI/release gates. It never opens network
sockets, never executes system commands, and never modifies host or VM state.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DEFAULT_MODEL = Path("/opt/nnids/ids_model.pkl")
DEFAULT_TRAIN_LOG = Path("/var/log/nn_ids_train.log")
DEFAULT_HEALTH_LOG = Path("/var/log/nn_ids_health.log")
DEFAULT_CAPTURE = Path("/opt/nnids/live_capture.csv")
DEFAULT_BASE_DATASET = Path("/opt/nnids/datasets/dataset.csv")
DEFAULT_MAX_MODEL_AGE_HOURS = 72.0
DEFAULT_MIN_F1 = 0.70
DEFAULT_MIN_ACCURACY = 0.70

METRIC_RE = re.compile(
    r"(?P<kind>Train|Retrain) accuracy:\s*(?P<accuracy>[0-9]*\.?[0-9]+)\s+f1:\s*(?P<f1>[0-9]*\.?[0-9]+)",
    re.IGNORECASE,
)
FAIL_WORDS = ("failed", "missing", "error", "traceback", "exception")
WARN_WORDS = ("restart", "restarted", "degraded", "warning")


@dataclass(frozen=True)
class MetricSnapshot:
    kind: str
    accuracy: float
    f1: float
    source_line: str


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def path_age_hours(path: Path, now: datetime) -> float | None:
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None
    return max((now - modified).total_seconds() / 3600.0, 0.0)


def read_tail(path: Path, max_lines: int) -> list[str]:
    if max_lines <= 0:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-max_lines:]


def parse_latest_metrics(lines: Iterable[str]) -> MetricSnapshot | None:
    latest: MetricSnapshot | None = None
    for line in lines:
        match = METRIC_RE.search(line)
        if not match:
            continue
        latest = MetricSnapshot(
            kind=match.group("kind").lower(),
            accuracy=float(match.group("accuracy")),
            f1=float(match.group("f1")),
            source_line=line.strip(),
        )
    return latest


def csv_row_count(path: Path) -> int | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return None


def classify_log_lines(lines: Iterable[str]) -> tuple[list[str], list[str]]:
    failing: list[str] = []
    warning: list[str] = []
    for line in lines:
        lowered = line.lower()
        if any(word in lowered for word in FAIL_WORDS):
            failing.append(line.strip())
        elif any(word in lowered for word in WARN_WORDS):
            warning.append(line.strip())
    return failing, warning


def add_file_evidence(findings: list[dict[str, str]], path: Path, control: str, message: str) -> None:
    if path.exists():
        findings.append({"control": control, "status": "pass", "message": f"{message}: {path}"})
    else:
        findings.append({"control": control, "status": "fail", "message": f"Missing {message}: {path}"})


def build_evidence(args: argparse.Namespace) -> dict[str, object]:
    now = utc_now()
    findings: list[dict[str, str]] = []
    warnings: list[str] = []
    failures: list[str] = []

    model = Path(args.model)
    train_log = Path(args.train_log)
    health_log = Path(args.health_log)
    capture = Path(args.capture)
    base_dataset = Path(args.base_dataset)

    add_file_evidence(findings, model, "nn_ids.model.present", "IDS model")
    add_file_evidence(findings, train_log, "nn_ids.training_log.present", "training log")

    model_age = path_age_hours(model, now)
    if model_age is None:
        failures.append("nn_ids.model.present")
    elif model_age > args.max_model_age_hours:
        findings.append(
            {
                "control": "nn_ids.model.freshness",
                "status": "warn",
                "message": f"Model age {model_age:.1f}h exceeds {args.max_model_age_hours:.1f}h target.",
            }
        )
        warnings.append("nn_ids.model.freshness")
    else:
        findings.append(
            {
                "control": "nn_ids.model.freshness",
                "status": "pass",
                "message": f"Model age {model_age:.1f}h is within target.",
            }
        )

    train_lines = read_tail(train_log, args.log_tail)
    latest = parse_latest_metrics(train_lines)
    if latest is None:
        findings.append(
            {
                "control": "nn_ids.metrics.present",
                "status": "warn",
                "message": "No recent accuracy/F1 line found in the training log tail.",
            }
        )
        warnings.append("nn_ids.metrics.present")
    else:
        metric_status = "pass"
        metric_messages: list[str] = []
        if latest.accuracy < args.min_accuracy:
            metric_status = "fail"
            failures.append("nn_ids.metrics.accuracy")
            metric_messages.append(f"accuracy {latest.accuracy:.3f} < {args.min_accuracy:.3f}")
        if latest.f1 < args.min_f1:
            metric_status = "fail"
            failures.append("nn_ids.metrics.f1")
            metric_messages.append(f"f1 {latest.f1:.3f} < {args.min_f1:.3f}")
        findings.append(
            {
                "control": "nn_ids.metrics.thresholds",
                "status": metric_status,
                "message": "; ".join(metric_messages)
                or f"Latest {latest.kind} metrics meet thresholds: accuracy={latest.accuracy:.3f}, f1={latest.f1:.3f}.",
            }
        )

    health_lines = read_tail(health_log, args.log_tail)
    health_failures, health_warnings = classify_log_lines(health_lines)
    if health_failures:
        failures.append("nn_ids.health_log.failures")
        findings.append(
            {
                "control": "nn_ids.health_log.failures",
                "status": "fail",
                "message": health_failures[-1],
            }
        )
    elif health_warnings:
        warnings.append("nn_ids.health_log.restarts")
        findings.append(
            {
                "control": "nn_ids.health_log.restarts",
                "status": "warn",
                "message": health_warnings[-1],
            }
        )
    elif health_log.exists():
        findings.append(
            {
                "control": "nn_ids.health_log.clean",
                "status": "pass",
                "message": "No failure or restart markers found in the health log tail.",
            }
        )
    else:
        findings.append(
            {
                "control": "nn_ids.health_log.present",
                "status": "warn",
                "message": f"Health log is not present yet: {health_log}",
            }
        )
        warnings.append("nn_ids.health_log.present")

    capture_rows = csv_row_count(capture)
    dataset_rows = csv_row_count(base_dataset)
    if capture_rows is not None:
        findings.append(
            {
                "control": "nn_ids.capture.readable",
                "status": "pass",
                "message": f"Capture file is readable with {capture_rows} non-empty row(s).",
            }
        )
    if dataset_rows is not None:
        findings.append(
            {
                "control": "nn_ids.dataset.readable",
                "status": "pass",
                "message": f"Base dataset is readable with {dataset_rows} non-empty row(s).",
            }
        )

    failing_controls = sorted(set(failures))
    warning_controls = sorted(set(warnings))
    if failing_controls:
        status = "fail"
    elif warning_controls:
        status = "warn"
    else:
        status = "pass"

    evidence: dict[str, object] = {
        "component": "nn_ids",
        "generated_at": now.isoformat(),
        "status": status,
        "ok": status == "pass",
        "message": "NN IDS evidence is passive and read-only; no services or firewall state were modified.",
        "failing_controls": failing_controls,
        "warning_controls": warning_controls,
        "thresholds": {
            "max_model_age_hours": args.max_model_age_hours,
            "min_accuracy": args.min_accuracy,
            "min_f1": args.min_f1,
            "log_tail": args.log_tail,
        },
        "paths": {
            "model": str(model),
            "train_log": str(train_log),
            "health_log": str(health_log),
            "capture": str(capture),
            "base_dataset": str(base_dataset),
        },
        "metrics": None
        if latest is None
        else {
            "kind": latest.kind,
            "accuracy": latest.accuracy,
            "f1": latest.f1,
            "source_line": latest.source_line,
        },
        "model_age_hours": model_age,
        "capture_rows": capture_rows,
        "base_dataset_rows": dataset_rows,
        "findings": findings,
    }
    return evidence


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit passive NN IDS health evidence as JSON.")
    parser.add_argument("--model", default=str(DEFAULT_MODEL), help="Path to the trained IDS model.")
    parser.add_argument("--train-log", default=str(DEFAULT_TRAIN_LOG), help="Path to IDS training metrics log.")
    parser.add_argument("--health-log", default=str(DEFAULT_HEALTH_LOG), help="Path to IDS healthcheck log.")
    parser.add_argument("--capture", default=str(DEFAULT_CAPTURE), help="Path to the live capture CSV.")
    parser.add_argument("--base-dataset", default=str(DEFAULT_BASE_DATASET), help="Path to the base IDS dataset CSV.")
    parser.add_argument("--max-model-age-hours", type=positive_float, default=DEFAULT_MAX_MODEL_AGE_HOURS)
    parser.add_argument("--min-accuracy", type=positive_float, default=DEFAULT_MIN_ACCURACY)
    parser.add_argument("--min-f1", type=positive_float, default=DEFAULT_MIN_F1)
    parser.add_argument("--log-tail", type=positive_int, default=200, help="Number of trailing log lines to inspect.")
    parser.add_argument("--output", help="Optional file to write JSON evidence to instead of stdout.")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the generated evidence passes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    evidence = build_evidence(args)
    rendered = json.dumps(evidence, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if not args.require_pass or evidence.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
