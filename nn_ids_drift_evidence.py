#!/usr/bin/env python3
"""Emit passive NN IDS feature-drift evidence as JSON.

MINC - Defensive validation only. This utility reads baseline/current feature
statistics and produces machine-readable drift evidence for release gates,
dashboards, and incident review. It never opens network sockets, executes remote
commands, changes firewall state, or modifies host/VM configuration.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from nn_ids_feature_schema import FEATURE_NAMES, population_stability_index

DEFAULT_WARN_PSI = 0.10
DEFAULT_FAIL_PSI = 0.25
DEFAULT_WARN_MEAN_SHIFT = 2.0
DEFAULT_FAIL_MEAN_SHIFT = 4.0
DEFAULT_WARN_MISSING_DELTA = 0.05
DEFAULT_FAIL_MISSING_DELTA = 0.15


@dataclass(frozen=True)
class FeatureDrift:
    """Normalized drift evidence for one IDS feature."""

    feature: str
    status: str
    psi: float | None
    mean_shift_sigma: float | None
    missing_rate_delta: float | None
    messages: tuple[str, ...]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finite_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return payload


def _feature_payload(payload: Mapping[str, Any], feature: str) -> Mapping[str, Any]:
    features = payload.get("features")
    if isinstance(features, Mapping):
        value = features.get(feature, {})
        return value if isinstance(value, Mapping) else {}
    value = payload.get(feature, {})
    return value if isinstance(value, Mapping) else {}


def _samples(payload: Mapping[str, Any]) -> list[float]:
    values = payload.get("samples") or payload.get("values") or []
    if not isinstance(values, list):
        return []
    return [number for number in (_finite_float(value) for value in values) if number is not None]


def _mean_shift_sigma(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> float | None:
    baseline_mean = _finite_float(baseline.get("mean"))
    current_mean = _finite_float(current.get("mean"))
    if baseline_mean is None or current_mean is None:
        return None
    baseline_std = _finite_float(baseline.get("std") or baseline.get("stdev") or baseline.get("sigma"))
    denominator = max(abs(baseline_std or 0.0), 1.0)
    return abs(current_mean - baseline_mean) / denominator


def _missing_rate_delta(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> float | None:
    baseline_missing = _finite_float(baseline.get("missing_rate"))
    current_missing = _finite_float(current.get("missing_rate"))
    if baseline_missing is None or current_missing is None:
        return None
    return abs(current_missing - baseline_missing)


def _status_rank(status: str) -> int:
    return {"pass": 0, "warn": 1, "fail": 2}.get(status, 2)


def _worse(left: str, right: str) -> str:
    return left if _status_rank(left) >= _status_rank(right) else right


def evaluate_feature(feature: str, baseline: Mapping[str, Any], current: Mapping[str, Any], args: argparse.Namespace) -> FeatureDrift:
    messages: list[str] = []
    status = "pass"

    base_samples = _samples(baseline)
    current_samples = _samples(current)
    psi: float | None = None
    if base_samples and current_samples:
        psi = population_stability_index(base_samples, current_samples)
        if psi >= args.fail_psi:
            status = _worse(status, "fail")
            messages.append(f"PSI {psi:.3f} >= fail threshold {args.fail_psi:.3f}")
        elif psi >= args.warn_psi:
            status = _worse(status, "warn")
            messages.append(f"PSI {psi:.3f} >= warn threshold {args.warn_psi:.3f}")
    else:
        messages.append("sample arrays unavailable; PSI not computed")

    mean_shift = _mean_shift_sigma(baseline, current)
    if mean_shift is None:
        messages.append("mean/std statistics unavailable; sigma shift not computed")
    elif mean_shift >= args.fail_mean_shift:
        status = _worse(status, "fail")
        messages.append(f"mean shift {mean_shift:.2f}σ >= fail threshold {args.fail_mean_shift:.2f}σ")
    elif mean_shift >= args.warn_mean_shift:
        status = _worse(status, "warn")
        messages.append(f"mean shift {mean_shift:.2f}σ >= warn threshold {args.warn_mean_shift:.2f}σ")

    missing_delta = _missing_rate_delta(baseline, current)
    if missing_delta is not None:
        if missing_delta >= args.fail_missing_delta:
            status = _worse(status, "fail")
            messages.append(
                f"missing-rate delta {missing_delta:.3f} >= fail threshold {args.fail_missing_delta:.3f}"
            )
        elif missing_delta >= args.warn_missing_delta:
            status = _worse(status, "warn")
            messages.append(
                f"missing-rate delta {missing_delta:.3f} >= warn threshold {args.warn_missing_delta:.3f}"
            )

    if not messages:
        messages.append("feature drift is within configured thresholds")

    return FeatureDrift(
        feature=feature,
        status=status,
        psi=psi,
        mean_shift_sigma=mean_shift,
        missing_rate_delta=missing_delta,
        messages=tuple(messages),
    )


def build_evidence(args: argparse.Namespace) -> dict[str, Any]:
    baseline_path = Path(args.baseline)
    current_path = Path(args.current)
    baseline = _load_json(baseline_path)
    current = _load_json(current_path)
    feature_names = list(dict.fromkeys(args.feature or FEATURE_NAMES))

    results = [
        evaluate_feature(
            feature,
            _feature_payload(baseline, feature),
            _feature_payload(current, feature),
            args,
        )
        for feature in feature_names
    ]
    failing_controls = [f"nn_ids.drift.{result.feature}" for result in results if result.status == "fail"]
    warning_controls = [f"nn_ids.drift.{result.feature}" for result in results if result.status == "warn"]

    if failing_controls:
        status = "fail"
    elif warning_controls:
        status = "warn"
    else:
        status = "pass"

    return {
        "component": "nn_ids_drift",
        "generated_at": utc_now(),
        "status": status,
        "ok": status == "pass",
        "message": "NN IDS drift evidence is passive and read-only; no host or VM state was modified.",
        "baseline": str(baseline_path),
        "current": str(current_path),
        "thresholds": {
            "warn_psi": args.warn_psi,
            "fail_psi": args.fail_psi,
            "warn_mean_shift": args.warn_mean_shift,
            "fail_mean_shift": args.fail_mean_shift,
            "warn_missing_delta": args.warn_missing_delta,
            "fail_missing_delta": args.fail_missing_delta,
        },
        "failing_controls": failing_controls,
        "warning_controls": warning_controls,
        "features": [
            {
                "feature": result.feature,
                "status": result.status,
                "psi": result.psi,
                "mean_shift_sigma": result.mean_shift_sigma,
                "missing_rate_delta": result.missing_rate_delta,
                "messages": list(result.messages),
            }
            for result in results
        ],
    }


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit passive NN IDS feature-drift evidence as JSON.")
    parser.add_argument("--baseline", required=True, help="Baseline feature statistics JSON file.")
    parser.add_argument("--current", required=True, help="Current feature statistics JSON file.")
    parser.add_argument("--feature", action="append", help="Feature to evaluate; defaults to the canonical IDS schema.")
    parser.add_argument("--warn-psi", type=non_negative_float, default=DEFAULT_WARN_PSI)
    parser.add_argument("--fail-psi", type=non_negative_float, default=DEFAULT_FAIL_PSI)
    parser.add_argument("--warn-mean-shift", type=non_negative_float, default=DEFAULT_WARN_MEAN_SHIFT)
    parser.add_argument("--fail-mean-shift", type=non_negative_float, default=DEFAULT_FAIL_MEAN_SHIFT)
    parser.add_argument("--warn-missing-delta", type=non_negative_float, default=DEFAULT_WARN_MISSING_DELTA)
    parser.add_argument("--fail-missing-delta", type=non_negative_float, default=DEFAULT_FAIL_MISSING_DELTA)
    parser.add_argument("--output", help="Optional path to write JSON evidence instead of stdout.")
    parser.add_argument("--require-pass", action="store_true", help="Exit non-zero unless the drift evidence passes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        evidence = build_evidence(args)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"nn_ids_drift_evidence error: {exc}", file=sys.stderr)
        return 2
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
