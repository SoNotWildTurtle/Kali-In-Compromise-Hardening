#!/usr/bin/env python3
"""NN IDS feature schema and lightweight drift checks.

Defensive purpose: keep training and live inference aligned so the IDS does not
silently learn from malformed data or score packets with the wrong feature order.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

FEATURE_NAMES = ["len", "ttl", "dport", "tcp_flags"]
LABEL_COLUMN = "label"
DEFAULT_SCHEMA_PATH = Path("/opt/nnids/feature_schema.json")
DEFAULT_DRIFT_PATH = Path("/var/log/nn_ids_feature_drift.log")

FEATURE_RANGES: Mapping[str, tuple[float, float]] = {
    "len": (1.0, 65535.0),
    "ttl": (0.0, 255.0),
    "dport": (0.0, 65535.0),
    "tcp_flags": (0.0, 255.0),
}


@dataclass(frozen=True)
class SchemaCheck:
    """Result from feature schema validation."""

    ok: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def _as_float(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def feature_schema() -> dict[str, object]:
    """Return the canonical schema used by training and live inference."""

    return {
        "version": 1,
        "feature_order": FEATURE_NAMES,
        "label_column": LABEL_COLUMN,
        "ranges": {name: list(bounds) for name, bounds in FEATURE_RANGES.items()},
        "notes": [
            "Feature order is part of the model contract.",
            "Training data may include extra columns only if mapped away.",
            "Live inference must produce exactly this ordered vector.",
        ],
    }


def save_feature_schema(path: Path = DEFAULT_SCHEMA_PATH) -> None:
    """Persist the canonical schema for audit, rollback, and PR review."""

    path.parent.mkdir(parents=True, exist_ok=True)
    schema_json = json.dumps(feature_schema(), indent=2, sort_keys=True)
    path.write_text(f"{schema_json}\n", encoding="utf-8")


def validate_columns(columns: Iterable[str], require_label: bool = True) -> SchemaCheck:
    """Validate that a dataset exposes the expected feature columns."""

    seen = list(columns)
    errors: list[str] = []
    warnings: list[str] = []

    missing = [name for name in FEATURE_NAMES if name not in seen]
    if missing:
        errors.append(f"missing required feature column(s): {', '.join(missing)}")

    if require_label and LABEL_COLUMN not in seen:
        errors.append(f"missing required label column: {LABEL_COLUMN}")

    extras = [name for name in seen if name not in FEATURE_NAMES and name != LABEL_COLUMN]
    if extras:
        warnings.append(f"ignoring extra column(s): {', '.join(extras)}")

    return SchemaCheck(ok=not errors, errors=tuple(errors), warnings=tuple(warnings))


def validate_feature_vector(values: Sequence[object]) -> SchemaCheck:
    """Validate a live packet feature vector before model inference."""

    errors: list[str] = []
    if len(values) != len(FEATURE_NAMES):
        return SchemaCheck(
            ok=False,
            errors=(
                f"expected {len(FEATURE_NAMES)} features, "
                f"received {len(values)}"
            ),
            warnings=(),
        )

    for name, value in zip(FEATURE_NAMES, values):
        number = _as_float(value)
        if number is None:
            errors.append(f"{name} is not a finite number")
            continue
        low, high = FEATURE_RANGES[name]
        if number < low or number > high:
            errors.append(
                f"{name}={number:g} outside expected range {low:g}..{high:g}"
            )

    return SchemaCheck(ok=not errors, errors=tuple(errors), warnings=())


def select_training_columns(dataframe):
    """Return X, y in canonical feature order after validating dataframe columns."""

    check = validate_columns(dataframe.columns)
    if not check.ok:
        raise ValueError("; ".join(check.errors))
    return dataframe[FEATURE_NAMES], dataframe[LABEL_COLUMN]


def population_stability_index(
    expected: Sequence[float],
    actual: Sequence[float],
    buckets: int = 10,
) -> float:
    """Compute a small PSI drift score without requiring heavy dependencies."""

    exp = sorted(value for value in (_as_float(v) for v in expected) if value is not None)
    act = [value for value in (_as_float(v) for v in actual) if value is not None]
    if len(exp) < buckets or not act:
        return 0.0

    cut_points = []
    for idx in range(1, buckets):
        position = round(len(exp) * idx / buckets)
        cut_points.append(exp[max(0, min(len(exp) - 1, position))])
    exp_counts = [0] * buckets
    act_counts = [0] * buckets

    def bucket_index(value: float) -> int:
        for idx, cut in enumerate(cut_points):
            if value <= cut:
                return idx
        return buckets - 1

    for value in exp:
        exp_counts[bucket_index(value)] += 1
    for value in act:
        act_counts[bucket_index(value)] += 1

    total_exp = sum(exp_counts)
    total_act = sum(act_counts)
    epsilon = 1e-6
    psi = 0.0
    for exp_count, act_count in zip(exp_counts, act_counts):
        exp_pct = max(exp_count / total_exp, epsilon)
        act_pct = max(act_count / total_act, epsilon)
        psi += (act_pct - exp_pct) * math.log(act_pct / exp_pct)
    return psi


def write_drift_report(
    scores: Mapping[str, float],
    path: Path = DEFAULT_DRIFT_PATH,
) -> None:
    """Append drift scores in an auditable, line-oriented JSON format."""

    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(dict(scores), sort_keys=True)
    path.open("a", encoding="utf-8").write(f"{line}\n")


def main() -> None:
    save_feature_schema()
    print(f"Wrote NN IDS feature schema to {DEFAULT_SCHEMA_PATH}")


if __name__ == "__main__":
    main()
