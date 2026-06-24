#!/usr/bin/env python3
"""nn_ids_model_audit.py - Defensive quality audit for the Kali NN IDS.

MINC - This script evaluates a locally trained IDS model for class imbalance,
concept drift, simple perturbation robustness, and feature importance drift. It
only reads local IDS artifacts and writes local audit reports; it does not scan,
attack, evade, or contact remote systems.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

MODEL_PATH = Path(os.getenv("NN_IDS_MODEL", "/opt/nnids/ids_model.pkl"))
DATA_DIR = Path(os.getenv("NN_IDS_DATA_DIR", "/opt/nnids/datasets"))
DATASET_PATH = Path(os.getenv("NN_IDS_AUDIT_DATASET", str(DATA_DIR / "dataset_clean.csv")))
RAW_DATASET_PATH = DATA_DIR / "dataset.csv"
AUDIT_DIR = Path(os.getenv("NN_IDS_AUDIT_DIR", "/opt/nnids/audit"))
REPORT_PATH = Path(os.getenv("NN_IDS_AUDIT_REPORT", "/var/log/nn_ids_model_audit.json"))
BASELINE_STATS_PATH = AUDIT_DIR / "baseline_feature_stats.json"
BASELINE_IMPORTANCE_PATH = AUDIT_DIR / "baseline_feature_importance.json"
MAX_ROWS = int(os.getenv("NN_IDS_AUDIT_MAX_ROWS", "50000"))
RANDOM_STATE = int(os.getenv("NN_IDS_RANDOM_STATE", "42"))
PERTURBATION_LEVELS = [0.0, 0.005, 0.01, 0.02, 0.05]


def _status(message: str, **extra: Any) -> Dict[str, Any]:
    return {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "message": message, **extra}


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o640)


def _load_dataset() -> pd.DataFrame:
    path = DATASET_PATH if DATASET_PATH.exists() else RAW_DATASET_PATH
    if not path.exists():
        raise FileNotFoundError(f"No IDS dataset found at {DATASET_PATH} or {RAW_DATASET_PATH}")
    df = pd.read_csv(path)
    if len(df) > MAX_ROWS:
        df = df.sample(n=MAX_ROWS, random_state=RANDOM_STATE)
    if "label" not in df.columns:
        raise ValueError("IDS audit dataset must contain a 'label' column")
    return df.drop_duplicates()


def _numeric_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    y = df["label"]
    x = df.drop(columns=["label"])
    x = x.select_dtypes(include=["number"]).replace([np.inf, -np.inf], np.nan)
    x = x.fillna(x.median(numeric_only=True)).fillna(0)
    if x.empty:
        raise ValueError("IDS audit dataset contains no numeric features")
    return x, y


def _metric_average(y: pd.Series) -> str:
    """Use binary scoring for 0/1 IDS labels, otherwise weighted multiclass scoring."""
    values = set(y.dropna().unique().tolist())
    if values.issubset({0, 1, 0.0, 1.0, "0", "1"}) and len(values) <= 2:
        return "binary"
    return "weighted"


def _class_distribution(y: pd.Series) -> Dict[str, int]:
    return {str(k): int(v) for k, v in y.value_counts(dropna=False).sort_index().items()}


def _safe_predict_proba(model: Any, x: pd.DataFrame) -> np.ndarray | None:
    if hasattr(model, "predict_proba"):
        try:
            return model.predict_proba(x)
        except Exception:
            return None
    return None


def _feature_stats(x: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    desc: Dict[str, Dict[str, float]] = {}
    for col in x.columns:
        s = x[col].astype(float)
        desc[col] = {
            "mean": float(s.mean()),
            "std": float(s.std(ddof=0)),
            "min": float(s.min()),
            "max": float(s.max()),
            "median": float(s.median()),
        }
    return desc


def _drift_report(current: Dict[str, Dict[str, float]]) -> Dict[str, Any]:
    if not BASELINE_STATS_PATH.exists():
        _write_json(BASELINE_STATS_PATH, {"feature_stats": current})
        return {"baseline_created": True, "max_mean_z": 0.0, "shifted_features": []}

    baseline = json.loads(BASELINE_STATS_PATH.read_text(encoding="utf-8")).get("feature_stats", {})
    shifted: List[Dict[str, Any]] = []
    max_mean_z = 0.0
    for feature, stats in current.items():
        old = baseline.get(feature)
        if not old:
            shifted.append({"feature": feature, "reason": "new_feature"})
            continue
        denom = max(float(old.get("std", 0.0)), 1e-9)
        mean_z = abs(float(stats["mean"]) - float(old.get("mean", 0.0))) / denom
        max_mean_z = max(max_mean_z, mean_z)
        if mean_z >= 3.0:
            shifted.append({"feature": feature, "mean_z": round(mean_z, 4)})
    return {"baseline_created": False, "max_mean_z": round(max_mean_z, 4), "shifted_features": shifted[:25]}


def _robustness_index(model: Any, x: pd.DataFrame, y: pd.Series, average: str) -> Dict[str, Any]:
    rng = np.random.default_rng(RANDOM_STATE)
    scores: List[Dict[str, float]] = []
    x_float = x.astype(float)
    std = x_float.std(ddof=0).replace(0, 1.0).to_numpy()
    for level in PERTURBATION_LEVELS:
        if level == 0.0:
            perturbed = x_float
        else:
            noise = rng.normal(0.0, level, size=x_float.shape) * std
            perturbed = pd.DataFrame(x_float.to_numpy() + noise, columns=x_float.columns, index=x_float.index)
        preds = model.predict(perturbed)
        scores.append({
            "noise_level": float(level),
            "accuracy": float(accuracy_score(y, preds)),
            "f1": float(f1_score(y, preds, average=average, zero_division=0)),
        })
    accuracies = [item["accuracy"] for item in scores]
    ri = float(np.trapz(accuracies, PERTURBATION_LEVELS) / max(PERTURBATION_LEVELS))
    return {"robustness_index": round(ri, 6), "perturbation_scores": scores}


def _importance_report(model: Any, x: pd.DataFrame, y: pd.Series, average: str) -> Dict[str, Any]:
    sample_size = min(len(x), 2000)
    x_sample = x.sample(sample_size, random_state=RANDOM_STATE) if len(x) > sample_size else x
    y_sample = y.loc[x_sample.index]
    scoring = "f1" if average == "binary" else "f1_weighted"
    result = permutation_importance(
        model,
        x_sample,
        y_sample,
        n_repeats=5,
        random_state=RANDOM_STATE,
        scoring=scoring,
    )
    importance = {
        col: float(mean)
        for col, mean in sorted(zip(x_sample.columns, result.importances_mean), key=lambda item: abs(item[1]), reverse=True)
    }
    top = list(importance.items())[:15]

    if not BASELINE_IMPORTANCE_PATH.exists():
        _write_json(BASELINE_IMPORTANCE_PATH, {"feature_importance": importance})
        drift = {"baseline_created": True, "top_feature_changes": []}
    else:
        baseline = json.loads(BASELINE_IMPORTANCE_PATH.read_text(encoding="utf-8")).get("feature_importance", {})
        changes = []
        for feature, current_value in top:
            old_value = float(baseline.get(feature, 0.0))
            changes.append({
                "feature": feature,
                "current": round(current_value, 8),
                "baseline": round(old_value, 8),
                "delta": round(current_value - old_value, 8),
            })
        drift = {"baseline_created": False, "top_feature_changes": changes}

    return {"top_features": [{"feature": k, "importance": round(v, 8)} for k, v in top], "importance_drift": drift}


def audit_model() -> Dict[str, Any]:
    model = joblib.load(MODEL_PATH)
    df = _load_dataset()
    x, y = _numeric_xy(df)
    average = _metric_average(y)
    stratify = y if y.nunique() > 1 and y.value_counts().min() >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=stratify,
    )
    del x_train, y_train

    preds = model.predict(x_test)
    proba = _safe_predict_proba(model, x_test)
    stats = _feature_stats(x)
    cm = confusion_matrix(y_test, preds).tolist()

    report: Dict[str, Any] = _status(
        "nn_ids_model_audit_complete",
        model_path=str(MODEL_PATH),
        dataset_path=str(DATASET_PATH if DATASET_PATH.exists() else RAW_DATASET_PATH),
        rows=int(len(df)),
        features=list(x.columns),
        class_distribution=_class_distribution(y),
        metric_average=average,
        metrics={
            "accuracy": float(accuracy_score(y_test, preds)),
            "balanced_accuracy": float(balanced_accuracy_score(y_test, preds)),
            "precision": float(precision_score(y_test, preds, average=average, zero_division=0)),
            "recall": float(recall_score(y_test, preds, average=average, zero_division=0)),
            "f1": float(f1_score(y_test, preds, average=average, zero_division=0)),
            "confusion_matrix": cm,
        },
        probability_available=proba is not None,
        drift=_drift_report(stats),
        robustness=_robustness_index(model, x_test, y_test, average),
        explainability=_importance_report(model, x_test, y_test, average),
    )
    _write_json(REPORT_PATH, report)
    return report


def main() -> int:
    try:
        report = audit_model()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # Defensive automation should fail closed and log why.
        payload = _status("nn_ids_model_audit_failed", error=str(exc))
        _write_json(REPORT_PATH, payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
