#!/usr/bin/env python3
"""nn_os_train.py - Train a baseline model of host OS characteristics."""
import json
import platform
from pathlib import Path

import joblib
import numpy as np
from sklearn.neural_network import MLPClassifier

MODEL_PATH = Path("/opt/nnids/os_model.pkl")
FEATURE_PATH = Path("/opt/nnids/os_features.json")


def collect_features():
    """Gather basic OS metadata and convert to numeric features."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }
    FEATURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FEATURE_PATH.open("w") as f:
        json.dump(info, f)
    # Simple numeric representation using hashed values
    return np.array([[hash(v) % 1000 for v in info.values()]]), np.array([1])


def train():
    X, y = collect_features()
    clf = MLPClassifier(hidden_layer_sizes=(16, 16), max_iter=50)
    clf.fit(X, y)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"OS baseline model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
