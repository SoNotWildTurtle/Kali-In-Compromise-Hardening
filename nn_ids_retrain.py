#!/usr/bin/env python3
"""nn_ids_retrain.py - Retrain neural network IDS with captured traffic."""
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, f1_score
import numpy as np
import joblib
import fcntl
from packet_sanitizer import sanitize_csv

DATA_DIR = Path("/opt/nnids")
MODEL_PATH = DATA_DIR / "ids_model.pkl"
BASE_DATASET = DATA_DIR / "datasets" / "dataset.csv"
CAPTURE_FILE = DATA_DIR / "live_capture.csv"


def main():
    if not BASE_DATASET.exists() or not CAPTURE_FILE.exists():
        return
    base_clean = DATA_DIR / 'datasets/dataset_clean.csv'
    sanitize_csv(BASE_DATASET, base_clean)
    df_base = pd.read_csv(base_clean)
    with CAPTURE_FILE.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        df_cap = pd.read_csv(f, header=None,
                             names=["len", "ttl", "dport", "flags", "label"])
        f.seek(0)
        f.truncate()
        fcntl.flock(f, fcntl.LOCK_UN)
    cap_clean = DATA_DIR / 'capture_clean.csv'
    df_cap.to_csv(cap_clean, index=False)
    sanitize_csv(cap_clean, cap_clean)
    df_cap = pd.read_csv(cap_clean)
    df = pd.concat([df_base, df_cap], ignore_index=True).drop_duplicates()

    numeric = df.select_dtypes(include=['number']).columns
    if not numeric.empty:
        zscores = (df[numeric] - df[numeric].mean()) / df[numeric].std(ddof=0)
        df = df[(zscores.abs() < 3).all(axis=1)]

    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    noise = pd.DataFrame(0.01 * np.random.randn(*X_train.shape), columns=X_train.columns)
    aug_X = pd.concat([X_train, X_train + noise])
    aug_y = pd.concat([y_train, y_train])

    clf = MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=20)
    clf.fit(aug_X, aug_y)
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, zero_division=0)
    joblib.dump(clf, MODEL_PATH)
    with open('/var/log/nn_ids_train.log', 'a') as log:
        log.write(f"Retrain accuracy: {acc:.2f} f1: {f1:.2f}\n")
    joblib.dump(clf, MODEL_PATH)

if __name__ == "__main__":
    main()
