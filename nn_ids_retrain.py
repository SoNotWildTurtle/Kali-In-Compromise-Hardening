#!/usr/bin/env python3
"""nn_ids_retrain.py - Retrain neural network IDS with captured traffic."""
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
import joblib

DATA_DIR = Path("/opt/nnids")
MODEL_PATH = DATA_DIR / "ids_model.pkl"
BASE_DATASET = DATA_DIR / "datasets" / "dataset.csv"
CAPTURE_FILE = DATA_DIR / "live_capture.csv"


def main():
    if not BASE_DATASET.exists() or not CAPTURE_FILE.exists():
        return
    df_base = pd.read_csv(BASE_DATASET)
    df_cap = pd.read_csv(CAPTURE_FILE, header=None,
                         names=["len", "ttl", "dport", "flags", "label"])
    df = pd.concat([df_base, df_cap], ignore_index=True)
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=20)
    clf.fit(X_train, y_train)
    joblib.dump(clf, MODEL_PATH)
    CAPTURE_FILE.unlink()


if __name__ == "__main__":
    main()
