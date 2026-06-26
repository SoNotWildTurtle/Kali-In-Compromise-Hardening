#!/usr/bin/env python3
"""Download datasets and train a schema-bound neural network IDS."""

from pathlib import Path
import hashlib
import os
import tarfile
import urllib.request

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

try:
    import joblib
    import numpy as np
    import pandas as pd
    from packet_sanitizer import sanitize_csv
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    from nn_ids_feature_schema import (
        save_feature_schema,
        select_training_columns,
    )
except ImportError:
    print(
        "Required Python packages not installed. Please install pandas, "
        "scikit-learn, numpy, and joblib."
    )
    raise

SANITIZE_ENABLED = os.getenv("NN_IDS_SANITIZE", "1") == "1"

DATASET_URLS = [
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/malrec_dataset.tar",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/references.tar.xz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/tools.tar.xz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/virustotal.tar.gz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/uuid_md5.txt",
]

# Placeholder SHA256 hashes for verifying dataset integrity. Replace with the
# official values if available.
DATASET_HASHES = {
    "malrec_dataset.tar": "e3b0c44298fc1c149afbf4c8996fb924",  # example
    "references.tar.xz": "e3b0c44298fc1c149afbf4c8996fb924",
    "tools.tar.xz": "e3b0c44298fc1c149afbf4c8996fb924",
    "virustotal.tar.gz": "e3b0c44298fc1c149afbf4c8996fb924",
    "uuid_md5.txt": "e3b0c44298fc1c149afbf4c8996fb924",
}

DATA_DIR = Path("/opt/nnids/datasets")
MODEL_PATH = Path("/opt/nnids/ids_model.pkl")
METRICS_PATH = Path("/var/log/nn_ids_train.log")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_datasets() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for url in DATASET_URLS:
        fname = DATA_DIR / os.path.basename(url)
        if not fname.exists():
            print(f"Downloading {url}...")
            urllib.request.urlretrieve(url, fname)
        expected = DATASET_HASHES.get(fname.name)
        if expected and _sha256(fname) != expected:
            print(f"Hash mismatch for {fname}. Redownloading...")
            urllib.request.urlretrieve(url, fname)
            if _sha256(fname) != expected:
                print(f"Warning: {fname} failed integrity check.")
        if tarfile.is_tarfile(fname):
            with tarfile.open(fname, "r:*") as tf:
                tf.extractall(DATA_DIR)
    print("Datasets downloaded and extracted.")


def _load_training_frame(csv_path: Path) -> pd.DataFrame:
    sanitized = DATA_DIR / "dataset_clean.csv"
    if SANITIZE_ENABLED:
        sanitize_csv(csv_path, sanitized)
        return pd.read_csv(sanitized)
    return pd.read_csv(csv_path)


def _drop_numeric_outliers(df: pd.DataFrame) -> pd.DataFrame:
    numeric = df.select_dtypes(include=["number"]).columns
    if numeric.empty:
        return df
    std = df[numeric].std(ddof=0).replace(0, np.nan)
    zscores = (df[numeric] - df[numeric].mean()) / std
    return df[(zscores.abs().fillna(0) < 3).all(axis=1)]


def train_model() -> None:
    csv_path = DATA_DIR / "dataset.csv"
    if not csv_path.exists():
        print(f"Training data {csv_path} not found. Skipping training.")
        return

    df = _load_training_frame(csv_path).drop_duplicates()
    df = _drop_numeric_outliers(df)
    X, y = select_training_columns(df)
    save_feature_schema()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )

    noise = pd.DataFrame(
        data=(0.01 * np.random.default_rng(42).standard_normal(X_train.shape)),
        columns=X_train.columns,
        index=X_train.index,
    )
    aug_X = pd.concat([X_train, X_train + noise], ignore_index=True)
    aug_y = pd.concat([y_train, y_train], ignore_index=True)

    clf = Pipeline(
        steps=[
            ("scale", StandardScaler()),
            (
                "mlp",
                MLPClassifier(
                    hidden_layer_sizes=(64, 64),
                    max_iter=50,
                    random_state=42,
                ),
            ),
        ]
    )
    clf.fit(aug_X, aug_y)
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, zero_division=0)
    precision = precision_score(y_test, preds, zero_division=0)
    recall = recall_score(y_test, preds, zero_division=0)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with METRICS_PATH.open("a", encoding="utf-8") as log:
        log.write(
            "Initial training "
            f"accuracy={acc:.4f} f1={f1:.4f} "
            f"precision={precision:.4f} recall={recall:.4f}\n"
        )
    print(f"Model trained and saved to {MODEL_PATH}")


def main() -> None:
    download_datasets()
    train_model()


if __name__ == "__main__":
    main()
