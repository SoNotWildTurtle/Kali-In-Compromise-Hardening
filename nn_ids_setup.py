#!/usr/bin/env python3
"""nn_ids_setup.py - Download datasets and train a simple neural network IDS."""
import os
import tarfile
import urllib.request
import hashlib
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    roc_auc_score,
)

try:
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
    import numpy as np
    import joblib
    from packet_sanitizer import sanitize_csv
    from nn_ids_adversarial import generate_adversarial
except ImportError:
    print("Required Python packages not installed. Please install pandas, scikit-learn, and joblib.")
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


def train_model() -> None:
    csv_path = DATA_DIR / "dataset.csv"
    if not csv_path.exists():
        print(f"Training data {csv_path} not found. Skipping training.")
        return
    sanitized = DATA_DIR / "dataset_clean.csv"
    if SANITIZE_ENABLED:
        sanitize_csv(csv_path, sanitized)
        df = pd.read_csv(sanitized)
    else:
        df = pd.read_csv(csv_path)
    if 'label' not in df.columns:
        print("CSV missing 'label' column. Skipping training.")
        return
    # basic sanitization against poisoning: drop exact duplicates
    df = df.drop_duplicates()

    # add synthetic adversarial samples to harden the model
    adv_samples = generate_adversarial()
    adv_df = pd.DataFrame(adv_samples, columns=["len", "ttl", "dport", "flags", "label", "reason"])
    adv_df.to_csv(DATA_DIR / "adversarial.csv", index=False)
    df = pd.concat([df, adv_df.drop(columns=["reason"])], ignore_index=True)

    # remove obvious outliers to defend against poisoning attempts
    numeric = df.select_dtypes(include=['number']).columns
    if not numeric.empty:
        zscores = (df[numeric] - df[numeric].mean()) / df[numeric].std(ddof=0)
        df = df[(zscores.abs() < 3).all(axis=1)]

    X = df.drop(columns=['label'])
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    # slight noise added to inputs to increase robustness against randomization
    noise = pd.DataFrame(
        data=(0.01 * np.random.randn(*X_train.shape)),
        columns=X_train.columns,
    )
    aug_X = pd.concat([X_train, X_train + noise])
    aug_y = pd.concat([y_train, y_train])

    clf = MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=20)
    clf.fit(aug_X, aug_y)
    preds = clf.predict(X_test)
    probas = clf.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds, zero_division=0)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    roc = roc_auc_score(y_test, probas)
    cm = confusion_matrix(y_test, preds).tolist()
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    with open('/var/log/nn_ids_train.log', 'a') as log:
        log.write(
            f"Initial training accuracy: {acc:.2f} f1: {f1:.2f} precision: {prec:.2f} "
            f"recall: {rec:.2f} roc_auc: {roc:.2f} confusion: {cm}\n"
        )
    print(f"Model trained and saved to {MODEL_PATH}")


def main() -> None:
    download_datasets()
    train_model()


if __name__ == "__main__":
    main()
