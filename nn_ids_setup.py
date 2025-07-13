#!/usr/bin/env python3
"""nn_ids_setup.py - Download datasets and train a simple neural network IDS."""
import os
import tarfile
import urllib.request
from pathlib import Path

try:
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.neural_network import MLPClassifier
    import joblib
except ImportError:
    print("Required Python packages not installed. Please install pandas, scikit-learn, and joblib.")
    raise

DATASET_URLS = [
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/malrec_dataset.tar",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/references.tar.xz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/tools.tar.xz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/virustotal.tar.gz",
    "https://giantpanda.gtisc.gatech.edu/malrec/dataset/uuid_md5.txt",
]

DATA_DIR = Path("/opt/nnids/datasets")
MODEL_PATH = Path("/opt/nnids/ids_model.pkl")


def download_datasets() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for url in DATASET_URLS:
        fname = DATA_DIR / os.path.basename(url)
        if not fname.exists():
            print(f"Downloading {url}...")
            urllib.request.urlretrieve(url, fname)
        if tarfile.is_tarfile(fname):
            with tarfile.open(fname, "r:*") as tf:
                tf.extractall(DATA_DIR)
    print("Datasets downloaded and extracted.")


def train_model() -> None:
    csv_path = DATA_DIR / "dataset.csv"
    if not csv_path.exists():
        print(f"Training data {csv_path} not found. Skipping training.")
        return
    df = pd.read_csv(csv_path)
    if 'label' not in df.columns:
        print("CSV missing 'label' column. Skipping training.")
        return
    X = df.drop(columns=['label'])
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=20)
    clf.fit(X_train, y_train)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Model trained and saved to {MODEL_PATH}")


def main() -> None:
    download_datasets()
    train_model()


if __name__ == "__main__":
    main()
