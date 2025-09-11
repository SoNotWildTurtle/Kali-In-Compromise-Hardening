#!/usr/bin/env python3
"""Train and run a GA Tech based malicious process detector.

This helper downloads the Georgia Tech malicious process dataset, augments it
with any locally flagged samples, trains a tiny neural network, and scans the
currently running processes.  Training metrics are appended to
``/var/log/ga_tech_proc_train.log`` and any newly flagged process hashes are
stored in ``/opt/nnids/ga_proc_local.txt`` so future runs can evolve the model.
"""

import argparse
import hashlib
import os
import urllib.request
from datetime import datetime
from pathlib import Path

import psutil

try:  # pragma: no cover - dependencies may be missing in minimal envs
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    import numpy as np
    import joblib
except Exception:  # pragma: no cover - libraries may not be installed in build env
    MLPClassifier = None


DATA_URL = "https://giantpanda.gtisc.gatech.edu/malrec/dataset/uuid_md5.txt"
DATA_FILE = Path("/opt/nnids/ga_proc_dataset.txt")
LOCAL_MALICIOUS = Path("/opt/nnids/ga_proc_local.txt")
MODEL_FILE = Path("/opt/nnids/ga_proc_model.pkl")
ALERT_LOG = Path("/var/log/ga_tech_proc_alerts.log")
TRAIN_LOG = Path("/var/log/ga_tech_proc_train.log")


def download_dataset() -> None:
    """Fetch the GA Tech malicious process dataset if missing."""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if DATA_FILE.exists():
        return
    try:
        urllib.request.urlretrieve(DATA_URL, DATA_FILE)
    except Exception:
        pass


def _load_malicious_hashes():
    """Return md5 hashes from the GA dataset and locally flagged samples."""
    hashes = []
    if DATA_FILE.exists():
        with DATA_FILE.open() as f:
            for line in f:
                parts = line.strip().split()
                if parts:
                    hashes.append(parts[-1])
    if LOCAL_MALICIOUS.exists():
        with LOCAL_MALICIOUS.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    hashes.append(line)
    return hashes


def _append_local_hash(md5: str) -> None:
    """Store md5 in the local malicious hash file if new."""
    LOCAL_MALICIOUS.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if LOCAL_MALICIOUS.exists():
        with LOCAL_MALICIOUS.open() as f:
            existing = {line.strip() for line in f if line.strip()}
    if md5 not in existing:
        with LOCAL_MALICIOUS.open("a") as f:
            f.write(md5 + "\n")


def train_model() -> None:
    """Train a small neural network and log evaluation metrics."""
    if MLPClassifier is None:
        return
    hashes = _load_malicious_hashes()
    malicious = [[int(c, 16) for c in h[:32]] for h in hashes]
    benign = []
    for proc in psutil.process_iter(["exe"]):
        exe = proc.info.get("exe")
        if not exe or not os.path.exists(exe):
            continue
        try:
            with open(exe, "rb") as fh:
                md5 = hashlib.md5(fh.read()).hexdigest()
            benign.append([int(c, 16) for c in md5[:32]])
        except Exception:
            continue
        if len(benign) >= len(malicious):
            break
    if not malicious or not benign:
        return
    X = np.array(malicious + benign)
    y = np.array([1] * len(malicious) + [0] * len(benign))
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    clf = MLPClassifier(hidden_layer_sizes=(32,), max_iter=200)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    TRAIN_LOG.parent.mkdir(parents=True, exist_ok=True)
    with TRAIN_LOG.open("a") as log:
        log.write(
            f"{datetime.utcnow().isoformat()} accuracy={acc:.3f} f1={f1:.3f} precision={prec:.3f} recall={rec:.3f} samples={len(y)}\n"
        )
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_FILE)


def run_scan(threshold: float) -> None:
    """Scan running processes and log any flagged by the model."""
    if MLPClassifier is None or not MODEL_FILE.exists():
        return
    clf = joblib.load(MODEL_FILE)
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    for proc in psutil.process_iter(["pid", "exe", "name"]):
        exe = proc.info.get("exe")
        if not exe or not os.path.exists(exe):
            continue
        try:
            with open(exe, "rb") as fh:
                md5 = hashlib.md5(fh.read()).hexdigest()
            feats = [int(c, 16) for c in md5[:32]]
            proba = clf.predict_proba([feats])[0][1]
            if proba >= threshold:
                _append_local_hash(md5)
                with ALERT_LOG.open("a") as log:
                    log.write(
                        f"{datetime.utcnow().isoformat()} {proc.info['name']} PID {proc.info['pid']} score {proba:.2f} flagged by GA Tech model\n"
                    )
        except Exception:
            continue


def main() -> None:
    parser = argparse.ArgumentParser(description="GA Tech process detector")
    parser.add_argument("--train", action="store_true", help="only train the model")
    parser.add_argument("--scan", action="store_true", help="only scan running processes")
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.getenv("GA_PROC_THRESHOLD", "0.5")),
        help="probability threshold for flagging processes",
    )
    args = parser.parse_args()

    download_dataset()
    do_train = args.train or not args.scan
    do_scan = args.scan or not args.train
    if do_train:
        train_model()
    if do_scan:
        run_scan(args.threshold)


if __name__ == "__main__":
    main()

