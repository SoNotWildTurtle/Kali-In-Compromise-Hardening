#!/usr/bin/env python3
"""nn_ids_restore.py - rebuild IDS model and data from snapshots."""
import tarfile
import subprocess
from pathlib import Path
import hashlib

MODEL_PATH = Path("/opt/nnids/ids_model.pkl")
DATA_DIR = Path("/opt/nnids/datasets")
SNAPSHOT_ROOT = Path("/var/backups/nnids")
NN_SETUP = "/usr/local/bin/nn_ids_setup.py"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def latest_snapshot() -> Path | None:
    if not SNAPSHOT_ROOT.exists():
        return None
    snaps = sorted(SNAPSHOT_ROOT.glob('*'))
    return snaps[-1] if snaps else None


def restore() -> None:
    snap = latest_snapshot()
    if not snap:
        return
    model_file = snap / MODEL_PATH.name
    dataset_tar = snap / 'datasets.tar.gz'
    model_hash = (snap / 'model.sha256')
    data_hash = (snap / 'datasets.sha256')

    if model_file.exists() and model_hash.exists():
        if sha256(model_file) == model_hash.read_text().strip():
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            model_file.replace(MODEL_PATH)
    if dataset_tar.exists() and data_hash.exists():
        if sha256(dataset_tar) == data_hash.read_text().strip():
            DATA_DIR.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(dataset_tar, 'r:gz') as tar:
                tar.extractall(DATA_DIR.parent)
    if not MODEL_PATH.exists() and DATA_DIR.exists():
        try:
            subprocess.run(["python3", NN_SETUP], check=True)
        except Exception:
            pass


if __name__ == "__main__":
    restore()
