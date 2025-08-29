#!/usr/bin/env python3
"""nn_ids_snapshot.py - snapshot IDS model and dataset for self-healing."""
import datetime
import shutil
import tarfile
from pathlib import Path
import hashlib

MODEL_PATH = Path("/opt/nnids/ids_model.pkl")
DATA_DIR = Path("/opt/nnids/datasets")
SNAPSHOT_ROOT = Path("/var/backups/nnids")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot() -> None:
    ts = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
    dest = SNAPSHOT_ROOT / ts
    dest.mkdir(parents=True, exist_ok=True)

    if MODEL_PATH.exists():
        model_dest = dest / MODEL_PATH.name
        shutil.copy2(MODEL_PATH, model_dest)
        (dest / 'model.sha256').write_text(sha256(model_dest))

    if DATA_DIR.exists():
        tar_path = dest / 'datasets.tar.gz'
        with tarfile.open(tar_path, 'w:gz') as tar:
            tar.add(DATA_DIR, arcname='datasets')
        (dest / 'datasets.sha256').write_text(sha256(tar_path))


if __name__ == "__main__":
    snapshot()
