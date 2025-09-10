#!/usr/bin/env python3
"""nn_ids_sanitize.py - Periodically sanitize IDS datasets."""
from pathlib import Path
import fcntl
from packet_sanitizer import sanitize_csv
import os

SANITIZE_ENABLED = os.getenv("NN_IDS_SANITIZE", "1") == "1"

DATA_DIR = Path("/opt/nnids")
DATASET = DATA_DIR / "datasets" / "dataset.csv"
CAPTURE = DATA_DIR / "live_capture.csv"


def sanitize_file(path: Path) -> None:
    if not path.exists():
        return
    tmp = path.with_suffix(".tmp")
    with path.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        sanitize_csv(path, tmp)
        tmp.replace(path)
        fcntl.flock(f, fcntl.LOCK_UN)


def main() -> None:
    if not SANITIZE_ENABLED:
        return
    sanitize_file(DATASET)
    sanitize_file(CAPTURE)


if __name__ == "__main__":
    main()
