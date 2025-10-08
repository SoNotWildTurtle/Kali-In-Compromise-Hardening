#!/usr/bin/env python3
"""nn_ids_healthcheck.py - Ensure the neural network IDS is running and healthy."""
import subprocess
from pathlib import Path
from datetime import datetime

MODEL = Path("/opt/nnids/ids_model.pkl")
LOG = Path("/var/log/nn_ids_health.log")


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(f"{datetime.utcnow().isoformat()} {msg}\n")


def service_active(name: str) -> bool:
    return subprocess.call(["systemctl", "is-active", "--quiet", name]) == 0


def main() -> None:
    if not MODEL.exists():
        log("IDS model missing; training may have failed")
    if not service_active("nn_ids.service"):
        log("nn_ids.service not active; attempting restart")
        subprocess.call(["systemctl", "restart", "nn_ids.service"])
        if service_active("nn_ids.service"):
            log("nn_ids.service restarted successfully")
        else:
            log("Failed to restart nn_ids.service")


if __name__ == "__main__":
    main()
