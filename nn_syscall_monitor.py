#!/usr/bin/env python3
"""Background GA Tech system call monitor service."""
from __future__ import annotations

import os

from nn_syscall_gt import monitor_syscalls


def main() -> None:
    duration = int(os.getenv("GA_SYS_DAEMON_DURATION", "0"))
    interval = float(os.getenv("GA_SYS_INTERVAL", "1.0"))
    window = int(os.getenv("GA_SYS_WINDOW", "25"))
    threshold_env = os.getenv("NN_SYS_THRESHOLD")
    threshold = float(threshold_env) if threshold_env else None
    try:
        monitor_syscalls(
            duration=duration,
            interval=max(0.1, interval),
            window=max(10, window),
            threshold=threshold,
            continuous=True,
            verbose=False,
        )
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
