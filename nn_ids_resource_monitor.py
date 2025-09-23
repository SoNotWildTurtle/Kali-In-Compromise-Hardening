#!/usr/bin/env python3
"""nn_ids_resource_monitor.py - Monitor resource usage of the NN IDS."""
import psutil
import subprocess
from datetime import datetime
from pathlib import Path

LOG = Path('/var/log/nn_ids_resource.log')
SERVICE = 'nn_ids.service'
MAX_MEM_MB = 200
MAX_CPU = 80.0


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open('a') as f:
        f.write(f"{datetime.utcnow().isoformat()} {msg}\n")


def main() -> None:
    found = False
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmd = ' '.join(proc.info.get('cmdline') or [])
            if 'nn_ids_service.py' in cmd:
                found = True
                mem = proc.memory_info().rss / 1024 / 1024
                cpu = proc.cpu_percent(interval=1)
                if mem > MAX_MEM_MB or cpu > MAX_CPU:
                    log(f'Resource spike mem={mem:.1f}MB cpu={cpu:.1f}% - restarting')
                    subprocess.call(['systemctl', 'restart', SERVICE])
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        log('nn_ids_service process not found')


if __name__ == '__main__':
    main()
