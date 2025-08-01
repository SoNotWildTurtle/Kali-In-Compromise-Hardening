#!/usr/bin/env python3
"""port_socket_monitor.py - Detect unexpected listening ports."""
import psutil
from pathlib import Path
from datetime import datetime
import json

BASELINE_FILE = Path('/var/lib/port_monitor/baseline.json')
ALERT_LOG = Path('/var/log/port_monitor_alerts.log')
WHITELIST = {22, 80, 443, 8080}


def log(msg: str) -> None:
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open('a') as f:
        f.write(f"{datetime.utcnow().isoformat()} {msg}\n")


def current_ports() -> set:
    ports = set()
    for c in psutil.net_connections(kind='inet'):
        if c.status == psutil.CONN_LISTEN and c.laddr:
            ports.add(c.laddr.port)
    return ports


def main() -> None:
    ports = current_ports()
    if not BASELINE_FILE.exists():
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with BASELINE_FILE.open('w') as f:
            json.dump(sorted(ports), f)
        return

    with BASELINE_FILE.open() as f:
        baseline = set(json.load(f))

    new_ports = ports - baseline
    suspicious = {p for p in new_ports if p not in WHITELIST}
    if suspicious:
        log(f"Suspicious listening ports: {', '.join(map(str, sorted(suspicious)))}")

    with BASELINE_FILE.open('w') as f:
        json.dump(sorted(ports), f)


if __name__ == '__main__':
    main()
