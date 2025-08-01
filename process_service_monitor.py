#!/usr/bin/env python3
"""process_service_monitor.py - baseline and detect new processes and services."""
import json
import psutil
import subprocess
from pathlib import Path
from datetime import datetime

BASELINE_FILE = Path("/var/lib/process_monitor/baseline.json")
ALERT_LOG = Path("/var/log/process_monitor_alerts.log")


def load_baseline():
    if BASELINE_FILE.exists():
        with BASELINE_FILE.open() as f:
            return json.load(f)
    return {"processes": [], "services": []}


def save_baseline(data):
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with BASELINE_FILE.open("w") as f:
        json.dump(data, f)


def current_processes():
    names = set()
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name']:
                names.add(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(names)


def current_services():
    try:
        out = subprocess.check_output([
            "systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"
        ], text=True)
        names = [line.split()[0] for line in out.strip().splitlines() if line]
        return sorted(names)
    except Exception:
        return []


def log_alert(message):
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_LOG.open("a") as f:
        f.write(f"{datetime.utcnow().isoformat()} {message}\n")


def main():
    baseline = load_baseline()
    current = {
        "processes": current_processes(),
        "services": current_services(),
    }

    if not BASELINE_FILE.exists():
        save_baseline(current)
        return

    new_procs = set(current['processes']) - set(baseline.get('processes', []))
    if new_procs:
        log_alert(f"New processes detected: {', '.join(sorted(new_procs))}")

    new_services = set(current['services']) - set(baseline.get('services', []))
    if new_services:
        log_alert(f"New services detected: {', '.join(sorted(new_services))}")

    # example heuristic: processes running from /tmp
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info.get('exe') or ''
            if exe.startswith('/tmp'):
                log_alert(f"Process running from /tmp: {proc.info['name']} PID {proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    save_baseline(current)


if __name__ == "__main__":
    main()

