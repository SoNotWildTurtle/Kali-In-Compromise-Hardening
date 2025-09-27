#!/usr/bin/env python3
"""process_service_monitor.py - baseline and detect new processes and services."""
import csv
import json
import psutil
import subprocess
from pathlib import Path
from datetime import datetime

BASELINE_FILE = Path("/var/lib/process_monitor/baseline.json")
ALERT_LOG = Path("/var/log/process_monitor_alerts.log")
PROC_DB = Path("/opt/nnids/process_log.csv")

# simple list of suspicious process names; extend as needed
MALICIOUS_NAMES = {"nc", "ncat", "netcat", "msfconsole", "meterpreter"}


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


def log_db(name, pid, reason):
    PROC_DB.parent.mkdir(parents=True, exist_ok=True)
    with PROC_DB.open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.utcnow().isoformat(), name, pid, reason])


def main():
    baseline = load_baseline()
    current = {
        "processes": current_processes(),
        "services": current_services(),
    }

    if not BASELINE_FILE.exists():
        save_baseline(current)
        return

    proc_pid_map = {p.info['name']: p.info['pid'] for p in psutil.process_iter(['name', 'pid']) if p.info['name']}

    new_procs = set(current['processes']) - set(baseline.get('processes', []))
    if new_procs:
        log_alert(f"New processes detected: {', '.join(sorted(new_procs))}")
        for name in sorted(new_procs):
            log_db(name, proc_pid_map.get(name, 0), "new process")

    new_services = set(current['services']) - set(baseline.get('services', []))
    if new_services:
        log_alert(f"New services detected: {', '.join(sorted(new_services))}")

    # heuristics and known-bad names
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info.get('name') or ''
            exe = proc.info.get('exe') or ''
            pid = proc.info['pid']
            if exe.startswith('/tmp'):
                reason = "running from /tmp"
                log_alert(f"Process running from /tmp: {name} PID {pid}")
                log_db(name, pid, reason)
            if name.lower() in MALICIOUS_NAMES:
                reason = "name in blocklist"
                log_alert(f"Malicious process {name} PID {pid}")
                log_db(name, pid, reason)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    save_baseline(current)


if __name__ == "__main__":
    main()

