#!/usr/bin/env python3
"""nn_ids_report.py - Summarize new IDS alerts and count offending IPs."""
from collections import Counter
from pathlib import Path
import json
import re
from datetime import datetime

LOG_FILE = Path('/var/log/nn_ids_alerts.log')
STATE_FILE = Path('/var/lib/nn_ids/report_state.json')
REPORT_LOG = Path('/var/log/nn_ids_report.log')


def load_state():
    if STATE_FILE.exists():
        with STATE_FILE.open() as f:
            return json.load(f)
    return {'pos': 0}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open('w') as f:
        json.dump(state, f)


def parse_new_lines(state):
    if not LOG_FILE.exists():
        return []
    lines = []
    pos = state.get('pos', 0)
    with LOG_FILE.open() as f:
        f.seek(pos)
        for line in f:
            lines.append(line.strip())
        state['pos'] = f.tell()
    return lines


def extract_ips(lines):
    ips = []
    for line in lines:
        ips.extend(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', line))
    return ips


def log_report(counts):
    REPORT_LOG.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().isoformat()
    with REPORT_LOG.open('a') as f:
        for ip, count in counts.items():
            f.write(f"{timestamp} {ip} {count}\n")


def main():
    state = load_state()
    lines = parse_new_lines(state)
    ips = extract_ips(lines)
    counts = Counter(ips)
    if counts:
        log_report(counts)
    save_state(state)


if __name__ == '__main__':
    main()
