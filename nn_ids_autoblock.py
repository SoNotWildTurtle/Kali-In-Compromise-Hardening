#!/usr/bin/env python3
"""nn_ids_autoblock.py - Block IPs with repeated IDS alerts."""
import json
import re
import subprocess
from pathlib import Path
from datetime import datetime

LOG_FILE = Path('/var/log/nn_ids_alerts.log')
STATE_FILE = Path('/var/lib/nn_ids/autoblock_state.json')
THRESHOLD = 5
BLOCK_DURATION = 24 * 3600  # seconds


def load_state():
    if STATE_FILE.exists():
        with STATE_FILE.open() as f:
            return json.load(f)
    return {'counts': {}, 'blocked': {}, 'pos': 0}
    return {'counts': {}, 'blocked': [], 'pos': 0}


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


def block_ip(ip):
    if subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        with open('/var/log/nn_ids_autoblock.log', 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} Blocked {ip}\n")


def unblock_ip(ip):
    if subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
        with open('/var/log/nn_ids_autoblock.log', 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} Unblocked {ip}\n")

def main():
    state = load_state()
    lines = parse_new_lines(state)
    ips = extract_ips(lines)
    now = datetime.utcnow().timestamp()

    # Unblock expired entries
    expired = []
    for ip, ts in state.get('blocked', {}).items():
        if now - ts >= BLOCK_DURATION:
            unblock_ip(ip)
            expired.append(ip)
    for ip in expired:
        state['blocked'].pop(ip, None)

    for ip in ips:
        state['counts'][ip] = state['counts'].get(ip, 0) + 1
        if state['counts'][ip] >= THRESHOLD and ip not in state.get('blocked', {}):
            block_ip(ip)
            state.setdefault('blocked', {})[ip] = now

    for ip in ips:
        state['counts'][ip] = state['counts'].get(ip, 0) + 1
        if state['counts'][ip] >= THRESHOLD and ip not in state.get('blocked', []):
            block_ip(ip)
            state.setdefault('blocked', []).append(ip)
    save_state(state)


if __name__ == '__main__':
    main()
